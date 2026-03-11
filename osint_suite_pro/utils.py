import time
import requests
import json
import re
import logging
from collections import OrderedDict
from bs4 import BeautifulSoup
from urllib.parse import urlparse, quote
from config import USER_AGENT, HTTP_TIMEOUT, MAX_DOMAIN_CACHE_SIZE

logger = logging.getLogger(__name__)

# Rate limiting intelligente per dominio (LRU cache con limite)
_domain_last_request: OrderedDict = OrderedDict()  # {"domain": timestamp} - max size: MAX_DOMAIN_CACHE_SIZE

# Rate limit configurabile per dominio (secondi between requests)
DOMAIN_RATE_LIMITS = {
    "instagram.com": 0.8,
    "facebook.com": 0.8,
    "twitter.com": 0.5,
    "x.com": 0.5,
    "github.com": 0.3,  # GitHub tolera di più
    "reddit.com": 0.4,
    "linkedin.com": 1.0,  # LinkedIn è rigoroso
    "tiktok.com": 1.0,
    "youtube.com": 0.5,
    "twitch.tv": 0.6,
    "default": 0.25  # Default fallback
}

EXPONENTIAL_BACKOFF = {
    429: 5,   # Rate limited → aspetta 5 sec
    403: 2,   # Forbidden → aspetta 2 sec
    401: 1,   # Unauthorized → aspetta 1 sec
}


def get_domain_from_url(url: str) -> str:
    """Estrae il dominio da un URL."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        # Rimuovi 'www.'
        if domain.startswith("www."):
            domain = domain[4:]
        return domain
    except Exception:
        return "default"


def get_rate_limit_for_domain(domain: str) -> float:
    """Ritorna il rate limit in secondi per un specifico dominio."""
    return DOMAIN_RATE_LIMITS.get(domain, DOMAIN_RATE_LIMITS["default"])


def apply_rate_limit(url: str) -> None:
    """Applica rate limit specifico per dominio prima della richiesta."""
    domain = get_domain_from_url(url)
    limit = get_rate_limit_for_domain(domain)
    
    now = time.time()
    last = _domain_last_request.get(domain, 0.0)
    delta = now - last
    
    if delta < limit:
        sleep_time = limit - delta
        logger.debug(f"Rate limit {domain}: sleeping {sleep_time:.2f}s")
        time.sleep(sleep_time)
    
    # Aggiorna timestamp (muove domain in fondo a OrderedDict)
    _domain_last_request[domain] = time.time()
    
    # Mantieni cache sotto limite massimo (rimuovi il più vecchio)
    if len(_domain_last_request) > MAX_DOMAIN_CACHE_SIZE:
        oldest_domain, _ = _domain_last_request.popitem(last=False)
        logger.debug(f"Removed oldest domain from cache: {oldest_domain}")


def rate_limited_get(url: str, headers: dict = None, timeout: int = None, max_retries: int = 1) -> dict:
    """
    Richiesta HTTP con rate limiting intelligente per dominio e exponential backoff.
    
    Args:
        url: URL da richiedere
        headers: Header HTTP custom
        timeout: Timeout in secondi (default: HTTP_TIMEOUT da config)
        max_retries: Numero di retry per 429/503
    
    Returns:
        Dict con status, text, url, ok
    """
    if timeout is None:
        timeout = HTTP_TIMEOUT
    hdr = {"User-Agent": USER_AGENT}
    if headers:
        hdr.update(headers)
    
    retry_count = 0
    
    while retry_count <= max_retries:
        try:
            # Applica rate limit per dominio
            apply_rate_limit(url)
            
            # Esegui richiesta
            r = requests.get(url, headers=hdr, timeout=timeout, allow_redirects=True)
            
            # Gestisci retry per rate-limit / server errors
            if r.status_code in EXPONENTIAL_BACKOFF:
                backoff = EXPONENTIAL_BACKOFF[r.status_code]
                if retry_count < max_retries:
                    logger.warning(f"Status {r.status_code} per {url}, retry in {backoff}s (attempt {retry_count+1})")
                    time.sleep(backoff)
                    retry_count += 1
                    continue
            
            return {
                "status": r.status_code,
                "text": r.text,
                "url": r.url,
                "ok": r.ok
            }
        
        except requests.exceptions.Timeout:
            logger.exception(f"Timeout per {url}")
            return {"status": None, "error": "Timeout", "ok": False}
        except requests.exceptions.ConnectionError:
            logger.exception(f"Connection error per {url}")
            return {"status": None, "error": "Connection error", "ok": False}
        except Exception as e:
            logger.exception(f"Unexpected error durante richiesta a {url}")
            return {"status": None, "error": str(e), "ok": False}
    
    return {"status": None, "error": "Max retries exceeded", "ok": False}


def http_get(url: str, headers: dict = None, timeout: int = None) -> dict:
    """Wrapper per rate_limited_get."""
    return rate_limited_get(url, headers=headers, timeout=timeout)


def extract_page_metadata(html_text, base_url=None):
    soup = BeautifulSoup(html_text, "html.parser")
    meta = {}

    title = soup.title.string.strip() if soup.title and soup.title.string else None
    if title:
        meta["title"] = title

    desc = (
        soup.find("meta", attrs={"name": "description"})
        or soup.find("meta", attrs={"property": "og:description"})
    )
    if desc and desc.get("content"):
        meta["description"] = desc["content"].strip()

    og = {}
    for tag in soup.find_all("meta"):
        prop = tag.get("property", "")
        if isinstance(prop, str) and prop.startswith("og:"):
            og[prop] = tag.get("content")
    if og:
        meta["og"] = og

    ld = []
    for script in soup.find_all("script", type="application/ld+json"):
        try:
            ld.append(json.loads(script.string))
        except Exception:
            continue
    if ld:
        meta["ld_json"] = ld

    text = soup.get_text(separator=" ").lower()
    patterns = {}
    if "followers" in text:
        m = re.search(r"([\d,.]+)\s*followers", text)
        patterns["followers_mention"] = m.group(1) if m else "found"
    if "bio" in text or "about" in text:
        patterns["bio_mention"] = True
    if patterns:
        meta["patterns"] = patterns

    if base_url:
        meta["base"] = base_url

    return meta


def brute_username(base):
    suffix = ["_official", "_real", "01", "dev", "_0", "hub", ".official", "the"]
    return [base + s for s in suffix]


def validate_username(username: str) -> tuple[bool, str]:
    """
    Valida username/email/telefono per sicurezza e formato.
    Supporta: username, email (@), handle (@username), telefono (+39...), simboli (._-), spazi.
    Returns: (is_valid, error_message)
    """
    if not username or not username.strip():
        return False, "Username/Email/Telefono non può essere vuoto"

    username = username.strip()

    if len(username) > 100:
        return False, "Input troppo lungo (max 100 caratteri)"

    # Pattern permissivo per validazione
    pattern = re.compile(r'^[a-zA-Z0-9._\-@\s\+]{1,100}$')
    if not pattern.match(username):
        return False, "Input contiene caratteri non validi. Usa lettere, numeri, @, +, punti, trattini, underscore e spazi"

    # Controllachè non sia un numero di telefono troppo corto
    is_phone = username.startswith('+') or (username.isdigit() and len(username) >= 7)
    is_email = '@' in username
    is_username = not is_phone and not is_email
    
    # Controlli aggiuntivi per sicurezza
    if is_username and username.lower() in ['admin', 'root', 'system', 'null', 'undefined']:
        return False, "Username riservato non permesso"

    return True, ""