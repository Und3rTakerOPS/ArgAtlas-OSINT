# engine_core.py
import time
import json
import logging
import ipaddress
from typing import Any, Dict, Optional, Tuple
from urllib.parse import quote
import requests
from bs4 import BeautifulSoup

from config import (
    USER_AGENT,
    GITHUB_API_TOKEN,
    ABUSEIPDB_API_KEY,
    ABUSEIPDB_ENABLED,
    VIRUSTOTAL_API_KEY,
    VIRUSTOTAL_ENABLED,
    IPINFO_TOKEN,
    IPINFO_ENABLED,
    REDDIT_CLIENT_ID,
    REDDIT_CLIENT_SECRET,
    REDDIT_USER_AGENT,
    REDDIT_ENABLED,
    YOUTUBE_API_KEY,
    YOUTUBE_ENABLED,
    URLSCAN_API_KEY,
    URLSCAN_ENABLED,
    OTX_API_KEY,
    OTX_ENABLED,
    GREYNOISE_API_KEY,
    GREYNOISE_ENABLED,
    CRTSH_ENABLED,
    URLHAUS_ENABLED,
    IPAPI_ENABLED,
    EXTERNAL_API_TIMEOUT,
    EXTERNAL_API_RETRIES,
    EXTERNAL_API_RETRY_BACKOFF,
    EXTERNAL_API_CACHE_TTL,
)
from utils import rate_limited_get, http_get, extract_page_metadata, brute_username

logger = logging.getLogger(__name__)

_API_CACHE: Dict[Tuple[str, str, str], Tuple[float, Dict[str, Any]]] = {}


def _build_cache_key(method: str, url: str, params: Optional[Dict[str, Any]]) -> Tuple[str, str, str]:
    safe_params = json.dumps(params or {}, sort_keys=True, default=str)
    return (method.upper(), url, safe_params)


def _api_request_json(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    data: Optional[Dict[str, Any]] = None,
    auth: Optional[Tuple[str, str]] = None,
    use_cache: bool = False,
) -> Dict[str, Any]:
    method_up = method.upper()
    cache_key = _build_cache_key(method_up, url, params)
    now_ts = time.time()

    if use_cache and method_up == "GET" and cache_key in _API_CACHE:
        cached_ts, cached_payload = _API_CACHE[cache_key]
        if now_ts - cached_ts <= EXTERNAL_API_CACHE_TTL:
            out = dict(cached_payload)
            out["cached"] = True
            return out

    last_error = ""
    retryable_statuses = {408, 425, 429, 500, 502, 503, 504}
    attempts = max(1, EXTERNAL_API_RETRIES + 1)

    for attempt in range(attempts):
        try:
            resp = requests.request(
                method=method_up,
                url=url,
                headers=headers,
                params=params,
                data=data,
                auth=auth,
                timeout=EXTERNAL_API_TIMEOUT,
            )

            payload_json: Dict[str, Any] = {}
            try:
                payload_json = resp.json() if resp.text else {}
            except ValueError:
                payload_json = {}

            result = {
                "ok": 200 <= resp.status_code < 300,
                "status": resp.status_code,
                "json": payload_json,
                "cached": False,
            }

            if use_cache and method_up == "GET" and result["ok"]:
                _API_CACHE[cache_key] = (now_ts, result)

            if resp.status_code in retryable_statuses and attempt < attempts - 1:
                time.sleep(EXTERNAL_API_RETRY_BACKOFF * (attempt + 1))
                continue

            return result

        except requests.RequestException as e:
            last_error = str(e)
            if attempt < attempts - 1:
                time.sleep(EXTERNAL_API_RETRY_BACKOFF * (attempt + 1))
                continue

    return {"ok": False, "status": None, "json": {}, "error": last_error, "cached": False}

# ---------------------------------------------------
# Funzione: costruisce i link social da uno username
# ---------------------------------------------------

def build_services_for_username(base: str) -> Dict[str, str]:
    """
    Costruisce lista completa di link social/web per ricerca OSINT.
    Supports username, email e varianti.
    
    Args:
        base: Username da usare per costruire i link
    
    Returns:
        Dictionary con platform: url mappings
    """
    from urllib.parse import quote
    # URL-encode il base per sicurezza (prevent injection)
    encoded = quote(base, safe='')
    services = {
        # Social network principali
        "GitHub": f"https://github.com/{encoded}",
        "X / Twitter": f"https://x.com/{encoded}",
        "Instagram": f"https://instagram.com/{encoded}",
        "Facebook": f"https://facebook.com/{encoded}",
        "TikTok": f"https://tiktok.com/@{encoded}",
        "YouTube": f"https://www.youtube.com/@{encoded}",
        "LinkedIn": f"https://www.linkedin.com/in/{encoded}",
        "Reddit": f"https://reddit.com/user/{encoded}",
        "Telegram": f"https://t.me/{encoded}",
        
        # Ulteriori social e comunità
        "Twitch": f"https://twitch.tv/{encoded}",
        "Mastodon": f"https://mastodon.social/@{encoded}",
        "Discord": f"https://discord.com/users/{encoded}",
        "Bluesky": f"https://bsky.app/profile/{encoded}",
        "Threads": f"https://www.threads.net/@{encoded}",
        "BeReal": f"https://bereal.com/user/{encoded}",
        "Pinterest": f"https://pinterest.com/{encoded}",
        "Tumblr": f"https://tumblr.com/blog/{encoded}",
        "Medium": f"https://medium.com/@{encoded}",
        "Dev.to": f"https://dev.to/{encoded}",
        
        # Forum e community
        "Stack Overflow": f"https://stackoverflow.com/users/{encoded}",
        "Quora": f"https://www.quora.com/profile/{encoded}",
        "4Chan": f"https://4chan.org/search?q={encoded}",
        "8kun": f"https://8kun.top/search?q={encoded}",
        
        # Piattaforme di gaming
        "Steam": f"https://steamcommunity.com/search/?text={encoded}",
        "PSN / PlayStation": f"https://psn.com/user/{encoded}",
        "Xbox": f"https://xbox.com/user/{encoded}",
        "Epic Games": f"https://www.epicgames.com/store/en-US/user/{encoded}",
        "Roblox": f"https://www.roblox.com/users/search?keyword={encoded}",
        
        # Piattaforme creative
        "DeviantArt": f"https://www.deviantart.com/{encoded}",
        "ArtStation": f"https://www.artstation.com/{encoded}",
        "Flickr": f"https://www.flickr.com/photos/{encoded}",
        "500px": f"https://500px.com/{encoded}",
        "Behance": f"https://www.behance.net/{encoded}",
        
        # Piattaforme di streaming e contenuti
        "Rumble": f"https://rumble.com/@{encoded}",
        "BitChute": f"https://www.bitchute.com/channel/{encoded}",
        "Odysee": f"https://odysee.com/@{encoded}",
        "LBRY": f"https://lbry.tv/@{encoded}",
        "Patreon": f"https://www.patreon.com/{encoded}",
        
        # Forum tecnici
        "HackerNews": f"https://news.ycombinator.com/from?site={encoded}",
        "ProductHunt": f"https://www.producthunt.com/search?q={encoded}",
        "SourceForge": f"https://sourceforge.net/user/{encoded}",
        
        # Dating e social
        "Tinder": f"https://tinder.com/users/{encoded}",
        "Bumble": f"https://bumble.com/user/{encoded}",
        "OkCupid": f"https://www.okcupid.com/profile/{encoded}",
        "Hinge": f"https://hinge.co/user/{encoded}",
        
        # Siti di musica
        "Spotify": f"https://open.spotify.com/user/{encoded}",
        "SoundCloud": f"https://soundcloud.com/{encoded}",
        "Bandcamp": f"https://bandcamp.com/{encoded}",
        "Last.fm": f"https://www.last.fm/user/{encoded}",
        
        # Piattaforme di cripto e finanza
        "Coinbase": f"https://coinbase.com/user/{encoded}",
        "Kraken": f"https://kraken.com/user/{encoded}",
        "OpenSea": f"https://opensea.io/{encoded}",
        "Etherscan": f"https://etherscan.io/address/{encoded}",
        
        # Blog e piattaforme di scrittura
        "Blogger": f"https://www.blogger.com/profile/{encoded}",
        "Substack": f"https://substack.com/@{encoded}",
        "Ghost": f"https://ghost.org/{encoded}",
        "WordPress.com": f"https://{encoded}.wordpress.com",
        
        # Siti di Q&A
        "Yahoo Answers": f"https://answers.yahoo.com/profile/{encoded}",
        
        # Altre piattaforme
        "GitLab": f"https://gitlab.com/{encoded}",
        "Gitea": f"https://gitea.com/{encoded}",
        "Replit": f"https://replit.com/@{encoded}",
        "Glitch": f"https://glitch.com/@{encoded}",
        "Codepen": f"https://codepen.io/{encoded}",
        "JSFiddle": f"https://jsfiddle.net/user/{encoded}",
        "Kaggle": f"https://www.kaggle.com/{encoded}",
        "AngelList": f"https://angel.co/{encoded}",
        "SlideShare": f"https://www.slideshare.net/{encoded}",
        "Scribd": f"https://www.scribd.com/{encoded}",
        "Issuu": f"https://issuu.com/search?q={encoded}",
    }
    return services


# ---------------------------------------------------
# Controllo se i profili esistono
# ---------------------------------------------------
def check_profiles_exist(services: Dict[str, str], limit: int = 8) -> Dict[str, dict]:
    """Controlla se i profili esistono."""
    from config import STATUS_CHECK_DELAY
    results = {}
    i = 0
    for platform, url in services.items():
        i += 1
        if i % limit == 0:
            time.sleep(STATUS_CHECK_DELAY)
        resp = http_get(url)
        status = resp.get("status")
        if resp.get("ok") or status in (301, 302):
            results[platform] = {"status": status, "exists": True, "url": resp.get("url")}
        else:
            results[platform] = {"status": status, "exists": False, "url": url}
    return results


# ---------------------------------------------------
# Esegue scraping meta preview dei profili
# ---------------------------------------------------
def scrape_social_preview(services: Dict[str, str], sample_limit: int = 10) -> Dict[str, dict]:
    """Esegue scraping meta preview dei profili."""
    from config import SCRAPE_DELAY
    out = {}
    i = 0
    for platform, url in services.items():
        i += 1
        resp = http_get(url)
        if resp.get("ok"):
            meta = extract_page_metadata(resp.get("text"), base_url=resp.get("url"))
            out[platform] = {"found": True, "status": resp.get("status"), "meta_preview": meta}
        else:
            out[platform] = {"found": False, "status": resp.get("status")}
        if i % sample_limit == 0:
            time.sleep(SCRAPE_DELAY)
    return out


# ---------------------------------------------------
# Ricerca profilo GitHub tramite API pubblica
# ---------------------------------------------------
def github_lookup(username: str) -> dict:
    """Ricerca profilo GitHub tramite API pubblica."""
    try:
        # URL-encode the username per sicurezza
        encoded_username = quote(username, safe='')
        headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
        if GITHUB_API_TOKEN:
            headers["Authorization"] = f"Bearer {GITHUB_API_TOKEN}"

        resp_data = _api_request_json(
            "GET",
            f"https://api.github.com/users/{encoded_username}",
            headers=headers,
            use_cache=True,
        )
        status = resp_data.get("status")
        if resp_data.get("ok"):
            d = resp_data.get("json", {})
            return {
                "exists": True,
                "followers": d.get("followers"),
                "public_repos": d.get("public_repos"),
                "following": d.get("following"),
                "bio": d.get("bio"),
                "location": d.get("location"),
                "created_at": d.get("created_at"),
                "api_authenticated": bool(GITHUB_API_TOKEN),
                "cached": resp_data.get("cached", False),
            }
        if status == 404:
            return {"exists": False}
        return {"exists": False, "status": status, "message": "GitHub API error"}

    except requests.RequestException as e:
        logger.exception(f"GitHub lookup error per {username}")
        return {"exists": False, "error": str(e)}
    except Exception as e:
        logger.exception(f"GitHub lookup error per {username}")
        return {"exists": False, "error": str(e)}


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def reddit_lookup(username: str) -> dict:
    """Lookup Reddit user info via OAuth (if configured) with public fallback."""
    try:
        encoded_username = quote(username, safe='')
        headers = {"User-Agent": REDDIT_USER_AGENT or USER_AGENT}

        if REDDIT_ENABLED:
            token_resp = _api_request_json(
                "POST",
                "https://www.reddit.com/api/v1/access_token",
                auth=(REDDIT_CLIENT_ID, REDDIT_CLIENT_SECRET),
                data={"grant_type": "client_credentials"},
                headers=headers,
                use_cache=False,
            )
            if token_resp.get("ok"):
                token = (token_resp.get("json") or {}).get("access_token")
                if token:
                    oauth_headers = dict(headers)
                    oauth_headers["Authorization"] = f"Bearer {token}"
                    info_resp = _api_request_json(
                        "GET",
                        f"https://oauth.reddit.com/user/{encoded_username}/about",
                        headers=oauth_headers,
                        use_cache=True,
                    )
                    if info_resp.get("ok"):
                        data = ((info_resp.get("json") or {}).get("data", {}))
                        return {
                            "exists": True,
                            "name": data.get("name"),
                            "created_utc": data.get("created_utc"),
                            "comment_karma": data.get("comment_karma"),
                            "link_karma": data.get("link_karma"),
                            "verified": data.get("verified"),
                            "over_18": data.get("over_18"),
                            "source": "oauth",
                            "cached": info_resp.get("cached", False),
                        }

        public_resp = _api_request_json(
            "GET",
            f"https://www.reddit.com/user/{encoded_username}/about.json",
            headers=headers,
            use_cache=True,
        )
        status = public_resp.get("status")
        if public_resp.get("ok"):
            data = ((public_resp.get("json") or {}).get("data", {}))
            return {
                "exists": True,
                "name": data.get("name"),
                "created_utc": data.get("created_utc"),
                "comment_karma": data.get("comment_karma"),
                "link_karma": data.get("link_karma"),
                "verified": data.get("verified"),
                "over_18": data.get("over_18"),
                "source": "public",
                "cached": public_resp.get("cached", False),
            }
        if status == 404:
            return {"exists": False}
        return {"exists": False, "status": status, "message": "Reddit API error"}

    except requests.RequestException as e:
        logger.warning(f"Reddit lookup failed for {username}: {e}")
        return {"exists": False, "error": str(e)}
    except Exception as e:
        logger.warning(f"Reddit lookup failed for {username}: {e}")
        return {"exists": False, "error": str(e)}


def youtube_lookup(username: str) -> dict:
    """Lookup YouTube channel by handle/name via YouTube Data API v3."""
    if not YOUTUBE_ENABLED:
        return {"enabled": False, "message": "YOUTUBE_API_KEY not configured"}

    try:
        query = quote(username, safe='')
        search_url = (
            "https://www.googleapis.com/youtube/v3/search"
            f"?part=snippet&type=channel&maxResults=1&q={query}&key={YOUTUBE_API_KEY}"
        )
        search_resp = _api_request_json("GET", search_url, use_cache=True)
        if not search_resp.get("ok"):
            return {"exists": False, "status": search_resp.get("status"), "message": "YouTube search error"}

        items = ((search_resp.get("json") or {}).get("items", []))
        if not items:
            return {"exists": False}

        first = items[0]
        channel_id = ((first.get("id") or {}).get("channelId"))
        snippet = first.get("snippet") or {}

        stats = {}
        if channel_id:
            channels_url = (
                "https://www.googleapis.com/youtube/v3/channels"
                f"?part=statistics,snippet&id={quote(channel_id, safe='')}&key={YOUTUBE_API_KEY}"
            )
            channels_resp = _api_request_json("GET", channels_url, use_cache=True)
            if channels_resp.get("ok"):
                ch_items = ((channels_resp.get("json") or {}).get("items", []))
                if ch_items:
                    stats = (ch_items[0] or {}).get("statistics", {}) or {}

        return {
            "exists": True,
            "channel_id": channel_id,
            "channel_title": snippet.get("channelTitle") or snippet.get("title"),
            "description": snippet.get("description"),
            "published_at": snippet.get("publishedAt"),
            "subscriber_count": stats.get("subscriberCount"),
            "video_count": stats.get("videoCount"),
            "view_count": stats.get("viewCount"),
            "cached": search_resp.get("cached", False),
        }

    except requests.RequestException as e:
        logger.warning(f"YouTube lookup failed for {username}: {e}")
        return {"exists": False, "error": str(e)}
    except Exception as e:
        logger.warning(f"YouTube lookup failed for {username}: {e}")
        return {"exists": False, "error": str(e)}


def abuseipdb_lookup(indicator: str) -> dict:
    """Lookup AbuseIPDB for IP reputation."""
    if not ABUSEIPDB_ENABLED:
        return {"enabled": False, "message": "ABUSEIPDB_API_KEY not configured"}
    if not _is_ip_address(indicator):
        return {"enabled": True, "skipped": True, "message": "Input is not an IP address"}

    try:
        resp = _api_request_json(
            "GET",
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": indicator, "maxAgeInDays": 90, "verbose": ""},
            use_cache=True,
        )
        if not resp.get("ok"):
            return {"exists": False, "status": resp.get("status"), "message": "AbuseIPDB API error"}

        data = ((resp.get("json") or {}).get("data", {}))
        return {
            "exists": True,
            "ip": data.get("ipAddress"),
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "country_code": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "total_reports": data.get("totalReports"),
            "last_reported_at": data.get("lastReportedAt"),
            "cached": resp.get("cached", False),
        }

    except requests.RequestException as e:
        logger.warning(f"AbuseIPDB lookup failed for {indicator}: {e}")
        return {"exists": False, "error": str(e)}
    except Exception as e:
        logger.warning(f"AbuseIPDB lookup failed for {indicator}: {e}")
        return {"exists": False, "error": str(e)}


def ipinfo_lookup(indicator: str) -> dict:
    """Lookup IPinfo for geolocation and ASN info."""
    if not IPINFO_ENABLED:
        return {"enabled": False, "message": "IPINFO_TOKEN not configured"}
    if not _is_ip_address(indicator):
        return {"enabled": True, "skipped": True, "message": "Input is not an IP address"}

    try:
        url = f"https://ipinfo.io/{quote(indicator, safe='')}/json?token={IPINFO_TOKEN}"
        resp = _api_request_json("GET", url, use_cache=True)
        if not resp.get("ok"):
            return {"exists": False, "status": resp.get("status"), "message": "IPinfo API error"}

        data = (resp.get("json") or {})
        return {
            "exists": True,
            "ip": data.get("ip"),
            "city": data.get("city"),
            "region": data.get("region"),
            "country": data.get("country"),
            "org": data.get("org"),
            "postal": data.get("postal"),
            "timezone": data.get("timezone"),
            "loc": data.get("loc"),
            "cached": resp.get("cached", False),
        }

    except requests.RequestException as e:
        logger.warning(f"IPinfo lookup failed for {indicator}: {e}")
        return {"exists": False, "error": str(e)}
    except Exception as e:
        logger.warning(f"IPinfo lookup failed for {indicator}: {e}")
        return {"exists": False, "error": str(e)}


def virustotal_lookup(indicator: str) -> dict:
    """Lookup VirusTotal for IP/domain reputation."""
    if not VIRUSTOTAL_ENABLED:
        return {"enabled": False, "message": "VIRUSTOTAL_API_KEY not configured"}

    endpoint = None
    safe_indicator = quote(indicator, safe='')
    if _is_ip_address(indicator):
        endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{safe_indicator}"
    elif "." in indicator and " " not in indicator and "/" not in indicator:
        endpoint = f"https://www.virustotal.com/api/v3/domains/{safe_indicator}"
    else:
        return {"enabled": True, "skipped": True, "message": "Input is not IP/domain"}

    try:
        resp = _api_request_json(
            "GET",
            endpoint,
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            use_cache=True,
        )
        if not resp.get("ok"):
            return {"exists": False, "status": resp.get("status"), "message": "VirusTotal API error"}

        attrs = (((resp.get("json") or {}).get("data") or {}).get("attributes", {}))
        stats = attrs.get("last_analysis_stats", {}) or {}
        return {
            "exists": True,
            "type": "ip" if _is_ip_address(indicator) else "domain",
            "indicator": indicator,
            "harmless": stats.get("harmless"),
            "malicious": stats.get("malicious"),
            "suspicious": stats.get("suspicious"),
            "undetected": stats.get("undetected"),
            "reputation": attrs.get("reputation"),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "cached": resp.get("cached", False),
        }

    except requests.RequestException as e:
        logger.warning(f"VirusTotal lookup failed for {indicator}: {e}")
        return {"exists": False, "error": str(e)}


def urlscan_lookup(indicator: str) -> dict:
    """Lookup URLScan.io search endpoint for URL/domain artifacts."""
    if not URLSCAN_ENABLED:
        return {"enabled": False, "message": "URLScan disabled"}

    query = indicator.strip()
    if not query:
        return {"enabled": True, "skipped": True, "message": "Empty indicator"}

    # If plain domain, use domain search; else generic free-text query.
    if "." in query and " " not in query and "/" not in query:
        q_value = f"domain:{query}"
    else:
        q_value = query

    headers = {"Content-Type": "application/json"}
    if URLSCAN_API_KEY:
        headers["API-Key"] = URLSCAN_API_KEY

    resp = _api_request_json(
        "GET",
        "https://urlscan.io/api/v1/search/",
        headers=headers,
        params={"q": q_value, "size": 5},
        use_cache=True,
    )
    if not resp.get("ok"):
        return {"exists": False, "status": resp.get("status"), "message": "URLScan API error"}

    results = (resp.get("json") or {}).get("results", [])
    return {
        "exists": len(results) > 0,
        "query": q_value,
        "count": len(results),
        "top_results": [
            {
                "task_time": item.get("task", {}).get("time"),
                "page_domain": item.get("page", {}).get("domain"),
                "page_ip": item.get("page", {}).get("ip"),
                "verdicts": item.get("verdicts", {}),
                "result": item.get("result"),
            }
            for item in results[:5]
        ],
        "cached": resp.get("cached", False),
    }


def otx_lookup(indicator: str) -> dict:
    """Lookup AlienVault OTX general indicator endpoint."""
    if not OTX_ENABLED:
        return {"enabled": False, "message": "OTX disabled"}

    indicator = indicator.strip()
    if not indicator:
        return {"enabled": True, "skipped": True, "message": "Empty indicator"}

    if _is_ip_address(indicator):
        section = "IPv4"
    elif "." in indicator and " " not in indicator and "/" not in indicator:
        section = "domain"
    else:
        return {"enabled": True, "skipped": True, "message": "Indicator type not supported"}

    headers = {}
    if OTX_API_KEY:
        headers["X-OTX-API-KEY"] = OTX_API_KEY

    resp = _api_request_json(
        "GET",
        f"https://otx.alienvault.com/api/v1/indicators/{section}/{quote(indicator, safe='')}/general",
        headers=headers,
        use_cache=True,
    )
    if not resp.get("ok"):
        return {"exists": False, "status": resp.get("status"), "message": "OTX API error"}

    data = resp.get("json") or {}
    pulse_info = data.get("pulse_info") or {}
    pulses = pulse_info.get("pulses") or []
    return {
        "exists": True,
        "indicator": indicator,
        "type": section,
        "pulse_count": pulse_info.get("count", len(pulses)),
        "top_pulses": [
            {
                "name": p.get("name"),
                "created": p.get("created"),
                "tags": p.get("tags", [])[:5],
            }
            for p in pulses[:5]
        ],
        "cached": resp.get("cached", False),
    }


def greynoise_lookup(indicator: str) -> dict:
    """Lookup GreyNoise community endpoint for IP noise classification."""
    if not GREYNOISE_ENABLED:
        return {"enabled": False, "message": "GREYNOISE_API_KEY not configured"}
    if not _is_ip_address(indicator):
        return {"enabled": True, "skipped": True, "message": "Input is not an IP address"}

    resp = _api_request_json(
        "GET",
        f"https://api.greynoise.io/v3/community/{quote(indicator, safe='')}",
        headers={"key": GREYNOISE_API_KEY},
        use_cache=True,
    )
    if not resp.get("ok"):
        return {"exists": False, "status": resp.get("status"), "message": "GreyNoise API error"}

    data = resp.get("json") or {}
    return {
        "exists": True,
        "ip": data.get("ip"),
        "noise": data.get("noise"),
        "riot": data.get("riot"),
        "classification": data.get("classification"),
        "name": data.get("name"),
        "link": data.get("link"),
        "cached": resp.get("cached", False),
    }


def crtsh_lookup(indicator: str) -> dict:
    """Lookup crt.sh certificate transparency for subdomains."""
    if not CRTSH_ENABLED:
        return {"enabled": False, "message": "crt.sh disabled"}

    if "." not in indicator or " " in indicator or "/" in indicator:
        return {"enabled": True, "skipped": True, "message": "Input is not a domain"}

    domain = indicator.strip().lower()
    resp = _api_request_json(
        "GET",
        "https://crt.sh/",
        params={"q": f"%.{domain}", "output": "json"},
        use_cache=True,
    )
    if not resp.get("ok"):
        return {"exists": False, "status": resp.get("status"), "message": "crt.sh query error"}

    entries = resp.get("json") or []
    names = set()
    for entry in entries[:200]:
        for name in str(entry.get("name_value", "")).split("\n"):
            name = name.strip().lower()
            if name.endswith(domain):
                names.add(name)

    subdomains = sorted(names)
    return {
        "exists": len(subdomains) > 0,
        "domain": domain,
        "subdomains_count": len(subdomains),
        "subdomains": subdomains[:30],
        "cached": resp.get("cached", False),
    }


def urlhaus_lookup(indicator: str) -> dict:
    """Lookup URLhaus for URL/domain malware sightings."""
    if not URLHAUS_ENABLED:
        return {"enabled": False, "message": "URLhaus disabled"}

    target = indicator.strip()
    if not target:
        return {"enabled": True, "skipped": True, "message": "Empty indicator"}

    if target.startswith("http://") or target.startswith("https://"):
        data = {"url": target}
    elif "." in target:
        data = {"host": target}
    else:
        return {"enabled": True, "skipped": True, "message": "Input is not URL/domain"}

    resp = _api_request_json(
        "POST",
        "https://urlhaus-api.abuse.ch/v1/url/",
        data=data,
        use_cache=False,
    )
    # Fallback to host endpoint if URL endpoint returns no data for host query.
    if data.get("host") and (not resp.get("ok") or (resp.get("json") or {}).get("query_status") == "no_results"):
        resp = _api_request_json(
            "POST",
            "https://urlhaus-api.abuse.ch/v1/host/",
            data=data,
            use_cache=False,
        )

    payload = resp.get("json") or {}
    status = payload.get("query_status")
    if status in {"ok", "ok_url", "ok_host"}:
        urls = payload.get("urls") or []
        return {
            "exists": True,
            "query_status": status,
            "blacklist_hits": len(urls),
            "urls": urls[:10],
        }
    return {"exists": False, "query_status": status or "no_results"}


def ipapi_lookup(indicator: str) -> dict:
    """Free geolocation fallback via ipapi.co (IP only)."""
    if not IPAPI_ENABLED:
        return {"enabled": False, "message": "ipapi disabled"}
    if not _is_ip_address(indicator):
        return {"enabled": True, "skipped": True, "message": "Input is not an IP address"}

    try:
        resp = _api_request_json(
            "GET",
            f"https://ipapi.co/{quote(indicator, safe='')}/json/",
            use_cache=True,
        )
        if not resp.get("ok"):
            return {"exists": False, "status": resp.get("status"), "message": "ipapi query error"}

        data = resp.get("json") or {}
        return {
            "exists": True,
            "ip": data.get("ip"),
            "city": data.get("city"),
            "region": data.get("region"),
            "country_name": data.get("country_name"),
            "org": data.get("org"),
            "asn": data.get("asn"),
            "timezone": data.get("timezone"),
            "cached": resp.get("cached", False),
        }
    except requests.RequestException as e:
        logger.warning(f"ipapi lookup failed for {indicator}: {e}")
        return {"exists": False, "error": str(e)}
    except Exception as e:
        logger.warning(f"ipapi lookup failed for {indicator}: {e}")
        return {"exists": False, "error": str(e)}


def run_external_enrichment(raw_input: str, base_username: str) -> Dict[str, Any]:
    """Runs configured external API enrichments with safe fallbacks."""
    domain_candidate = raw_input.strip()
    if "@" in domain_candidate:
        domain_candidate = domain_candidate.split("@")[-1]
    elif "." not in domain_candidate or " " in domain_candidate:
        domain_candidate = base_username

    return {
        "reddit_api": reddit_lookup(base_username),
        "youtube_api": youtube_lookup(base_username),
        "abuseipdb": abuseipdb_lookup(raw_input),
        "ipinfo": ipinfo_lookup(raw_input),
        "virustotal": virustotal_lookup(raw_input),
        "urlscan": urlscan_lookup(raw_input),
        "otx": otx_lookup(raw_input),
        "greynoise": greynoise_lookup(raw_input),
        "crtsh": crtsh_lookup(domain_candidate),
        "urlhaus": urlhaus_lookup(raw_input),
        "ipapi": ipapi_lookup(raw_input),
    }


def compute_risk_assessment(result: Dict[str, Any]) -> Dict[str, Any]:
    """Compute a 0-100 risk score from profile spread and threat intel enrichments."""
    profile_status = (result.get("profile_status") or {})
    total_profiles = len(profile_status)
    found_profiles = sum(1 for v in profile_status.values() if v.get("exists")) if total_profiles else 0
    found_pct = round((found_profiles / total_profiles) * 100.0, 1) if total_profiles else 0.0

    external = (result.get("external_apis") or {})
    vt = external.get("virustotal") or {}
    abuse = external.get("abuseipdb") or {}

    vt_mal = int(vt.get("malicious") or 0)
    vt_susp = int(vt.get("suspicious") or 0)
    abuse_score = float(abuse.get("abuse_confidence_score") or 0.0)

    # Weighted formula
    base = found_pct * 0.35
    vt_component = min(100.0, (vt_mal * 15.0) + (vt_susp * 8.0)) * 0.4
    abuse_component = min(100.0, abuse_score) * 0.25

    risk_score = round(max(0.0, min(100.0, base + vt_component + abuse_component)), 1)

    if risk_score >= 70:
        level = "High"
    elif risk_score >= 40:
        level = "Medium"
    else:
        level = "Low"

    return {
        "score": risk_score,
        "level": level,
        "factors": {
            "found_profiles_pct": found_pct,
            "virustotal_malicious": vt_mal,
            "virustotal_suspicious": vt_susp,
            "abuseipdb_confidence": abuse_score,
        },
    }


# ---------------------------------------------------
# Esegue una scansione completa per un username/email
# ---------------------------------------------------
def run_scan_for_input(
    user_input: str,
    do_status: bool = True,
    do_preview: bool = True,
    do_github: bool = True,
    max_profiles: int = 8,
    do_external_apis: bool = True
) -> dict:
    """Esegue una scansione completa per un username/email."""
    # Fix email parsing: gestisci caso senza @
    base = user_input.split("@")[0] if "@" in user_input else user_input
    services = build_services_for_username(base)

    result = {
        "username": base,
        "queried_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "social_profiles": services
    }

    if do_status:
        result["profile_status"] = check_profiles_exist(services, limit=max_profiles)
    if do_preview:
        result["scraping_preview"] = scrape_social_preview(services)
    if do_github:
        result["github_api"] = github_lookup(base)
    if do_external_apis:
        result["external_apis"] = run_external_enrichment(user_input.strip(), base)

    result["risk_assessment"] = compute_risk_assessment(result)
    result["variants"] = brute_username(base)
    return result

import csv
import pandas as pd
from config import CSV_BATCH_SIZE

def run_batch_scan_from_csv(
    file_path: str,
    do_status: bool = True,
    do_preview: bool = True,
    do_github: bool = True,
    max_profiles: int = 8,
    do_external_apis: bool = True
) -> list:
    """
    Esegue scansioni batch da file CSV con chunking per memoria efficiente.
    
    Args:
        file_path: Path al file CSV
        do_status: Esegui HTTP status check
        do_preview: Esegui scraping preview
        do_github: Esegui GitHub API lookup
        max_profiles: Max profili da controllare
    
    Returns:
        Lista di risultati di scansione
    """
    results = []
    try:
        # Usa chunking per evitare OOM con file grandi
        chunks = pd.read_csv(file_path, chunksize=CSV_BATCH_SIZE, dtype={'username': str})
        for chunk_idx, chunk in enumerate(chunks):
            logger.info(f"Processing chunk {chunk_idx + 1} ({len(chunk)} usernames)")
            for _, row in chunk.iterrows():
                user_input = str(row.get('username', '')).strip()
                if not user_input or user_input.lower() == 'username':
                    continue
                logger.debug(f"[BATCH] Scansione di: {user_input}")
                res = run_scan_for_input(
                    user_input,
                    do_status=do_status,
                    do_preview=do_preview,
                    do_github=do_github,
                    max_profiles=max_profiles,
                    do_external_apis=do_external_apis,
                )
                results.append(res)
    except Exception as e:
        logger.exception(f"Errore durante batch CSV scan da {file_path}")
    return results
# ---------------------------
# Profilatore OSINT automatico
# ---------------------------
def build_osint_profile_summary(result: dict) -> dict:
    """
    Analizza i risultati OSINT e produce un profilo sintetico:
    livello di attività, categorie, piattaforme principali, bio e sintesi.
    """
    profile_status = result.get("profile_status", {}) or {}
    scraping_preview = result.get("scraping_preview", {}) or {}
    github_info = result.get("github_api", {}) or {}

    active_platforms = [p for p, v in profile_status.items() if v.get("exists")]
    activity_level = "Basso"
    if len(active_platforms) >= 6:
        activity_level = "Molto alto"
    elif len(active_platforms) >= 3:
        activity_level = "Medio"

    # Cerca parole chiave da meta e bio
    text_data = " ".join([
        str(v.get("meta_preview", {}).get("description", "")) +
        str(v.get("meta_preview", {}).get("title", "")) for v in scraping_preview.values()
    ])
    text_data += " " + json.dumps(github_info)

    keywords = {
        "tech": ["developer", "engineer", "python", "coding", "github"],
        "social": ["instagram", "tiktok", "selfie", "friends", "travel"],
        "crypto": ["crypto", "bitcoin", "blockchain", "nft"],
        "gaming": ["twitch", "gamer", "game", "steam", "playstation"],
        "creative": ["art", "music", "design", "photo", "illustration"],
    }

    detected_categories = [k for k, kw in keywords.items() if any(word in text_data.lower() for word in kw)]
    main_category = detected_categories[0] if detected_categories else "Generico"

    summary_text = f"Profilo {main_category}, attività {activity_level.lower()}. "
    if github_info:
        summary_text += f"Attivo su GitHub con {github_info.get('public_repos',0)} repository pubbliche. "
    if "instagram" in active_platforms:
        summary_text += "Presenza rilevata su Instagram. "
    if "twitter" in active_platforms or "x" in active_platforms:
        summary_text += "Attività sociale su Twitter/X. "
    if "linkedin" in active_platforms:
        summary_text += "Presenza professionale su LinkedIn. "

    return {
        "activity_level": activity_level,
        "active_platforms": active_platforms,
        "categories": detected_categories,
        "summary": summary_text.strip()
    }