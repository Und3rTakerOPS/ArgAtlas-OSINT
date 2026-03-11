# engine_core_advanced.py — Advanced OSINT Features
# Funzioni avanzate: Email Reverse Lookup, Account Correlation, Alert Triggers

import json
import logging
import requests
from typing import Dict, List, Tuple
from datetime import datetime

from config import (
    HUNTER_IO_API_KEY,
    HUNTER_IO_ENABLED,
    ALERT_CONFIG,
    CORRELATION_MIN_PLATFORMS,
    CORRELATION_MIN_SIMILARITY
)
from utils import http_get

logger = logging.getLogger(__name__)

# ---------------------------------------------------
# Email Reverse Lookup (Hunter.io API)
# ---------------------------------------------------
def reverse_lookup_email(email: str) -> Dict:
    """
    Ricerca il proprietario di un'email usando Hunter.io API (free tier).
    Ritorna nome, cognome, azienda se trovato.
    
    Args:
        email: Email da ricercare
    
    Returns:
        Dict con informazioni persona (name, first_name, last_name, company)
    """
    if not HUNTER_IO_ENABLED:
        logger.debug("Hunter.io non abilitato")
        return {"error": "Hunter.io API key non configurato"}
    
    try:
        url = f"https://api.hunter.io/v2/email-finder?email={email}&domain={email.split('@')[1]}"
        headers = {"Authorization": f"Bearer {HUNTER_IO_API_KEY}"}
        
        r = http_get(url, headers=headers)
        
        if r.get("ok"):
            data = json.loads(r.get("text", "{}"))
            if data.get("data"):
                person = data["data"]
                return {
                    "found": True,
                    "first_name": person.get("first_name"),
                    "last_name": person.get("last_name"),
                    "name": person.get("name"),
                    "company": person.get("company"),
                    "seniority": person.get("seniority"),
                    "job_title": person.get("job_title")
                }
        
        return {"found": False}
    
    except Exception as e:
        logger.error(f"Errore Hunter.io lookup: {e}")
        return {"error": str(e)}


def extract_email_domain_accounts(email: str, all_results: Dict) -> List[str]:
    """
    Se email è data, analizza risultati per trovare altri account
    dello stesso dominio (es. azienda).
    
    Args:
        email: Email completa (es. user@company.com)
        all_results: Dict con risultati di tutti gli scan
    
    Returns:
        Lista di account probabili della stessa azienda
    """
    if "@" not in email:
        return []
    
    domain = email.split("@")[1]
    probable_accounts = []
    
    # Cerca pattern comuni da questo dominio
    for username, result in all_results.items():
        if "github_api" in result and result["github_api"].get("exists"):
            # GitHub spesso ha company info
            probable_accounts.append(f"{username} (possibly {domain.split('.')[0]})")
    
    return probable_accounts


# ---------------------------------------------------
# Account Correlation Detection
# ---------------------------------------------------
def calculate_similarity_score(platforms1: List[str], platforms2: List[str]) -> float:
    """
    Calcola score di similarità tra due liste di piattaforme (0-1).
    Misura quante piattaforme comuni hanno.
    """
    if not platforms1 or not platforms2:
        return 0.0
    
    common = len(set(platforms1) & set(platforms2))
    union = len(set(platforms1) | set(platforms2))
    
    return round(common / union, 2) if union > 0 else 0.0


def suggest_account_correlations(all_results: List[Dict]) -> List[Dict]:
    """
    Analizza multiple scansioni e suggerisce correlazioni tra account.
    Due account sono correlati se:
    - Hanno 3+ piattaforme in comune
    - Hanno similarity score > 70%
    
    Args:
        all_results: Lista di risultati scan (da database)
    
    Returns:
        Lista di correlazioni suggerite con score
    """
    correlations = []
    
    for i, result1 in enumerate(all_results):
        for result2 in all_results[i+1:]:
            platforms1 = result1.get("active_platforms", result1.get("profile_status", {}).keys())
            platforms2 = result2.get("active_platforms", result2.get("profile_status", {}).keys())
            
            # Converti in liste se necessario
            if not isinstance(platforms1, list):
                platforms1 = [p for p, v in platforms1.items() if v.get("exists")] if isinstance(platforms1, dict) else []
            if not isinstance(platforms2, list):
                platforms2 = [p for p, v in platforms2.items() if v.get("exists")] if isinstance(platforms2, dict) else []
            
            common_platforms = set(platforms1) & set(platforms2)
            similarity = calculate_similarity_score(platforms1, platforms2)
            
            # Soglie di correlazione
            if len(common_platforms) >= CORRELATION_MIN_PLATFORMS and similarity >= CORRELATION_MIN_SIMILARITY:
                correlations.append({
                    "account1": result1.get("username"),
                    "account2": result2.get("username"),
                    "common_platforms": list(common_platforms),
                    "similarity_score": similarity,
                    "confidence": "HIGH" if similarity > 0.85 else "MEDIUM"
                })
    
    return sorted(correlations, key=lambda x: x["similarity_score"], reverse=True)


# ---------------------------------------------------
# Alert System
# ---------------------------------------------------
def detect_verified_accounts(result: Dict) -> List[str]:
    """
    Rileva account verificati da indicatori HTML/meta.
    Cerca badge di verifica, checkmark, ecc.
    """
    verified = []
    scraping_preview = result.get("scraping_preview", {}) or {}
    
    verification_keywords = ["verified", "✓", "☑️", "checkmark", "official", "verified_badge"]
    
    for platform, data in scraping_preview.items():
        if data.get("found"):
            html_text = str(data.get("meta_preview", {})).lower()
            if any(kw in html_text for kw in verification_keywords):
                verified.append(platform)
    
    return verified


def generate_alerts(scan_id: int, result: Dict) -> List[Dict]:
    """
    Genera alert basato su soglie configurate in ALERT_CONFIG.
    
    Args:
        scan_id: ID dello scan nel database
        result: Risultato della scansione
    
    Returns:
        Lista di alert generati
    """
    if not ALERT_CONFIG.get("enable_alerts"):
        return []
    
    alerts = []
    profile_status = result.get("profile_status", {}) or {}
    
    # Calcola percentuale profili trovati
    if profile_status:
        found = sum(1 for v in profile_status.values() if v.get("exists"))
        found_pct = (found / len(profile_status) * 100.0)
    else:
        found_pct = 0.0
    
    # Alert 1: Alta percentuale profili trovati
    if found_pct >= ALERT_CONFIG.get("min_found_pct_threshold", 50.0):
        alerts.append({
            "type": "HIGH_PROFILE_COUNT",
            "message": f"Account trovato su {found_pct:.1f}% piattaforme (soglia: {ALERT_CONFIG.get('min_found_pct_threshold')}%)",
            "severity": "MEDIUM"
        })
    
    # Alert 2: Account verificati rilevati
    if ALERT_CONFIG.get("verified_account_alert"):
        verified = detect_verified_accounts(result)
        if verified:
            alerts.append({
                "type": "VERIFIED_ACCOUNT",
                "message": f"Account verificato rilevato: {', '.join(verified)}",
                "severity": "HIGH"
            })
    
    # Alert 3: Alto numero di follower (se tracciato)
    github_info = result.get("github_api", {}) or {}
    if github_info.get("followers", 0) > ALERT_CONFIG.get("high_follower_threshold", 10000):
        alerts.append({
            "type": "HIGH_FOLLOWER_COUNT",
            "message": f"GitHub followers: {github_info.get('followers')} (soglia: {ALERT_CONFIG.get('high_follower_threshold')})",
            "severity": "MEDIUM"
        })
    
    # Alert 4: Account attivo su piattaforme sensibili
    sensitive_platforms = ["crypto", "banking", "military", "government"]
    active_platforms = [p.lower() for p in profile_status.keys() if profile_status[p].get("exists")]
    
    suspicious = [p for p in active_platforms if any(sp in p for sp in sensitive_platforms)]
    if suspicious:
        alerts.append({
            "type": "SENSITIVE_PLATFORM",
            "message": f"Attività su piattaforme sensibili: {', '.join(suspicious)}",
            "severity": "HIGH"
        })
    
    logger.debug(f"Generati {len(alerts)} alert per scan {scan_id}")
    return alerts


# ---------------------------------------------------
# Analisi pattern account
# ---------------------------------------------------
def detect_account_pattern(results: List[Dict]) -> Dict:
    """
    Analizza pattern tra multiple account per rilevare:
    - Pattern di naming (es. tutti con underscore, numeri, ecc)
    - Pattern di piattaforme preferite
    - Pattern temporale di creazione
    """
    patterns = {
        "naming_patterns": [],
        "platform_preferences": {},
        "activity_patterns": []
    }
    
    if not results:
        return patterns
    
    # Analizza pattern di naming
    usernames = [r.get("username", "") for r in results]
    has_underscore = sum(1 for u in usernames if "_" in u)
    has_numbers = sum(1 for u in usernames if any(c.isdigit() for c in u))
    
    if has_underscore > len(usernames) * 0.5:
        patterns["naming_patterns"].append("Underscore preference")
    if has_numbers > len(usernames) * 0.5:
        patterns["naming_patterns"].append("Numeric suffix pattern")
    
    # Analizza preferenze piattaforme
    platform_freq = {}
    for result in results:
        active = result.get("active_platforms", [])
        if not isinstance(active, list):
            active = [p for p, v in active.items() if v.get("exists")] if isinstance(active, dict) else []
        for p in active:
            platform_freq[p] = platform_freq.get(p, 0) + 1
    
    patterns["platform_preferences"] = sorted(
        platform_freq.items(),
        key=lambda x: x[1],
        reverse=True
    )[:5]
    
    return patterns