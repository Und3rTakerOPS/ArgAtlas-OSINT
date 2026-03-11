# ArgAtlas — Intelligence Dashboard
# Compatible with: engine_core.py, datastore.py, exporters.py, config.py
# Features: Dark theme (C3 Enterprise) • Navbar sticky auto-hide • Static sections • Global search
# Map (capitals+heatmap+clustering+threat zones) • Combined filters • Analytics extended
# Quick Scan • Single Scan (full) • Batch CSV • Reports Center • Entity Graph • Snapshot HTML
# Smart cache (invalidates on DB changes)

import os
import json
import tempfile
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional

import streamlit as st
import pandas as pd

from engine_core import (
    run_scan_for_input,
    run_batch_scan_from_csv,
    build_osint_profile_summary,
    compute_risk_assessment,
)
from datastore import (
    init_db,
    save_scan,
    load_recent,
    bulk_delete_username,
    bulk_mark_verified,
    bulk_export_usernames,
    add_scan_alert,
    get_scan_alerts,
    get_all_scan_alerts,
    update_scan_alert_status,
)
from exporters import (
    generate_pdf_report,
    generate_excel,
    generate_json,
    generate_csv_profiles,
    generate_jsonl_bulk,
    generate_csv_bulk_summary
)
from config import (
    REPORTS_PATH,
    ACCENT_COLOR,
    PAGE_TITLE,
    CACHE_LIMIT,
    CLUSTER_LEVELS,
    DEFAULT_MAP_ZOOM,
    DEFAULT_MAP_CENTER,
    THREAT_ZONES,
    MAX_CSV_ROWS,
    CSV_ENCODING,
    DEFAULT_MAX_PROFILES,
    MAX_CONCURRENT_CHECKS,
    RECENT_SCANS_LIMIT,
    LIVE_MONITOR_LIMIT,
    SKIP_DUPLICATE_DAYS,
    HUNTER_IO_ENABLED,
    ALERT_CONFIG,
    ABUSEIPDB_ENABLED,
    VIRUSTOTAL_ENABLED,
    IPINFO_ENABLED,
    REDDIT_ENABLED,
    YOUTUBE_ENABLED,
    URLSCAN_ENABLED,
    OTX_ENABLED,
    GREYNOISE_ENABLED,
    CRTSH_ENABLED,
    URLHAUS_ENABLED,
    IPAPI_ENABLED,
)
from utils import validate_username
from analysis_tools import (
    compare_scan_results,
    detect_account_pattern,
    generate_alerts,
    suggest_account_correlations,
)
from viz import (
    create_heatmap_figure,
    create_cluster_map_figure,
    create_points_map_figure,
    create_platform_bar_chart,
    create_hourly_area_chart,
    create_weekly_trend_chart,
    create_daily_timeline_chart,
    create_platform_pie_chart,
    create_entity_graph,
    create_live_activity_chart,
    export_snapshot_html,
)

# Setup logging
import logging
logger = logging.getLogger(__name__)

def reverse_lookup_email(email_or_domain: str) -> Dict:
    """
    Email reverse lookup using Hunter.io API.
    Supports email verification or domain search for associated emails.
    
    Args:
        email_or_domain: Email address or domain name
    
    Returns:
        Dict with lookup results
    """
    from config import HUNTER_IO_API_KEY, HUNTER_IO_ENABLED
    import requests
    
    if not HUNTER_IO_ENABLED or not HUNTER_IO_API_KEY:
        return {"found": False, "message": "Hunter.io API not configured"}
    
    try:
        # Determine if it's an email or domain
        if "@" in email_or_domain:
            # Email verification
            url = f"https://api.hunter.io/v2/email-verifier?email={email_or_domain}&api_key={HUNTER_IO_API_KEY}"
            response = requests.get(url, timeout=10)
            data = response.json()
            
            if response.status_code == 200 and data.get("data"):
                result = data["data"]
                return {
                    "found": result.get("result") == "deliverable",
                    "email": email_or_domain,
                    "verification": result.get("result"),
                    "score": result.get("score"),
                    "sources": result.get("sources", []),
                    "message": f"Email {result.get('result')} (score: {result.get('score')})"
                }
            else:
                return {"found": False, "message": "Email verification failed", "error": data.get("errors", [])}
        else:
            # Domain search for associated emails
            url = f"https://api.hunter.io/v2/domain-search?domain={email_or_domain}&api_key={HUNTER_IO_API_KEY}"
            response = requests.get(url, timeout=10)
            data = response.json()
            
            if response.status_code == 200 and data.get("data"):
                domain_data = data["data"]
                emails = domain_data.get("emails", [])
                return {
                    "found": len(emails) > 0,
                    "domain": email_or_domain,
                    "emails_found": len(emails),
                    "emails": [{"value": e.get("value"), "type": e.get("type"), "confidence": e.get("confidence")} for e in emails[:10]],  # Limit to 10
                    "pattern": domain_data.get("pattern"),
                    "message": f"Found {len(emails)} emails for domain {email_or_domain}"
                }
            else:
                return {"found": False, "message": "Domain search failed", "error": data.get("errors", [])}
    
    except requests.exceptions.RequestException as e:
        logger.exception(f"Hunter.io API error for {email_or_domain}")
        return {"found": False, "message": f"API request failed: {str(e)}"}
    except Exception as e:
        logger.exception(f"Unexpected error in reverse lookup for {email_or_domain}")
        return {"found": False, "message": f"Unexpected error: {str(e)}"}


def _prepare_export_file(state_key: str, export_name: str, generator, *args) -> None:
    try:
        path = generator(*args)
        st.session_state.setdefault("prepared_exports", {})[state_key] = {
            "path": path,
            "name": export_name,
        }
    except Exception as e:
        logger.error(f"Errore preparazione export {export_name}: {e}", exc_info=True)
        st.error(f"Impossibile preparare l'export {export_name}.")


def _cleanup_prepared_exports(max_age_hours: int = 12, max_entries: int = 40) -> None:
    prepared = st.session_state.get("prepared_exports", {})
    if not prepared:
        return

    now_ts = datetime.now(timezone.utc).timestamp()
    cutoff = max_age_hours * 3600
    cleaned: Dict[str, Dict[str, str]] = {}

    # Keep newest entries and evict stale/missing files.
    items = []
    for key, meta in prepared.items():
        path = meta.get("path") if isinstance(meta, dict) else None
        if not path or not os.path.exists(path):
            continue
        try:
            mtime = os.path.getmtime(path)
            age = now_ts - mtime
            if age <= cutoff:
                items.append((mtime, key, meta))
            else:
                try:
                    os.remove(path)
                except OSError:
                    logger.debug(f"Impossibile rimuovere export obsoleto: {path}")
        except OSError:
            continue

    items.sort(key=lambda item: item[0], reverse=True)
    for _, key, meta in items[:max_entries]:
        cleaned[key] = meta

    # Remove overflow files from disk as well.
    for _, _, meta in items[max_entries:]:
        path = meta.get("path")
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                logger.debug(f"Impossibile rimuovere export in overflow: {path}")

    st.session_state["prepared_exports"] = cleaned


def _clear_all_prepared_exports() -> int:
    prepared = st.session_state.get("prepared_exports", {})
    removed = 0
    for meta in prepared.values():
        path = meta.get("path") if isinstance(meta, dict) else None
        if path and os.path.exists(path):
            try:
                os.remove(path)
                removed += 1
            except OSError:
                logger.debug(f"Impossibile rimuovere export preparato: {path}")
    st.session_state["prepared_exports"] = {}
    return removed


def _render_prepared_download(state_key: str, label: str, file_name: Optional[str] = None, mime: Optional[str] = None) -> None:
    prepared = st.session_state.get("prepared_exports", {}).get(state_key)
    if not prepared:
        return

    path = prepared.get("path")
    if not path or not os.path.exists(path):
        return

    with open(path, "rb") as file_handle:
        st.download_button(
            label,
            file_handle,
            file_name=file_name or os.path.basename(path),
            mime=mime,
            key=f"download_{state_key}",
        )

# =============================================================================
# PAGE CONFIG + THEME
# =============================================================================
st.set_page_config(
    page_title=PAGE_TITLE,
    page_icon="🛰️",
    layout="wide",
    initial_sidebar_state="collapsed"  # Sidebar collassata per default per più spazio
)

# CSS per sidebar FISSA + tema scuro
st.markdown(f"""
<style>
/* Tema scuro */
:root {{
    --bg:#0a0d14;
    --bg2:#111522;
    --card:#151a24;
    --muted:#98a2b3;
    --text:#e6eaf2;
    --border:#232a38;
    --accent:{ACCENT_COLOR};
    --ok:#3ecf8e;
    --warn:#ffb84d;
    --danger:#ff5d5d;
}}
html, body {{
    background:linear-gradient(180deg, var(--bg) 0%, var(--bg2) 100%) !important;
    color:var(--text);
  font-family:'Poppins',system-ui,Segoe UI,Roboto,Arial,sans-serif;
  font-size: 14px !important;
}}

/* Sidebar FISSA - Streamlit container */
section[data-testid="stSidebar"] {{
    width: 250px !important;
  font-size: 13px !important;
    background: linear-gradient(180deg, #0c1018 0%, #121824 100%) !important;
  border-right: 1px solid var(--border) !important;
}}

/* Riduce lo spazio vuoto in alto nella sidebar */
[data-testid="stSidebarContent"] {{
    padding-top: 0.5rem !important;
}}

[data-testid="collapsedControl"] {{
    margin-top: 0.25rem !important;
}}

section[data-testid="stSidebar"] hr {{
    margin: 0.75rem 0 !important;
}}

/* Layout principale si adatta automaticamente */
[data-testid="stMainBlockContainer"],
section[data-testid="stMain"],
div.block-container {{
    padding-left: 1.25rem !important;
    padding-right: 1.25rem !important;
}}

[data-testid="stAppViewContainer"] {{
    background: linear-gradient(180deg, #0a0d14 0%, #111522 100%) !important;
}}

/* Block container padding */
.block-container {{
    padding-left: 1.25rem !important;
    padding-right: 1.25rem !important;
  padding-top: 1rem !important;
}}

/* Top monitor bar */
.monitor-shell {{
    background: linear-gradient(90deg, #121722 0%, #1a2030 100%);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 12px 16px;
    margin-bottom: 14px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}}
.monitor-title {{
    font-size: 1.15rem;
    font-weight: 700;
    color: #f2f5fb;
}}
.monitor-sub {{
    color: var(--muted);
    font-size: 0.85rem;
}}
.live-pill {{
    display:inline-block;
    background: rgba(62, 207, 142, 0.16);
    color: var(--ok);
    border: 1px solid rgba(62, 207, 142, 0.35);
    border-radius: 999px;
    padding: 4px 10px;
    font-weight: 600;
    font-size: 0.8rem;
}}

/* KPI cards */
.kpi-card {{
    background: linear-gradient(180deg, #131925 0%, #111622 100%);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 12px 14px;
    min-height: 88px;
}}
.kpi-value {{
    font-size: 1.7rem;
    color: #f8fbff;
    font-weight: 700;
    line-height: 1.1;
}}
.kpi-label {{
    color: var(--muted);
    font-size: 0.8rem;
    margin-top: 2px;
    text-transform: uppercase;
    letter-spacing: .04em;
}}
.kpi-trend {{
    margin-top: 8px;
    display: inline-block;
    font-size: 0.74rem;
    padding: 2px 8px;
    border-radius: 999px;
    font-weight: 600;
}}
.kpi-up {{
    color: var(--ok);
    background: rgba(62, 207, 142, 0.16);
    border: 1px solid rgba(62, 207, 142, 0.35);
}}
.kpi-down {{
    color: var(--danger);
    background: rgba(255, 93, 93, 0.16);
    border: 1px solid rgba(255, 93, 93, 0.35);
}}
.kpi-stable {{
    color: #7ecbff;
    background: rgba(126, 203, 255, 0.14);
    border: 1px solid rgba(126, 203, 255, 0.35);
}}

.side-live-title {{
    font-size: 0.75rem;
    letter-spacing: .08em;
    text-transform: uppercase;
    color: var(--muted);
    margin: 10px 0 6px;
}}
.side-live-item {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 6px 8px;
    border-radius: 8px;
    background: rgba(40, 54, 86, 0.18);
    margin-bottom: 6px;
    color: #dce7ff;
    font-size: 0.86rem;
}}
.side-live-badge {{
    background: rgba(62, 207, 142, 0.16);
    border: 1px solid rgba(62, 207, 142, 0.35);
    color: var(--ok);
    border-radius: 999px;
    font-size: 0.66rem;
    padding: 1px 7px;
    font-weight: 700;
}}

.ops-card {{
    background: linear-gradient(180deg, #131926 0%, #101521 100%);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 12px;
    min-height: 540px;
}}
.feed-item {{
    border-left: 3px solid #8ce56c;
    padding: 8px 10px;
    margin-bottom: 10px;
    background: rgba(140, 229, 108, 0.06);
    border-radius: 8px;
}}
.feed-title {{
    color: #eaf1ff;
    font-size: 0.9rem;
    font-weight: 600;
}}
.feed-meta {{
    color: var(--muted);
    font-size: 0.76rem;
    margin-top: 4px;
}}

/* Stili bottoni */
div.stButton > button {{
  background: var(--accent);
  color: white;
  border: none;
  border-radius: 10px;
  font-weight: 600;
  transition: all 0.2s ease;
}}
div.stButton > button:hover {{
  filter: brightness(1.08);
  transform: translateY(-2px);
}}

/* Metric cards - IMPORTANTE per il layout a 5 colonne */
.metric-card {{
  background: linear-gradient(180deg, #121721 0%, #10151D 100%);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 12px !important;
  text-align: center;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
  transition: all 0.2s ease;
  min-height: 80px;
  display: flex;
  flex-direction: column;
  justify-content: center;
}}
.metric-card:hover {{
  border-color: var(--accent);
  box-shadow: 0 6px 20px rgba(0, 123, 255, 0.15);
}}
.metric-card h3 {{
  margin: 0.2rem 0;
  color: #FFFFFF;
  font-weight: 700;
  font-size: 1.2em;
}}
.metric-card p {{
  margin: 0;
  color: var(--muted);
  font-size: 0.75rem;
  font-weight: 500;
}}

/* DataFrames */
div[data-testid="stDataFrame"] {{
    background: #0f141b;
  border: 1px solid var(--border);
  border-radius: 12px;
}}

/* Headings */
h1, h2, h3, h4, h5 {{
  color: var(--accent);
  font-weight: 700;
    margin-top: 1rem !important;
}}

h1 {{
    font-size: 2.4rem !important;
  margin-bottom: 0.3rem !important;
}}

h2 {{
  font-size: 1.3rem !important;
  margin-bottom: 0.6rem !important;
}}

hr {{
  border: 1px solid var(--border);
  margin: 2rem 0 !important;
}}

/* Section descriptions */
.section-desc {{
  color: var(--muted);
  font-size: 0.9rem;
  margin-bottom: 1.5rem;
  font-style: italic;
  letter-spacing: 0.3px;
}}

/* Radio buttons e selectbox styling */
div[data-testid="stRadio"] label,
div[data-testid="stSelectbox"] label,
div[data-testid="stCheckbox"] label {{
  color: #E6EDF3 !important;
  font-weight: 500 !important;
}}

/* Toggle styling */
div[data-testid="stToggle"] {{
  margin: 0.5rem 0 !important;
}}

/* Markdown styling */
st-markdown {{
  color: #E6EDF3;
}}

/* Colonne spacing */
[class*="stColumn"] {{
  padding: 0 0.5rem !important;
}}

/* Expander styling */
details {{
  border: 1px solid var(--border) !important;
    border-radius: 12px !important;
    background: linear-gradient(180deg, #101521 0%, #0f141f 100%) !important;
    padding: 0.4rem 0.6rem !important;
}}

details summary {{
    color: #dbe4ff !important;
  font-weight: 600 !important;
}}

/* Sidebar nav radio style */
div[data-testid="stSidebar"] div[role="radiogroup"] > label {{
    background: rgba(50, 76, 122, 0.16);
    border: 1px solid transparent;
    border-radius: 10px;
    margin-bottom: 6px;
    padding: 8px 10px;
}}
div[data-testid="stSidebar"] div[role="radiogroup"] > label:hover {{
    border-color: rgba(95, 138, 228, 0.45);
}}

/* Caption styling */
.caption {{
  color: var(--muted) !important;
  font-size: 0.85rem !important;
  margin: 0.5rem 0 !important;
}}
</style>
""", unsafe_allow_html=True)

# =============================================================================
# DEMO DATA FUNCTION (Testing/Demo)
# =============================================================================

def generate_demo_data(num_scans: int = 5):
    """Genera dati demo per testare la dashboard quando il database è vuoto."""
    import random
    
    demo_usernames = [
        "john_dev", "sarah_crypto", "alex_gamer", "emma_artist", "mike_hacker",
        "alice_data", "bob_finance", "charlie_security", "diana_ml", "evan_fullstack"
    ]
    
    platforms_subset = [
        "GitHub", "X / Twitter", "Instagram", "LinkedIn", "Reddit",
        "YouTube", "Twitch", "Dev.to", "Stack Overflow", "Spotify"
    ]
    
    for i in range(min(num_scans, len(demo_usernames))):
        username = demo_usernames[i]
        
        # Genera status profili casuali
        profile_status = {}
        for platform in random.sample(platforms_subset, random.randint(3, 7)):
            profile_status[platform] = {"exists": True, "status": 200, "url": f"https://example.com/{username}"}
        
        # Completa con piattaforme non trovate
        for platform in platforms_subset:
            if platform not in profile_status:
                profile_status[platform] = {"exists": False, "status": 404, "url": f"https://example.com/{username}"}
        
        # Calcola data casuale negli ultimi 3 giorni
        hours_back = random.randint(0, 72)
        queried_at = (datetime.now(timezone.utc) - pd.Timedelta(hours=hours_back)).isoformat()
        
        result = {
            "username": username,
            "queried_at": queried_at,
            "profile_status": profile_status,
            "social_profiles": {p: f"https://example.com/{username}" for p in profile_status.keys()},
            "github_api": {"exists": True, "followers": random.randint(10, 500), "public_repos": random.randint(5, 30)},
            "scraping_preview": {},
            "variants": []
        }
        
        save_scan(result, skip_duplicate_days=SKIP_DUPLICATE_DAYS)
    
    logger.info(f"Demo data generato: {num_scans} scansioni")

# =============================================================================
# PAGE / THEME
# =============================================================================
ACCENT = ACCENT_COLOR
init_db()

# Session state initialization (esplicita per chiarezza)
if "data_nonce" not in st.session_state:
    st.session_state["data_nonce"] = 0
if "filters" not in st.session_state:
    st.session_state["filters"] = {}
if "global_query" not in st.session_state:
    st.session_state["global_query"] = ""
if "cache_timestamp" not in st.session_state:
    st.session_state["cache_timestamp"] = None
if "background_theme" not in st.session_state:
    st.session_state["background_theme"] = "dark_default"
if "prepared_exports" not in st.session_state:
    st.session_state["prepared_exports"] = {}

# Keep export cache tidy across reruns.
_cleanup_prepared_exports()

# Preset di background personalizzati
BACKGROUND_THEMES = {
    "dark_default": {
        "name": "🌙 Scuro Predefinito",
        "bg": "linear-gradient(180deg, #0B0E13 0%, #0C1118 100%)"
    },
    "dark_blue": {
        "name": "🔵 Scuro Blu",
        "bg": "linear-gradient(180deg, #0A0E27 0%, #1A1F3A 100%)"
    },
    "dark_purple": {
        "name": "💜 Scuro Viola",
        "bg": "linear-gradient(180deg, #1A0B2E 0%, #2D1B4E 100%)"
    },
    "dark_green": {
        "name": "💚 Scuro Verde",
        "bg": "linear-gradient(180deg, #0B1F0B 0%, #1A3A1A 100%)"
    },
    "dark_red": {
        "name": "❤️ Scuro Rosso",
        "bg": "linear-gradient(180deg, #2B0B0B 0%, #3A1A1A 100%)"
    },
    "cyberpunk": {
        "name": "⚡ Cyberpunk",
        "bg": "linear-gradient(180deg, #0A0210 0%, #1A0A2E 50%, #0F3460 100%)"
    },
    "ocean": {
        "name": "🌊 Oceano",
        "bg": "linear-gradient(180deg, #0B1F3A 0%, #0D47A1 50%, #01579B 100%)"
    },
    "forest": {
        "name": "🌲 Foresta",
        "bg": "linear-gradient(180deg, #0D2818 0%, #1B4D36 50%, #0F3820 100%)"
    },
    "sunset": {
        "name": "🌅 Tramonto",
        "bg": "linear-gradient(180deg, #1A0E0E 0%, #4A2C2C 50%, #2C1A1A 100%)"
    },
    "galaxy": {
        "name": "🌌 Galassia",
        "bg": "linear-gradient(180deg, #0A0520 0%, #1B0B4D 50%, #0D0535 100%)"
    }
}

# CSS + Navbar sticky auto-hide + subtle animations
def get_dynamic_css(background_theme: str = "dark_default") -> str:
    """Genera CSS dinamico basato sul tema di background scelto."""
    theme = BACKGROUND_THEMES.get(background_theme, BACKGROUND_THEMES["dark_default"])
    bg_style = theme["bg"]
    
    return f"""
<style>
:root {{
  --bg:#0B0E13; --card:#121721; --muted:#9AA7B1; --border:#1E2732; --accent:{ACCENT};
}}

html, body {{
  background: {bg_style} !important;
  color:#E6EDF3; 
  font-family:'Poppins',system-ui,Segoe UI,Roboto,Arial,sans-serif;
}}

[data-testid="stAppViewContainer"] {{
  background: {bg_style} !important;
}}

/* Applica il tema solo ai contenitori principali della sidebar */
[data-testid="stSidebar"],
[data-testid="stSidebar"] > div,
[data-testid="stSidebarContent"] {{
  background: {bg_style} !important;
}}

[data-testid="stSidebar"] hr {{
    border-color: var(--border) !important;
}}

.stMainBlockContainer {{
  background: {bg_style} !important;
}}

.section-desc {{ color:#96A3AE; margin-top:-6px; font-size:.92rem; }}
hr {{ border:1px solid var(--border); }}

.metric-card {{ background:linear-gradient(180deg, #121721 0%, #10151D 100%);
  border:1px solid var(--border); border-radius:14px; padding:12px; text-align:center; }}
.metric-card h3 {{ margin:.2rem 0; color:#FFFFFF; font-weight:700; font-size:1.2em; }}
.metric-card p {{ margin:0; color:var(--muted); font-size:0.75rem; }}

div[data-testid="stDataFrame"] {{ background:#0f141a; border:1px solid var(--border); border-radius:12px; }}
div.stButton > button {{ background: var(--accent); color:white; border:none; border-radius:10px; }}
div.stButton > button:hover {{ filter:brightness(1.08); }}
</style>
"""

# Applica il CSS dinamico DOPO la sidebar (così viene rigenerato ad ogni rerun)
css_placeholder = st.empty()
# Il CSS sarà applicato dopo la sidebar, vedere riga con "Applica il CSS dinamico DOPO la sidebar"

# Read hash for global search / refresh
qs = st.query_params
if "q" in qs:
    st.session_state["global_query"] = qs.get("q") or ""
if "refresh" in qs:
    st.session_state["data_nonce"] += 1

# =============================================================================
# DATA HELPERS
# =============================================================================

def _load_capitals() -> List[Tuple[str, str, float, float]]:
    """
    Carica i dati dei capitali dal file JSON con fallback robusto.
    
    Returns:
        Lista di tuple (country, capital, lat, lon)
    """
    default_capitals = [("Italy", "Rome", 41.9028, 12.4964)]
    
    try:
        capitals_file = os.path.join(os.path.dirname(__file__), "data", "capitals.json")
        with open(capitals_file, "r", encoding="utf-8") as f:
            capitals_data = json.load(f)
        
        capitals = [(c[0], c[1], c[2], c[3]) for c in capitals_data]
        logger.info(f"Caricate {len(capitals)} capitali dal file JSON")
        return capitals
    
    except FileNotFoundError:
        logger.warning("File capitals.json non trovato, usando dati di fallback")
        return default_capitals
    except json.JSONDecodeError as e:
        logger.error(f"Errore parsing capitals.json: {e}")
        return default_capitals
    except Exception as e:
        logger.error(f"Errore caricamento capitali: {e}")
        return default_capitals


def _validate_csv(file_path: str) -> Tuple[bool, str | pd.DataFrame]:
    """
    Valida un file CSV caricato.
    
    Args:
        file_path: Percorso del file CSV
    
    Returns:
        Tuple (is_valid, dataframe_or_error_message)
    """
    encodings = [CSV_ENCODING, "utf-8-sig", "latin-1"]
    tried = []
    for encoding in encodings:
        if encoding in tried:
            continue
        tried.append(encoding)
        try:
            df = pd.read_csv(file_path, encoding=encoding)
            break
        except UnicodeDecodeError:
            continue
        except pd.errors.ParserError as e:
            return False, f"Errore parsing CSV: {e}"
        except Exception as e:
            return False, f"Errore lettura CSV: {e}"
    else:
        return False, f"Impossibile leggere il CSV con encoding supportati: {', '.join(tried)}"
        
    if df.empty:
        return False, "CSV vuoto"
    if len(df.columns) < 1:
        return False, "CSV senza colonne"
    if len(df) > MAX_CSV_ROWS:
        return False, f"CSV contiene più di {MAX_CSV_ROWS} righe"

    logger.info(f"CSV validato: {len(df)} righe (encoding={encoding})")
    return True, df


def _execute_scan(
    username: str,
    do_status: bool,
    do_preview: bool,
    do_github: bool,
    max_profiles: int,
    auto_report: bool,
    key_prefix: str
) -> bool:
    """
    Esegue una scansione OSINT per un utente.
    Funzione centralizzata per eliminare duplicazione di codice.
    
    Args:
        username: Username da scansionare
        do_status: Flag per HTTP profile check
        do_preview: Flag per scraping preview
        do_github: Flag per GitHub API
        max_profiles: Numero massimo di profili da controllare
        auto_report: Flag per auto-salvare PDF/Excel
        key_prefix: Prefisso per le chiavi Streamlit
    
    Returns:
        True se scan completata con successo, False altrimenti
    """
    is_valid, error_msg = validate_username(username)
    if not is_valid:
        st.error(error_msg)
        logger.warning(f"Username non valido: {username} — Errore: {error_msg}")
        return False
    
    try:
        with st.spinner("Esecuzione scansione in corso..."):
            logger.debug(f"Inizio scan: username={username}, do_status={do_status}, "
                        f"do_preview={do_preview}, do_github={do_github}, max_profiles={max_profiles}")
            
            result = run_scan_for_input(
                username.strip(),
                do_status=do_status,
                do_preview=do_preview,
                do_github=do_github,
                max_profiles=max_profiles
            )
            
            saved = save_scan(result, skip_duplicate_days=SKIP_DUPLICATE_DAYS)
            if saved:
                st.session_state["data_nonce"] += 1
                logger.info(f"Scan completato e salvato: {username}")
                st.success(f"Scansione completata per {username} ✅")
            else:
                logger.info(f"Scan completato ma non salvato (duplicato recente): {username}")
                st.warning(
                    f"Scansione completata per {username}, ma non salvata per evitare duplicati negli ultimi {SKIP_DUPLICATE_DAYS} giorni."
                )
            
            _display_scan_results(result, auto_report=auto_report, key_prefix=key_prefix)
            return True
    
    except Exception as e:
        logger.error(f"Errore durante scan di {username}: {e}", exc_info=True)
        st.error(f"Errore durante la scansione: {e}")
        return False

def _display_scan_results(result: Dict, auto_report: bool = False, key_prefix: str = ""):
    """
    Funzione unificata per mostrare risultati di scansione.
    """
    try:
        from exporters import generate_pdf_report, generate_excel
        from engine_core import build_osint_profile_summary

        # Profilazione automatica
        try:
            prof = build_osint_profile_summary(result)
            st.subheader("🧠 Profilazione automatica")
            st.write(f"**Livello attività:** {prof.get('activity_level','-')}")
            st.write(f"**Piattaforme attive:** {', '.join(prof.get('active_platforms', [])) or 'Nessuna'}")
            st.write(f"**Categorie:** {', '.join(prof.get('categories', [])) or 'Nessuna'}")
            if prof.get("summary"):
                st.info(prof["summary"])
        except Exception as e:
            logger.warning(f"Errore profilazione per {result.get('username')}: {e}")
            st.warning("Impossibile completare la profilazione automatica")

        # Risultati profili
        ps = result.get("profile_status", {})
        if ps:
            st.subheader("Risultati profili")
            dfp = pd.DataFrame([{
                "Piattaforma": p,
                "URL": d.get("url",""),
                "Stato": d.get("status",""),
                "Profilo trovato": "✅" if d.get("exists") else "❌"
            } for p,d in ps.items()])
            st.dataframe(dfp, use_container_width=True)
        else:
            st.warning("Nessun profilo rilevato.")

        risk = result.get("risk_assessment") or compute_risk_assessment(result)
        st.subheader("Risk Assessment")
        r1, r2 = st.columns(2)
        with r1:
            st.metric("Risk Score", f"{risk.get('score', 0):.1f}/100")
        with r2:
            st.metric("Risk Level", risk.get("level", "Low"))

        # Dettagli GitHub
        gh = result.get("github_api")
        if gh:
            st.subheader("Dettagli GitHub")
            st.table(pd.DataFrame([gh]))

        # Enrichment API esterne
        ext = result.get("external_apis", {}) or {}
        if ext:
            st.subheader("Enrichment API esterne")
            tabs = st.tabs([
                "Reddit",
                "YouTube",
                "AbuseIPDB",
                "IPinfo",
                "VirusTotal",
                "URLScan",
                "OTX",
                "GreyNoise",
                "crt.sh",
                "URLhaus",
                "ipapi",
            ])

            with tabs[0]:
                st.json(ext.get("reddit_api", {}))
            with tabs[1]:
                st.json(ext.get("youtube_api", {}))
            with tabs[2]:
                st.json(ext.get("abuseipdb", {}))
            with tabs[3]:
                st.json(ext.get("ipinfo", {}))
            with tabs[4]:
                st.json(ext.get("virustotal", {}))
            with tabs[5]:
                st.json(ext.get("urlscan", {}))
            with tabs[6]:
                st.json(ext.get("otx", {}))
            with tabs[7]:
                st.json(ext.get("greynoise", {}))
            with tabs[8]:
                st.json(ext.get("crtsh", {}))
            with tabs[9]:
                st.json(ext.get("urlhaus", {}))
            with tabs[10]:
                st.json(ext.get("ipapi", {}))

        # Informazioni di preview
        sp = result.get("scraping_preview", {})
        if sp:
            st.subheader("Informazioni di preview (meta/og)")
            rows = []
            for site, content in sp.items():
                meta = content.get("meta_preview", {})
                rows.append({
                    "Sito": site,
                    "Titolo": meta.get("title"),
                    "Descrizione": meta.get("description"),
                    "Dominio": meta.get("base")
                })
            st.dataframe(pd.DataFrame(rows), use_container_width=True)

        # Varianti username
        variants = result.get("variants", [])
        if variants:
            st.subheader("Varianti di username generate")
            st.write(", ".join(variants))

        # Export report
        try:
            export_state_base = f"scan_{key_prefix}_{result.get('username', 'unknown')}"
            if auto_report:
                _prepare_export_file(f"{export_state_base}_pdf", "PDF", generate_pdf_report, result)
                _prepare_export_file(f"{export_state_base}_xlsx", "Excel", generate_excel, result)
                st.success("Report salvati automaticamente (PDF/Excel).")
            else:
                c_pdf, c_xlsx = st.columns(2)
                with c_pdf:
                    if st.button("Prepara PDF", key=f"prepare_pdf_{export_state_base}"):
                        _prepare_export_file(f"{export_state_base}_pdf", "PDF", generate_pdf_report, result)
                with c_xlsx:
                    if st.button("Prepara Excel", key=f"prepare_xlsx_{export_state_base}"):
                        _prepare_export_file(f"{export_state_base}_xlsx", "Excel", generate_excel, result)

                _render_prepared_download(f"{export_state_base}_pdf", "📄 Download PDF")
                _render_prepared_download(f"{export_state_base}_xlsx", "📊 Download Excel")
        except Exception as e:
            logger.error(f"Errore generazione report: {e}")
            st.error("Errore nella generazione dei report")

    except Exception as e:
        logger.error(f"Errore display risultati: {e}")
        st.error(f"Errore nella visualizzazione dei risultati: {e}")

# Carica dati capitali dal file JSON
CAPITALS: List[Tuple[str, str, float, float]] = _load_capitals()
cap_df = pd.DataFrame(CAPITALS, columns=["country", "capital", "lat", "lon"])


def parse_result(val: object) -> Dict:
    """Parsa il risultato della scansione da JSON."""
    if isinstance(val, dict):
        return val
    if isinstance(val, str):
        try:
            return json.loads(val)
        except Exception:
            logger.warning(f"Impossibile parsare risultato JSON: {str(val)[:100]}")
            return {}
    return {}


def deterministic_capital_for_username(username: str) -> Dict[str, object]:
    """Assegna un capitale deterministico basato su hash dell'username."""
    if not username:
        return {"city": None, "country": None, "lat": None, "lon": None}
    
    idx = int(hashlib.sha256(username.encode("utf-8")).hexdigest(), 16) % len(cap_df)
    r = cap_df.iloc[idx]
    return {
        "city": r["capital"],
        "country": r["country"],
        "lat": float(r["lat"]),
        "lon": float(r["lon"])
    }


def extract_geo_from_result(result: Dict) -> Dict[str, object]:
    """Estrae dati geografici da un risultato di scansione."""
    if not isinstance(result, dict):
        return {"city": None, "country": None, "lat": None, "lon": None}
    
    geo = result.get("geo") or {}
    lat, lon = geo.get("lat"), geo.get("lon")
    
    if lat is not None and lon is not None:
        return {
            "city": geo.get("city"),
            "country": geo.get("country"),
            "lat": float(lat),
            "lon": float(lon)
        }
    
    return deterministic_capital_for_username(str(result.get("username", "")))


def compute_profile_found_ratio(result: Dict) -> float:
    """Calcola la percentuale di profili trovati."""
    ps = result.get("profile_status", {}) or {}
    if not ps:
        return 0.0
    
    total = len(ps)
    found = sum(1 for v in ps.values() if v.get("exists"))
    return round(found / total * 100.0, 1)


def render_kpi_cards(items: List[Tuple[str, str, str]]) -> None:
    cols = st.columns(len(items))
    for col, (value, label, trend) in zip(cols, items):
        trend_cls = "kpi-stable"
        if trend.startswith("+"):
            trend_cls = "kpi-up"
        elif trend.startswith("-"):
            trend_cls = "kpi-down"
        with col:
            st.markdown(
                f"""
                <div class="kpi-card">
                    <div class="kpi-value">{value}</div>
                    <div class="kpi-label">{label}</div>
                    <span class="kpi-trend {trend_cls}">{trend}</span>
                </div>
                """,
                unsafe_allow_html=True,
            )


def cluster_points_grid(df_points: pd.DataFrame, level: int = 2) -> pd.DataFrame:
    """Aggrega punti in un grid per il clustering."""
    if df_points.empty:
        return df_points
    
    step = CLUSTER_LEVELS.get(level, 0.25)
    dfc = df_points.copy()
    dfc["lat_bin"] = (dfc["lat"] / step).round().astype(int)
    dfc["lon_bin"] = (dfc["lon"] / step).round().astype(int)
    
    return (dfc.groupby(["lat_bin", "lon_bin"])
            .agg(lat=("lat", "mean"),
                 lon=("lon", "mean"),
                 count=("username", "count"),
                 avg_found_pct=("found_pct", "mean"))
            .reset_index(drop=True))

@st.cache_data(show_spinner=False)
def _cached_load_processed(nonce: int, limit: int = CACHE_LIMIT) -> pd.DataFrame:
    """
    Carica e processa scansioni con limite configurabile per performance.
    Usa CACHE_LIMIT da config per il valore di default.
    
    Args:
        nonce: Session state nonce per invalidare cache
        limit: Numero massimo di scansioni da caricare
    
    Returns:
        DataFrame con scansioni elaborate
    """
    try:
        scans = load_recent(limit)
        df = pd.DataFrame(scans) if scans else pd.DataFrame(
            columns=["id", "username", "queried_at", "result"]
        )
        
        if not df.empty:
            df["queried_at"] = pd.to_datetime(df["queried_at"], errors="coerce")
            df["result"] = df["result"].apply(parse_result)
            df["found_pct_calc"] = df["result"].apply(compute_profile_found_ratio)
            df["risk_score_calc"] = df["result"].apply(
                lambda r: float((r.get("risk_assessment") or compute_risk_assessment(r)).get("score") or 0.0)
            )
            df["risk_level"] = df["result"].apply(
                lambda r: (r.get("risk_assessment") or compute_risk_assessment(r)).get("level", "Low")
            )

            # Cache geo calculations to avoid repeated computations
            df["geo_cache"] = df.apply(
                lambda row: extract_geo_from_result(row["result"]),
                axis=1
            )
            df["lat"] = df["geo_cache"].apply(lambda g: g.get("lat"))
            df["lon"] = df["geo_cache"].apply(lambda g: g.get("lon"))
            df["city"] = df["geo_cache"].apply(lambda g: g.get("city"))
            df["country"] = df["geo_cache"].apply(lambda g: g.get("country"))

        logger.info(f"Caricate {len(df)} scansioni dal database (limit={limit})")
        return df
    
    except Exception as e:
        logger.error(f"Errore caricamento dati processati: {e}", exc_info=True)
        return pd.DataFrame(columns=["id", "username", "queried_at", "result"])

def get_df() -> pd.DataFrame:
    try:
        return _cached_load_processed(st.session_state["data_nonce"])
    except Exception as e:
        logger.error(f"Errore caricamento dati: {e}")
        st.error("Impossibile caricare i dati delle scansioni. Controlla la connessione al database.")
        return pd.DataFrame(columns=["id","username","queried_at","result"])

# =============================================================================
# Sidebar - Menu Principale
# =============================================================================
st.sidebar.markdown("""
### 🎯 ArgAtlas
**Release v4**  
*Sidebar Permanente*
""")

# Sezione Personalizzazione Background
with st.sidebar.expander("🎨 Personalizza Background", expanded=False):
    st.markdown("**Scegli un tema per lo sfondo:**")
    
    # Crea una lista di nomi di tema per il selectbox
    theme_options = [BACKGROUND_THEMES[key]["name"] for key in BACKGROUND_THEMES.keys()]
    theme_keys = list(BACKGROUND_THEMES.keys())
    
    # Trova l'indice del tema attuale
    current_idx = theme_keys.index(st.session_state["background_theme"])
    
    # Selectbox per scegliere il tema
    selected_theme_name = st.selectbox(
        "Tema", 
        options=theme_options,
        index=current_idx,
        key="bg_theme_selector"
    )
    
    # Trova la chiave del tema selezionato
    selected_theme_key = theme_keys[theme_options.index(selected_theme_name)]
    
    # Aggiorna il session state se è cambiato
    if selected_theme_key != st.session_state["background_theme"]:
        st.session_state["background_theme"] = selected_theme_key
        st.rerun()
    
    st.caption(f"Tema attivo: **{BACKGROUND_THEMES[st.session_state['background_theme']]['name']}**")

st.sidebar.markdown(
    """
    <div class="side-live-title">Live Channels</div>
    <div class="side-live-item"><span>Feeds</span><span class="side-live-badge">LIVE</span></div>
    <div class="side-live-item"><span>Signals</span><span class="side-live-badge">LIVE</span></div>
    <div class="side-live-item"><span>Markets</span><span class="side-live-badge">LIVE</span></div>
    <div class="side-live-item"><span>Sources</span><span class="side-live-badge">LIVE</span></div>
    """,
    unsafe_allow_html=True,
)

# Applica il CSS dinamico DOPO la sidebar (così viene rigenerato ad ogni rerun)
css_placeholder.markdown(get_dynamic_css(st.session_state["background_theme"]), unsafe_allow_html=True)

menu = st.sidebar.radio("📋 Navigazione", [
    "🏠 Dashboard Completo",
    "⚡ Quick Scan",
    "🧪 Full Scan",
    "📤 Batch CSV",
    "📊 Reports",
    "🔬 Advanced Analysis",
    "⚙️ Bulk Ops",
    "🔧 System"
], label_visibility="collapsed")

st.sidebar.markdown("""
---
**© 2026 ArgAtlas**  
Enterprise Edition v4
""")

# =============================================================================
# Dashboard Completo — TUTTE le informazioni
# =============================================================================
# =============================================================================
# Dashboard Completo — TUTTE le informazioni in una pagina
# =============================================================================
if menu == "🏠 Dashboard Completo":
    df = get_df()

    st.markdown(
        """
        <div class="monitor-shell">
            <div>
                <div class="monitor-title">Conflict Activity Monitor</div>
                <div class="monitor-sub">Aggiornamento real-time della situazione operativa</div>
            </div>
            <span class="live-pill">● Live</span>
        </div>
        """,
        unsafe_allow_html=True,
    )
    
    # Tasto per generare demo data
    if df.empty:
        col1, col2, col3 = st.columns([2, 1, 1])
        with col1:
            st.info("📌 Database vuoto - Clicca il pulsante per generare dati demo")
        with col2:
            if st.button("🎯 Genera Demo Data", key="gen_demo"):
                with st.spinner("Generando dati demo..."):
                    generate_demo_data(5)
                    st.session_state["data_nonce"] += 1
                    st.rerun()
        with col3:
            pass
        # Carica di nuovo i dati dopo generazione
        df = get_df()

    # =================================================================
    # METRICHE PRINCIPALI - SEMPRE VISIBILI
    # =================================================================
    st.markdown("### 📊 OSINT Intelligence Monitor")
    
    total_scans = len(df) if not df.empty else 0
    unique_users = df["username"].nunique() if not df.empty else 0
    avg_platforms = round(df["found_pct_calc"].mean(), 1) if (not df.empty and total_scans > 0) else 0
    avg_risk = round(df["risk_score_calc"].mean(), 1) if (not df.empty and total_scans > 0) else 0
    
    # Calcola dati per metriche
    all_platforms = {}
    for r in df["result"] if not df.empty else []:
        for k, v in (r.get("profile_status") or {}).items():
            if v.get("exists"):
                all_platforms[k] = all_platforms.get(k, 0) + 1
    
    # Fix type error: use list comprehension instead of max() with method key
    top_platform = max(all_platforms, key=lambda k: all_platforms[k]) if all_platforms else "N/A"
    top_count = all_platforms.get(top_platform, 0) if isinstance(top_platform, str) else 0

    now_utc = pd.Timestamp.utcnow()
    q_utc = pd.to_datetime(df["queried_at"], utc=True, errors="coerce") if not df.empty else pd.Series(dtype="datetime64[ns, UTC]")
    scans_last_24h = int((q_utc >= (now_utc - pd.Timedelta(hours=24))).sum()) if not df.empty else 0
    scans_prev_24h = int(((q_utc >= (now_utc - pd.Timedelta(hours=48))) & (q_utc < (now_utc - pd.Timedelta(hours=24)))).sum()) if not df.empty else 0
    delta_24h = scans_last_24h - scans_prev_24h
    trend_scans = f"{delta_24h:+d} vs prev 24h"

    risk_delta = 0.0
    if not df.empty and len(df) > 1:
        risk_delta = float(df["risk_score_calc"].iloc[-1] - df["risk_score_calc"].iloc[-2])
    trend_risk = f"{risk_delta:+.1f} delta"
    
    render_kpi_cards([
        (str(scans_last_24h), "Total Events (24h)", trend_scans),
        (str(unique_users), "Active Sources", "stable"),
        (str(len(all_platforms)), "Activity Zones", f"Top {top_platform[:12]}"),
        (f"{avg_platforms}%", "Coverage", "stable"),
        (f"{avg_risk}/100", "Risk Index", trend_risk),
    ])
    
    # Se non ci sono dati, mostra una schermata alternativa
    if df.empty:
        st.info("📌 Database vuoto - Usa 'Quick Scan' o 'Full Scan' per iniziare")
        st.markdown('<div class="ops-card">', unsafe_allow_html=True)
        st.markdown("### Global Event Map")
        empty_points = pd.DataFrame(columns=["username", "lat", "lon", "city", "country", "found_pct"])
        fig_map_empty = create_points_map_figure(
            empty_points,
            cap_df,
            DEFAULT_MAP_CENTER,
            show_capitals=True,
            threat_zones=THREAT_ZONES,
            zoom=DEFAULT_MAP_ZOOM,
        )
        st.plotly_chart(fig_map_empty, use_container_width=True, config={"displayModeBar": True})
        st.markdown("</div>", unsafe_allow_html=True)
        st.stop()

    # =================================================================
    # FILTRI COMBINATI
    # =================================================================
    with st.expander("🔍 Filtri Avanzati", expanded=False):
        f1, f2, f3, f4, f5 = st.columns([2, 2, 2, 2, 1])
        with f1:
            search = st.text_input("Username contiene…", value=st.session_state["filters"].get("search", ""), key="search_v34")
        all_platforms_list = sorted({k for r in df["result"] for k in (r.get("profile_status") or {}).keys()})
        with f2:
            platform_sel = st.multiselect("Piattaforme", options=all_platforms_list, default=st.session_state["filters"].get("platform_sel", []))
        with f3:
            min_d, max_d = df["queried_at"].min().date(), df["queried_at"].max().date()
            date_range = st.date_input("Intervallo date", value=st.session_state["filters"].get("date_range", (min_d, max_d)))
            if not (isinstance(date_range, tuple) and len(date_range) == 2):
                date_range = (min_d, max_d)
        with f4:
            min_pct = st.slider("Min % profili", 0, 100, st.session_state["filters"].get("min_pct", 0))
        with f5:
            if st.button("Reset", key="reset_filters_v34"):
                st.session_state["filters"] = {}
                st.rerun()

        # Applica filtri
        mask = pd.Series([True] * len(df), index=df.index)
        if search:
            mask &= df["username"].str.contains(search, case=False, na=False)
        if platform_sel:
            def has_platforms(res):
                ps = res.get("profile_status", {}) or {}
                return any(p in ps and ps[p].get("exists") for p in platform_sel)
            mask &= df["result"].apply(has_platforms)
        mask &= (df["queried_at"].dt.date >= date_range[0]) & (df["queried_at"].dt.date <= date_range[1])
        mask &= df["found_pct_calc"].fillna(0) >= float(min_pct)

        st.session_state["filters"] = {
            "search": search,
            "platform_sel": platform_sel,
            "date_range": date_range,
            "min_pct": min_pct
        }
        df_f = df[mask].copy()
        st.caption(f"📌 Risultati nel filtro: **{len(df_f)}** scansioni")

    # =================================================================
    # OPERATIONS LAYOUT (MAP + FEED)
    # =================================================================
    points = []
    for _, row in df_f.iterrows():
        user = str(row.get("username", ""))
        geo = row["geo_cache"]
        pct = row["found_pct_calc"]
        points.append({
            "username": user,
            "lat": geo.get("lat"),
            "lon": geo.get("lon"),
            "city": geo.get("city"),
            "country": geo.get("country"),
            "found_pct": pct,
        })
    points_df = pd.DataFrame(points).dropna(subset=["lat", "lon"]) if points else pd.DataFrame()

    left_ops, right_ops = st.columns([2.1, 1])
    with left_ops:
        st.markdown('<div class="ops-card">', unsafe_allow_html=True)
        st.markdown("### Global Event Map")
        fig_map_fixed = create_points_map_figure(
            points_df,
            cap_df,
            DEFAULT_MAP_CENTER,
            show_capitals=True,
            threat_zones=THREAT_ZONES,
            zoom=DEFAULT_MAP_ZOOM,
        )
        st.plotly_chart(fig_map_fixed, use_container_width=True, config={"displayModeBar": True})
        st.markdown("</div>", unsafe_allow_html=True)

    with right_ops:
        st.markdown('<div class="ops-card">', unsafe_allow_html=True)
        st.markdown("### Recent Geopolitical Activities")
        recent_feed = df_f.sort_values("queried_at", ascending=False).head(6)
        if recent_feed.empty:
            st.info("Nessuna attività recente disponibile.")
        else:
            for _, row in recent_feed.iterrows():
                uname = str(row.get("username", "unknown"))
                risk_level = str(row.get("risk_level", "Low"))
                qat = row.get("queried_at")
                qtxt = qat.strftime("%d %b %Y %H:%M") if hasattr(qat, "strftime") else str(qat)
                st.markdown(
                    f"""
                    <div class="feed-item">
                        <div class="feed-title">Attività su {uname}</div>
                        <div class="feed-meta">Risk: {risk_level} • {qtxt}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
        st.markdown("</div>", unsafe_allow_html=True)
    
    # =================================================================
    # MAPPA GLOBALE
    # =================================================================
    with st.expander("🌍 OSINT GeoMap Globale", expanded=False):
        o1, o2, o3, o4, o5 = st.columns([1, 1, 2, 1, 1])
        with o1:
            use_heatmap = st.toggle("Heatmap", value=False, key="hm_v34")
        with o2:
            use_cluster = st.toggle("Clustering", value=False, key="cl_v34") if not use_heatmap else False
        with o3:
            cluster_level = st.slider("Livello clustering", 0, 4, 2, key="cl_level_v34")
        with o4:
            show_capitals = st.toggle("Capitali", value=True, key="cap_v34")
        with o5:
            show_threat = st.toggle("Threat Zones", value=False, key="threat_v34")

        points = []
        for _, row in df_f.iterrows():
            user = str(row.get("username", ""))
            geo = row["geo_cache"]
            pct = row["found_pct_calc"]
            points.append({
                "username": user,
                "lat": geo.get("lat"),
                "lon": geo.get("lon"),
                "city": geo.get("city"),
                "country": geo.get("country"),
                "found_pct": pct
            })

        points_df = pd.DataFrame(points).dropna(subset=["lat", "lon"]) if points else pd.DataFrame()

        if use_heatmap and not points_df.empty:
            fig_map = create_heatmap_figure(points_df, DEFAULT_MAP_CENTER, zoom=DEFAULT_MAP_ZOOM)
        else:
            if use_cluster and not points_df.empty:
                clusters_df = cluster_points_grid(points_df, cluster_level)
                fig_map = create_cluster_map_figure(
                    points_df, clusters_df, cap_df, DEFAULT_MAP_CENTER,
                    show_capitals=show_capitals,
                    threat_zones=THREAT_ZONES if show_threat else [],
                    zoom=DEFAULT_MAP_ZOOM
                )
            else:
                fig_map = create_points_map_figure(
                    points_df, cap_df, DEFAULT_MAP_CENTER,
                    show_capitals=show_capitals,
                    threat_zones=THREAT_ZONES if show_threat else [],
                    zoom=DEFAULT_MAP_ZOOM
                )
        
        st.plotly_chart(fig_map, use_container_width=True, config={
            "scrollZoom": True,
            "displayModeBar": True,
            "modeBarButtonsToAdd": ["zoomInMapbox", "zoomOutMapbox", "resetViewMapbox"]
        })
    
    # =================================================================
    # ANALYTICS ESTESI
    # =================================================================
    with st.expander("📈 Analytics Estesi", expanded=False):
        c1, c2 = st.columns([1.2, 1])
        with c1:
            plat_counts = {}
            for r in df_f["result"]:
                for k, v in (r.get("profile_status") or {}).items():
                    if v.get("exists"):
                        plat_counts[k] = plat_counts.get(k, 0) + 1
            
            if plat_counts:
                fig_top = create_platform_bar_chart(plat_counts, top_n=10)
                st.plotly_chart(fig_top, use_container_width=True)
            else:
                st.info("Nessuna piattaforma attiva nei dati filtrati.")
        
        with c2:
            fig_hr = create_hourly_area_chart(df_f)
            if fig_hr:
                st.plotly_chart(fig_hr, use_container_width=True)
            else:
                st.info("Nessun dato per calcolare trend orario.")

        st.markdown("#### 📊 Trend Settimanale")
        result = create_weekly_trend_chart(df_f) if not df_f.empty else None
        if result is not None:
            fig_wk, wk = result
            if fig_wk is not None:
                st.plotly_chart(fig_wk, use_container_width=True)
            if wk is not None and isinstance(wk, pd.DataFrame) and len(wk) >= 2:
                try:
                    delta = int(wk["count"].iloc[-1] - wk["count"].iloc[-2])
                    st.caption(f"Δ ultimo periodo: **{delta:+d}** scansioni")
                except (KeyError, IndexError, TypeError):
                    st.caption("⚠️ Impossibile calcolare delta")
        else:
            st.info("Nessun dato per calcolare il trend.")
    
    # =================================================================
    # QUICK SCAN INLINE
    # =================================================================
    with st.expander("⚡ Quick Scan", expanded=False):
        q1, q2, q3 = st.columns([3, 1, 1])
        with q1:
            quick_user = st.text_input("Username • Email • Telefono (+39...):", key="quick_user_dash")
        with q2:
            quick_preview = st.checkbox("Preview", value=True, key="quick_prev_dash")
        with q3:
            quick_github = st.checkbox("GitHub", value=True, key="quick_gh_dash")
        quick_status = st.checkbox("Check profili (60+ siti)", value=True, key="quick_status_dash")
        quick_max = st.slider("Max profili simultanei", 1, 30, DEFAULT_MAX_PROFILES, key="quick_max_dash")
        quick_auto_report = st.checkbox("Auto-salva PDF/Excel", value=False, key="quick_autorep_dash")
        
        if st.button("🚀 Avvia Quick Scan", key="quick_run_dash"):
            _execute_scan(quick_user, do_status=quick_status, do_preview=quick_preview,
                         do_github=quick_github, max_profiles=quick_max, auto_report=quick_auto_report,
                         key_prefix="quick_dash")

    # =================================================================
    # FULL SCAN INLINE
    # =================================================================
    with st.expander("🧪 Full Scan Completo", expanded=False):
        d1, d2, d3 = st.columns([3, 1, 1])
        with d1:
            full_user = st.text_input("Username • Email • Telefono (+39...):", key="full_user_dash")
        with d2:
            full_preview = st.checkbox("Scraping preview", value=True, key="full_prev_dash")
        with d3:
            full_github = st.checkbox("GitHub API", value=True, key="full_gh_dash")
        full_status = st.checkbox("Check profili (60+ siti)", value=True, key="full_status_dash")
        full_max = st.slider("Max concurrent checks", 1, MAX_CONCURRENT_CHECKS, DEFAULT_MAX_PROFILES, key="full_max_dash")
        full_auto_report = st.checkbox("Auto-salva PDF/Excel", value=True, key="full_autorep_dash")

        if st.button("🚀 Avvia Full Scan", key="full_run_dash"):
            _execute_scan(full_user, do_status=full_status, do_preview=full_preview,
                         do_github=full_github, max_profiles=full_max, auto_report=full_auto_report,
                         key_prefix="full_dash")

    # Initialize optional charts used by Snapshot export.
    fig_recent = None
    fig_tl = None
    fig_pf = None
    
    # =================================================================
    # LIVE MONITOR
    # =================================================================
    with st.expander("📡 Live Activity Monitor", expanded=False):
        recent = load_recent(LIVE_MONITOR_LIMIT)
        
        if recent:
            dfr = pd.DataFrame(recent)[["username", "queried_at"]]
            dfr["queried_at_dt"] = pd.to_datetime(dfr["queried_at"])
            dfrs = dfr.sort_values("queried_at_dt")
            dfrs_display = dfrs.copy()
            dfrs_display["queried_at"] = dfrs_display["queried_at_dt"].dt.strftime("%d %b %Y %H:%M:%S")
            
            st.dataframe(
                dfrs_display[["username", "queried_at"]].rename(
                    columns={"username": "Utente", "queried_at": "Data/Ora"}
                ),
                use_container_width=True,
                height=200
            )
            
            fig_recent = create_live_activity_chart(dfrs)
            if fig_recent is not None:
                st.plotly_chart(fig_recent, use_container_width=True)
        else:
            st.info("Nessuna scansione recente trovata.")

    # =================================================================
    # INTELLIGENCE SUMMARY
    # =================================================================
    with st.expander("📊 Intelligence Summary", expanded=False):
        fig_tl = create_daily_timeline_chart(df_f)
        if fig_tl is not None:
            st.plotly_chart(fig_tl, use_container_width=True)

        plat = {}
        for r in df_f["result"]:
            for k, v in (r.get("profile_status") or {}).items():
                if v.get("exists"):
                    plat[k] = plat.get(k, 0) + 1
        
        if plat:
            fig_pf = create_platform_pie_chart(plat)
            if fig_pf is not None:
                st.plotly_chart(fig_pf, use_container_width=True)
        else:
            st.info("Nessuna piattaforma attiva nel filtro.")

        st.subheader("Elenco Dettagliato Scansioni")
        st.dataframe(
            df_f[["id", "username", "queried_at", "found_pct_calc", "risk_score_calc", "risk_level"]]
            .rename(columns={
                "found_pct_calc": "found_pct",
                "risk_score_calc": "risk_score",
            })
            .sort_values("queried_at", ascending=False),
            use_container_width=True,
            height=200
        )

    # =================================================================
    # ENTITY GRAPH
    # =================================================================
    with st.expander("🕸️ Entity Graph", expanded=False):
        show_graph = st.toggle("Mostra Entity Graph", value=False, key="eg_v34")
        max_users = st.slider("Numero massimo utenti", 10, 300, 70, key="max_users_v34")
        
        if show_graph:
            edges, seen = [], set()
            for _, row in df.iterrows():
                u = str(row.get("username", ""))
                if u in seen:
                    continue
                seen.add(u)
                ps = (row.get("result", {}).get("profile_status") or {})
                for p, v in ps.items():
                    if v.get("exists"):
                        edges.append((f"u:{u}", f"p:{p}"))
                if len(seen) >= max_users:
                    break
            
            if edges:
                fig_g = create_entity_graph(edges, accent=ACCENT_COLOR)
                st.plotly_chart(fig_g, use_container_width=True)
            else:
                st.info("Nessuna relazione utente–piattaforma trovata.")

    # =================================================================
    # ESPORTA SNAPSHOT
    # =================================================================
    with st.expander("📦 Esporta Snapshot", expanded=False):
        l1, l2, l3 = st.columns([1, 2, 1])
        with l1:
            auto_refresh = st.toggle("🔁 Auto-refresh", value=False, key="auto_refresh_v34")
        with l2:
            refresh_interval = st.slider("Intervallo aggiornamento (sec)", 5, 60, 15, key="refresh_int_v34")
        with l3:
            export_snap = st.button("📦 Esporta Snapshot (HTML)", key="export_snap_v34")
        
        if auto_refresh:
            st.markdown(f"<i>Aggiornamento automatico ogni {refresh_interval}s…</i>", unsafe_allow_html=True)
            st.markdown(
                f'<meta http-equiv="refresh" content="{refresh_interval}">',
                unsafe_allow_html=True,
            )

        if export_snap:
            figs, titles = [], []
            if fig_recent is not None:
                figs.append(fig_recent)
                titles.append("Live Activity")
            if fig_tl is not None:
                figs.append(fig_tl)
                titles.append("Timeline scansioni")
            if fig_pf is not None:
                figs.append(fig_pf)
                titles.append("Piattaforme (filtro)")
            
            snap_filename = f"dashboard_snapshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            snap = export_snapshot_html(figs, titles, snap_filename)
            
            with open(snap, "r", encoding="utf-8") as f:
                st.download_button(
                    "⬇️ Scarica snapshot (HTML)",
                    f,
                    file_name=os.path.basename(snap),
                    mime="text/html"
                )
            logger.info(f"Snapshot esportato: {snap_filename}")

# =============================================================================
# Quick Scan page
# =============================================================================
elif menu == "⚡ Quick Scan":
    st.title("⚡ Quick Scan")
    st.markdown("Ricerca veloce su username, email, telefono o handle social.")
    q1, q2, q3 = st.columns([3, 1, 1])
    with q1:
        quick_user = st.text_input("Username • Email • Telefono (+39...):", key="quick_user_qs")
    with q2:
        quick_preview = st.checkbox("Preview", value=True, key="quick_prev_qs")
    with q3:
        quick_github = st.checkbox("GitHub", value=True, key="quick_gh_qs")
    quick_status = st.checkbox("Check profili (60+ siti)", value=True, key="quick_status_qs")
    quick_max = st.slider("Max profili simultanei", 1, 30, DEFAULT_MAX_PROFILES, key="quick_max_qs")
    quick_auto_report = st.checkbox("Auto-salva PDF/Excel", value=False, key="quick_autorep_qs")
    
    if st.button("🚀 Avvia Quick Scan", key="quick_run_qs"):
        _execute_scan(
            quick_user,
            do_status=quick_status,
            do_preview=quick_preview,
            do_github=quick_github,
            max_profiles=quick_max,
            auto_report=quick_auto_report,
            key_prefix="quick_qs"
        )

# =============================================================================
# Full Scan page
# =============================================================================
elif menu == "🧪 Full Scan":
    st.title("🧪 Full Scan Completo")
    st.markdown("Ricerca approfondita su 60+ piattaforme (Instagram, TikTok, YouTube, LinkedIn, Reddit, Twitch, Discord, Steam, GitHub, Spotify, e molte altre)")
    user_input = st.text_input("Username • Email • Telefono (+39...):", key="full_user_fs")
    do_preview = st.checkbox("Scraping preview", value=True, key="full_prev_fs")
    do_status = st.checkbox("Check profili su tutte le piattaforme", value=True, key="full_status_fs")
    do_github = st.checkbox("GitHub API", value=True, key="full_gh_fs")
    max_profiles = st.number_input("Max concurrent checks", 1, MAX_CONCURRENT_CHECKS, DEFAULT_MAX_PROFILES, key="full_max_fs")
    auto_report = st.checkbox("Auto-salva PDF/Excel al termine", value=True, key="full_autorep_fs")

    if st.button("🚀 Avvia Scansione Completa", key="full_run_fs"):
        _execute_scan(
            user_input,
            do_status=do_status,
            do_preview=do_preview,
            do_github=do_github,
            max_profiles=int(max_profiles),
            auto_report=auto_report,
            key_prefix="full_fs"
        )

# -----------------------------------------------------------------------------
# Batch CSV
# -----------------------------------------------------------------------------
elif menu == "📤 Batch CSV":
    st.title("Batch Scan (CSV)")
    st.write("Carica un CSV con una username/email/telefono per riga (prima colonna).")
    st.info("Supporta: username, email, numero di telefono (+39...) così come ogni combinazione")
    uploaded = st.file_uploader("Upload CSV", type=["csv"])
    do_preview = st.checkbox("Scraping preview", value=True)
    do_status = st.checkbox("Check profili (60+ siti)", value=True)
    do_github = st.checkbox("GitHub API", value=True)
    max_profiles = st.number_input("Max concurrent checks", 1, MAX_CONCURRENT_CHECKS, DEFAULT_MAX_PROFILES)

    if uploaded:
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmpf:
                tmpf.write(uploaded.getbuffer())
                tmp_path = tmpf.name

            is_valid, result = _validate_csv(tmp_path)
            if not is_valid:
                st.error(f"Errore: {result}")
            else:
                st.success(f"CSV caricato: {len(result)} righe")

                if st.button("Start Batch Scan"):
                    with st.spinner("Esecuzione batch..."):
                        logger.info(f"Inizio batch scan: {len(result)} righe")
                        results = run_batch_scan_from_csv(
                            tmp_path,
                            do_status=do_status,
                            do_preview=do_preview,
                            do_github=do_github,
                            max_profiles=int(max_profiles)
                        )

                        saved_count = 0
                        skipped_count = 0
                        for r in results:
                            try:
                                saved = save_scan(r, skip_duplicate_days=SKIP_DUPLICATE_DAYS)
                                if saved:
                                    saved_count += 1
                                else:
                                    skipped_count += 1
                            except Exception as e:
                                skipped_count += 1
                                logger.warning(f"Errore salvataggio risultato: {e}")

                        st.session_state["data_nonce"] += 1
                        logger.info(
                            f"Batch completato: processate={len(results)}, salvate={saved_count}, skippate={skipped_count}"
                        )
                        st.success(
                            f"Batch completato. Processate: {len(results)} • Salvate: {saved_count} • Skippate/duplicate: {skipped_count}."
                        )
                        st.dataframe(
                            pd.DataFrame(results)[["username", "queried_at"]],
                            use_container_width=True
                        )
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError as e:
                    logger.warning(f"Impossibile rimuovere file temporaneo {tmp_path}: {e}")

# -----------------------------------------------------------------------------
# Reports
# -----------------------------------------------------------------------------
elif menu == "📊 Reports":
    st.title("Reports Center")
    scans = load_recent(RECENT_SCANS_LIMIT)
    if scans:
        df = pd.DataFrame(scans)
        users = sorted(df["username"].unique())
        sel = st.selectbox("Seleziona username", users) if users else None
        user_scans = [row for row in scans if row["username"] == sel] if sel else []
        rec = user_scans[0] if user_scans else None
        
        if rec:
            res = parse_result(rec.get("result"))
            st.json(res)
            try:
                state_base = f"reports_{sel}_{rec.get('id')}"
                col_pdf, col_xlsx = st.columns(2)
                with col_pdf:
                    if st.button("Prepara PDF", key=f"prepare_report_pdf_{state_base}"):
                        _prepare_export_file(f"{state_base}_pdf", "PDF", generate_pdf_report, res)
                with col_xlsx:
                    if st.button("Prepara Excel", key=f"prepare_report_xlsx_{state_base}"):
                        _prepare_export_file(f"{state_base}_xlsx", "Excel", generate_excel, res)

                _render_prepared_download(f"{state_base}_pdf", "Download PDF")
                _render_prepared_download(f"{state_base}_xlsx", "Download Excel")
            except Exception as e:
                st.warning(f"Export non riuscito: {e}")
                logger.error(f"Errore generazione report: {e}", exc_info=True)

        if len(user_scans) >= 2:
            st.markdown("---")
            st.markdown("#### 🔍 Confronto scansioni")
            comparison_options = [
                f"#{row['id']} • {row['queried_at']}" for row in user_scans
            ]
            option_to_scan = {f"#{row['id']} • {row['queried_at']}": row for row in user_scans}
            c1, c2 = st.columns(2)
            with c1:
                previous_label = st.selectbox("Scansione precedente", comparison_options, index=min(1, len(comparison_options) - 1))
            with c2:
                current_label = st.selectbox("Scansione corrente", comparison_options, index=0)

            previous_scan = option_to_scan[previous_label]
            current_scan = option_to_scan[current_label]
            if previous_scan["id"] != current_scan["id"]:
                comparison = compare_scan_results(parse_result(previous_scan["result"]), parse_result(current_scan["result"]))
                m1, m2, m3 = st.columns(3)
                with m1:
                    st.metric("Delta risk", f"{comparison['risk_delta']:+.1f}")
                with m2:
                    st.metric("Delta found %", f"{comparison['found_pct_delta']:+.1f}%")
                with m3:
                    st.metric("Delta GitHub follower", f"{comparison['followers_delta']:+d}")

                d1, d2 = st.columns(2)
                with d1:
                    st.write("**Piattaforme aggiunte**")
                    st.write(", ".join(comparison["added_platforms"]) or "Nessuna")
                    st.write("**Piattaforme rimosse**")
                    st.write(", ".join(comparison["removed_platforms"]) or "Nessuna")
                with d2:
                    st.write("**Rimaste invariate**")
                    st.write(", ".join(comparison["unchanged_platforms"][:20]) or "Nessuna")
            else:
                st.info("Seleziona due scansioni diverse per il confronto.")
        
        st.markdown("---")
        st.markdown("#### 📦 Download multiplo")
        if st.button("Genera Excel per tutti gli utenti visibili"):
            try:
                out = os.path.join(
                    os.getcwd(),
                    f"all_scans_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
                )
                with pd.ExcelWriter(out, engine="openpyxl") as wr:
                    df.to_excel(wr, index=False, sheet_name="scans")
                with open(out, "rb") as f:
                    st.download_button(
                        "⬇️ Scarica Excel completo",
                        f,
                        file_name=os.path.basename(out)
                    )
                logger.info(f"Excel multiplo generato: {len(df)} righe")
            except Exception as e:
                st.warning(f"Export multiplo non riuscito: {e}")
                logger.error(f"Errore export multiplo: {e}", exc_info=True)
    else:
        st.info("Nessun report disponibile.")

# -----------------------------------------------------------------------------
# Advanced Analysis — Correlazione, Alert, Email Lookup
# -----------------------------------------------------------------------------
elif menu == "🔬 Advanced Analysis":
    st.title("🔬 Advanced Analysis")
    st.markdown("Correlazione account, email reverse lookup, alert system")
    
    analysis_tab = st.selectbox(
        "Scegli analisi",
        ["Email Reverse Lookup", "Account Correlation", "Scan Alerts", "Pattern Detection"]
    )
    
    # 1. Email Reverse Lookup
    if analysis_tab == "Email Reverse Lookup":
        st.markdown("### 📧 Email Reverse Lookup (Hunter.io)")
        if not HUNTER_IO_ENABLED:
            st.warning("Hunter.io non configurato. Imposta HUNTER_IO_API_KEY come variabile ambiente.")
        else:
            email_input = st.text_input("Inserisci indirizzo email:", placeholder="john@company.com")
            if st.button("🔍 Lookup"):
                if not email_input.strip():
                    st.warning("Inserisci un'email o un dominio valido.")
                else:
                    with st.spinner("Ricerca in corso..."):
                        result = reverse_lookup_email(email_input.strip())
                        if result.get("found"):
                            st.success(result.get("message", "Lookup completato con successo"))

                            if result.get("email"):
                                col1, col2 = st.columns(2)
                                with col1:
                                    st.metric("Email", result.get("email", "N/A"))
                                    st.metric("Verifica", result.get("verification", "N/A"))
                                with col2:
                                    score = result.get("score")
                                    score_txt = f"{score}" if score is not None else "N/A"
                                    st.metric("Score", score_txt)
                                    st.metric("Fonti", len(result.get("sources", [])))

                            elif result.get("domain"):
                                col1, col2 = st.columns(2)
                                with col1:
                                    st.metric("Dominio", result.get("domain", "N/A"))
                                    st.metric("Email trovate", result.get("emails_found", 0))
                                with col2:
                                    st.metric("Pattern", result.get("pattern", "N/A"))
                                    st.metric("Top risultati", len(result.get("emails", [])))

                                emails = result.get("emails", [])
                                if emails:
                                    st.dataframe(pd.DataFrame(emails), use_container_width=True)

                            with st.expander("Dettagli risposta API"):
                                st.json(result)
                        else:
                            st.warning(result.get("message", "Nessuna informazione trovata."))
                            if result.get("error"):
                                st.json(result.get("error"))
    
    # 2. Account Correlation
    elif analysis_tab == "Account Correlation":
        st.markdown("### 🔗 Account Correlation Detection")
        st.markdown("Analizza correlazioni tra account basato su piattaforme comuni.")
        
        scans_list = load_recent(CACHE_LIMIT)
        df = pd.DataFrame(scans_list) if scans_list else pd.DataFrame(columns=["id","username","queried_at","result"])
        if not df.empty:
            all_scans = [
                {
                    "username": row.get("username"),
                    "active_platforms": [p for p, v in (row.get("result", {}).get("profile_status", {}) or {}).items() if v.get("exists")],
                    "profile_status": row.get("result", {}).get("profile_status", {})
                }
                for _, row in df.iterrows()
            ]
            
            correlations = suggest_account_correlations(all_scans)
            
            if correlations:
                st.success(f"Trovate {len(correlations)} correlazioni possibili")
                for corr in correlations:
                    with st.expander(f"**{corr['account1']}** ↔ **{corr['account2']}** (Score: {corr['similarity_score']})"):
                        col1, col2 = st.columns([1, 3])
                        with col1:
                            st.metric("Confidence", corr['confidence'])
                            st.metric("Similarity", f"{corr['similarity_score']:.0%}")
                        with col2:
                            st.write("**Piattaforme comuni:**")
                            st.write(", ".join(corr['common_platforms']))
            else:
                st.info("Nessuna correlazione trovata tra i dati disponibili.")
        else:
            st.warning("Nessuno scan disponibile per correlazione.")
    
    # 3. Scan Alerts
    elif analysis_tab == "Scan Alerts":
        st.markdown("### 🚨 Scan Alerts")
        if not ALERT_CONFIG.get("enable_alerts"):
            st.warning("Alert system disabilitato in config.py")
        else:
            recent_scans = load_recent(RECENT_SCANS_LIMIT)
            if recent_scans:
                usernames = sorted({s["username"] for s in recent_scans})
                selected_user = st.selectbox("Seleziona username", usernames)
                
                selected_scan = next((s for s in recent_scans if s["username"] == selected_user), None)
                if selected_scan:
                    alerts = generate_alerts(selected_scan["id"], selected_scan.get("result", {}))
                    existing_scan_alerts = get_scan_alerts(selected_scan["id"])
                    
                    if alerts:
                        st.success(f"Generati {len(alerts)} alert")
                        for idx, alert in enumerate(alerts):
                            severity_color = {
                                "HIGH": "🔴",
                                "MEDIUM": "🟡",
                                "LOW": "🟢"
                            }
                            with st.expander(f"{severity_color.get(alert['severity'], '⚪')} {alert['type']}"):
                                st.write(alert['message'])
                                if st.button(f"Salva alert", key=f"save_alert_{selected_scan['id']}_{alert['type']}_{idx}"):
                                    add_scan_alert(
                                        selected_scan["id"],
                                        alert["type"],
                                        alert["message"],
                                        severity=alert.get("severity", "LOW"),
                                    )
                                    st.success("Alert salvato al database")
                    else:
                        st.info("Nessun alert generato per questo scan.")

                    st.markdown("#### Storico alert scan selezionato")
                    if existing_scan_alerts:
                        st.dataframe(pd.DataFrame(existing_scan_alerts), use_container_width=True)
                    else:
                        st.info("Nessun alert salvato per questo scan.")
                else:
                    st.info("Nessuna scansione disponibile per l'utente selezionato.")

                st.markdown("#### Storico globale alert")
                filter_col1, filter_col2, filter_col3 = st.columns(3)
                with filter_col1:
                    alert_status = st.selectbox("Filtro stato", ["Tutti", "OPEN", "RESOLVED", "DISMISSED"], key="alert_status_filter")
                with filter_col2:
                    alert_severity = st.selectbox("Filtro severita", ["Tutte", "HIGH", "MEDIUM", "LOW"], key="alert_severity_filter")
                with filter_col3:
                    alert_limit = st.slider("Limite storico", 20, 300, 100, key="alert_limit_filter")

                history = get_all_scan_alerts(
                    status=None if alert_status == "Tutti" else alert_status,
                    severity=None if alert_severity == "Tutte" else alert_severity,
                    limit=alert_limit,
                )
                if history:
                    st.dataframe(pd.DataFrame(history), use_container_width=True)
                    alert_ids = [int(item["id"]) for item in history]
                    manage_col1, manage_col2, manage_col3 = st.columns(3)
                    with manage_col1:
                        selected_alert_id = st.selectbox("Alert ID", alert_ids, key="alert_manage_id")
                    with manage_col2:
                        next_status = st.selectbox("Nuovo stato", ["OPEN", "RESOLVED", "DISMISSED"], key="alert_manage_status")
                    with manage_col3:
                        if st.button("Aggiorna stato alert", key="alert_manage_update"):
                            if update_scan_alert_status(selected_alert_id, next_status):
                                st.success(f"Alert {selected_alert_id} aggiornato a {next_status}.")
                            else:
                                st.warning("Aggiornamento stato non riuscito.")
                else:
                    st.info("Nessun alert nello storico con i filtri attuali.")
            else:
                st.warning("Nessuno scan disponibile.")
    
    # 4. Pattern Detection
    elif analysis_tab == "Pattern Detection":
        st.markdown("### 📊 Pattern Detection")
        st.markdown("Analizza pattern tra multiple scansioni.")
        
        scans_list = load_recent(CACHE_LIMIT)
        df = pd.DataFrame(scans_list) if scans_list else pd.DataFrame(columns=["id","username","queried_at","result"])
        if not df.empty:
            all_scans = [
                {
                    "username": row.get("username"),
                    "active_platforms": [p for p, v in (row.get("result", {}).get("profile_status", {}) or {}).items() if v.get("exists")],
                    "queried_at": row.get("queried_at")
                }
                for _, row in df.iterrows()
            ]
            
            patterns = detect_account_pattern(all_scans)
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("🎯 Naming Patterns")
                if patterns["naming_patterns"]:
                    for p in patterns["naming_patterns"]:
                        st.write(f"• {p}")
                else:
                    st.write("No specific naming patterns detected")
            
            with col2:
                st.subheader("🔥 Platform Preferences")
                if patterns["platform_preferences"]:
                    for platform, count in patterns["platform_preferences"]:
                        st.write(f"• {platform}: {count}x")
        else:
            st.warning("Nessuno scan disponibile per analisi.")

# -----------------------------------------------------------------------------
# Bulk Operations
# -----------------------------------------------------------------------------
elif menu == "⚙️ Bulk Ops":
    st.title("⚙️ Bulk Operations")
    st.markdown("Operazioni batch: eliminazione, esportazione, re-scansione massiva")
    
    bulk_op = st.selectbox(
        "Scegli operazione",
        ["Bulk Delete", "Bulk Mark Verified", "Bulk Export", "Bulk Re-Scan", "Bulk Export Formats"]
    )
    
    if bulk_op == "Bulk Delete":
        st.markdown("### 🗑️ Bulk Delete")
        st.warning("⚠️ Attenzione: questa operazione è IRREVERSIBILE")
        
        scans_list = load_recent(CACHE_LIMIT)
        df = pd.DataFrame(scans_list) if scans_list else pd.DataFrame(columns=["id","username","queried_at","result"])
        if not df.empty:
            usernames = sorted(df["username"].unique())
            selected_users = st.multiselect("Seleziona username da cancellare", usernames)
            
            if selected_users:
                col1, col2 = st.columns([2, 1])
                with col1:
                    confirm = st.checkbox("✅ Confermo l'eliminazione di tutti i dati selezionati")
                with col2:
                    if st.button("🗑️ Elimina") and confirm:
                        total_deleted = 0
                        for user in selected_users:
                            deleted = bulk_delete_username(user)
                            total_deleted += deleted
                        st.session_state["data_nonce"] += 1
                        st.success(f"Cancellati {total_deleted} record per {len(selected_users)} username")
            else:
                st.info("Seleziona almeno un username.")
        else:
            st.warning("Nessuno username disponibile.")
    
    elif bulk_op == "Bulk Mark Verified":
        st.markdown("### ✅ Bulk Mark Verified")
        st.markdown("Marca scan come verificati manualmente.")
        
        scans_list = load_recent(CACHE_LIMIT)
        df = pd.DataFrame(scans_list) if scans_list else pd.DataFrame(columns=["id","username","queried_at","result"])
        if not df.empty:
            # compute found_pct_calc if missing
            if "found_pct_calc" not in df.columns:
                df["found_pct_calc"] = df["result"].apply(lambda r: compute_profile_found_ratio(parse_result(r)))
            scans_df = df[["id", "username", "queried_at", "found_pct_calc"]].head(100).rename(columns={"found_pct_calc":"found_pct"})
            st.dataframe(scans_df, use_container_width=True, key="bulk_verified_preview")

            row_options = scans_df.to_dict("records")
            selected_ids = st.multiselect(
                "Seleziona scan ID",
                options=[int(r["id"]) for r in row_options],
                format_func=lambda scan_id: next(
                    (
                        f"#{r['id']} • {r['username']} • {str(r['queried_at'])[:19]} • {float(r['found_pct']):.1f}%"
                        for r in row_options if int(r["id"]) == int(scan_id)
                    ),
                    str(scan_id)
                ),
                key="bulk_verified_ids"
            )
            
            col1, col2 = st.columns([2, 1])
            with col1:
                action = st.radio("Azione", ["Marca come verificato", "Marca come non verificato"])
            with col2:
                if st.button("💾 Salva"):
                    if not selected_ids:
                        st.warning("Seleziona almeno uno scan ID.")
                    else:
                        mark_verified = action == "Marca come verificato"
                        updated = bulk_mark_verified(selected_ids, verified=mark_verified)
                        if updated > 0:
                            st.session_state["data_nonce"] += 1
                            stato = "verificato" if mark_verified else "non verificato"
                            st.success(f"Aggiornati {updated} scan come {stato}.")
                        else:
                            st.warning("Nessun record aggiornato.")
    
    elif bulk_op == "Bulk Export":
        st.markdown("### 📤 Bulk Export")
        st.markdown("Esporta dati multipli in vari formati.")
        
        scans_list = load_recent(CACHE_LIMIT)
        df = pd.DataFrame(scans_list) if scans_list else pd.DataFrame(columns=["id","username","queried_at","result"])
        if not df.empty:
            export_format = st.selectbox("Formato", ["CSV Summary", "JSON Lines", "Excel"])
            min_found_pct = st.slider("Filtra per % profili trovati", 0, 100, 0)
            
            if st.button("📥 Genera export"):
                with st.spinner("Generazione in corso..."):
                    results = [s["result"] for s in load_recent(CACHE_LIMIT, filters={"min_found_pct": min_found_pct})]
                    
                    if export_format == "CSV Summary":
                        filepath = generate_csv_bulk_summary(results)
                    elif export_format == "JSON Lines":
                        filepath = generate_jsonl_bulk(results)
                    else:  # Excel
                        filepath = os.path.join(REPORTS_PATH, f"bulk_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx")
                        pd.DataFrame(results).to_excel(filepath, index=False)
                    
                    with open(filepath, "rb") as f:
                        st.download_button(
                            f"⬇️ Scarica ({export_format})",
                            f,
                            file_name=os.path.basename(filepath)
                        )
                    st.success(f"Export generato: {os.path.basename(filepath)}")
        else:
            st.warning("Nessuno dato disponibile.")
    
    elif bulk_op == "Bulk Re-Scan":
        st.markdown("### 🔄 Bulk Re-Scan")
        st.markdown("Re-scansiona massivamente su soglie (es. solo profili con >50% attività)")
        
        min_activity = st.slider("Filtra per % profili trovati", 0, 100, 50)
        
        scans = load_recent(CACHE_LIMIT, filters={"min_found_pct": min_activity})
        if scans:
            usernames = bulk_export_usernames({"min_found_pct": min_activity})
            st.info(f"Trovati {len(usernames)} username da re-scansionare")
            
            if st.button("🚀 Avvia Re-Scan Massivo"):
                progress_bar = st.progress(0)
                results = []
                
                for i, user in enumerate(usernames[:10]):  # Limita a 10 per demo
                    with st.spinner(f"Scansione {i+1}/10: {user}"):
                        res = run_scan_for_input(user, do_status=True, do_preview=False, do_github=False)
                        results.append(res)
                        save_scan(res, skip_duplicate_days=SKIP_DUPLICATE_DAYS)
                    progress_bar.progress((i+1)/min(10, len(usernames)))
                
                st.success(f"Re-scan completato per {len(results)} username")
                st.session_state["data_nonce"] += 1
        else:
            st.info("Nessun username corrisponde ai criteri.")
    
    elif bulk_op == "Bulk Export Formats":
        st.markdown("### 🔀 Advanced Export Formats")
        st.markdown("Esporta scan singoli in JSON, CSV profili, ecc.")
        
        recent = load_recent(RECENT_SCANS_LIMIT)
        if recent:
            df = pd.DataFrame(recent)
            selected = st.selectbox("Seleziona scan", df["username"].unique())
            scan = next((s for s in recent if s["username"] == selected), None)
            
            if scan:
                result = scan["result"]
                col1, col2, col3 = st.columns(3)
                export_state_base = f"bulk_single_{selected}_{scan.get('id', 'na')}"
                
                with col1:
                    if st.button("📄 JSON"):
                        _prepare_export_file(f"{export_state_base}_json", "JSON", generate_json, result)
                
                with col2:
                    if st.button("📊 CSV Profili"):
                        _prepare_export_file(f"{export_state_base}_csv", "CSV", generate_csv_profiles, result)
                
                with col3:
                    if st.button("📋 Tutti"):
                        _prepare_export_file(f"{export_state_base}_pdf", "PDF", generate_pdf_report, result)
                        _prepare_export_file(f"{export_state_base}_xlsx", "Excel", generate_excel, result)
                        _prepare_export_file(f"{export_state_base}_json", "JSON", generate_json, result)

                _render_prepared_download(f"{export_state_base}_json", "⬇️ JSON")
                _render_prepared_download(f"{export_state_base}_csv", "⬇️ CSV")
                _render_prepared_download(f"{export_state_base}_pdf", "⬇️ PDF")
                _render_prepared_download(f"{export_state_base}_xlsx", "⬇️ Excel")

# -----------------------------------------------------------------------------
# System
# -----------------------------------------------------------------------------
elif menu == "🔧 System":
    st.title("System Insights")
    try:
        df = get_df()
        n_scans = len(df)
        n_users = df["username"].nunique() if not df.empty else 0
        last_update = df["queried_at"].max() if not df.empty else None
        
        size_reports = 0
        try:
            for root, _, files in os.walk(REPORTS_PATH):
                for fn in files:
                    size_reports += os.path.getsize(os.path.join(root, fn))
        except Exception as e:
            logger.warning(f"Errore calcolo dimensione report: {e}")
        
        st.metric("Total scans", n_scans)
        st.metric("Unique users", n_users)
        st.metric("Reports size", f"{(size_reports/1024/1024):.1f} MB")
        st.write("Ultimo aggiornamento:", last_update)
        st.code(f"REPORTS_PATH = {REPORTS_PATH}")

        prepared_count = len(st.session_state.get("prepared_exports", {}))
        cexp1, cexp2 = st.columns([2, 1])
        with cexp1:
            st.caption(f"Export preparati in sessione: {prepared_count}")
        with cexp2:
            if st.button("Pulisci export preparati", key="clear_prepared_exports"):
                removed = _clear_all_prepared_exports()
                st.success(f"Export rimossi: {removed}")

        st.markdown("---")
        st.subheader("API Health")
        api_rows = [
            {"API": "Hunter.io", "Configured": HUNTER_IO_ENABLED, "Status": "Ready" if HUNTER_IO_ENABLED else "Missing key"},
            {"API": "AbuseIPDB", "Configured": ABUSEIPDB_ENABLED, "Status": "Ready" if ABUSEIPDB_ENABLED else "Missing key"},
            {"API": "VirusTotal", "Configured": VIRUSTOTAL_ENABLED, "Status": "Ready" if VIRUSTOTAL_ENABLED else "Missing key"},
            {"API": "IPinfo", "Configured": IPINFO_ENABLED, "Status": "Ready" if IPINFO_ENABLED else "Missing key"},
            {"API": "Reddit", "Configured": REDDIT_ENABLED, "Status": "Ready" if REDDIT_ENABLED else "Missing key"},
            {"API": "YouTube Data API", "Configured": YOUTUBE_ENABLED, "Status": "Ready" if YOUTUBE_ENABLED else "Missing key"},
            {"API": "URLScan", "Configured": URLSCAN_ENABLED, "Status": "Ready" if URLSCAN_ENABLED else "Disabled"},
            {"API": "AlienVault OTX", "Configured": OTX_ENABLED, "Status": "Ready" if OTX_ENABLED else "Disabled"},
            {"API": "GreyNoise", "Configured": GREYNOISE_ENABLED, "Status": "Ready" if GREYNOISE_ENABLED else "Missing key"},
            {"API": "crt.sh", "Configured": CRTSH_ENABLED, "Status": "Ready" if CRTSH_ENABLED else "Disabled"},
            {"API": "URLhaus", "Configured": URLHAUS_ENABLED, "Status": "Ready" if URLHAUS_ENABLED else "Disabled"},
            {"API": "ipapi", "Configured": IPAPI_ENABLED, "Status": "Ready" if IPAPI_ENABLED else "Disabled"},
        ]
        st.dataframe(pd.DataFrame(api_rows), use_container_width=True, hide_index=True)

        missing = [r["API"] for r in api_rows if not r["Configured"]]
        if missing:
            st.warning("API non configurate: " + ", ".join(missing))
        else:
            st.success("Tutte le API risultano configurate correttamente.")
        
        logger.info(f"System Insights: {n_scans} scans, {n_users} utenti, {size_reports/1024/1024:.1f} MB")
    
    except Exception as e:
        st.warning(f"Impossibile leggere System Insights: {e}")
        logger.error(f"Errore in System Insights: {e}", exc_info=True)

st.markdown("<hr>", unsafe_allow_html=True)
st.caption("© 2026 ArgAtlas — Enterprise v4")