import os
from dotenv import load_dotenv

load_dotenv()

# Percorso principale del progetto
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Percorso database
DB_PATH = os.path.join(BASE_DIR, "osint_scans.db")

# Percorso dove salvare i report (PDF / Excel)
REPORTS_PATH = os.path.join(BASE_DIR, "reports")

# User-Agent per le richieste HTTP
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OSINT-Suite-Pro/2.0"

# ==================== DASHBOARD CONFIGURATION ====================

# Theme and UI
ACCENT_COLOR = "#007BFF"
PAGE_TITLE = "ArgAtlas"

# Cache and performance
CACHE_LIMIT = 500
CLUSTER_LEVELS = {0: 1.0, 1: 0.5, 2: 0.25, 3: 0.1, 4: 0.05}

# Map defaults
DEFAULT_MAP_ZOOM = 1
DEFAULT_MAP_CENTER = {"lat": 20.0, "lon": 0.0}  # Float per type compatibility

# Threat zones (lat, lon) - London, NYC, Tokyo, Sydney, Singapore
THREAT_ZONES = [
    (51.5, -0.12),
    (40.7, -74.0),
    (35.7, 139.7),
    (-33.9, 151.2),
    (1.35, 103.8),
]

# CSV validation
MAX_CSV_ROWS = 5000
CSV_ENCODING = "utf-8"

# Scan defaults
DEFAULT_MAX_PROFILES = 8
MAX_CONCURRENT_CHECKS = 50

# Reports
RECENT_SCANS_LIMIT = 300
LIVE_MONITOR_LIMIT = 20

# ==================== ADVANCED FEATURES ====================

# Email Reverse Lookup (Hunter.io API)
# Ottieni free API key da: https://hunter.io
HUNTER_IO_API_KEY = os.getenv("HUNTER_IO_API_KEY", "")
HUNTER_IO_ENABLED = bool(HUNTER_IO_API_KEY)

# ==================== EXTERNAL API INTEGRATIONS ====================
# Usa variabili ambiente per non salvare segreti nel codice.
GITHUB_API_TOKEN = os.getenv("GITHUB_API_TOKEN", "")

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_ENABLED = bool(ABUSEIPDB_API_KEY)

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
VIRUSTOTAL_ENABLED = bool(VIRUSTOTAL_API_KEY)

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")
IPINFO_ENABLED = bool(IPINFO_TOKEN)

REDDIT_CLIENT_ID = os.getenv("REDDIT_CLIENT_ID", "")
REDDIT_CLIENT_SECRET = os.getenv("REDDIT_CLIENT_SECRET", "")
REDDIT_USER_AGENT = os.getenv("REDDIT_USER_AGENT", USER_AGENT)
REDDIT_ENABLED = bool(REDDIT_CLIENT_ID and REDDIT_CLIENT_SECRET)

YOUTUBE_API_KEY = os.getenv("YOUTUBE_API_KEY", "")
YOUTUBE_ENABLED = bool(YOUTUBE_API_KEY)

# Additional OSINT APIs (free/free-tier)
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")
# URLScan supports limited public queries without key; key improves quota.
URLSCAN_ENABLED = True

OTX_API_KEY = os.getenv("OTX_API_KEY", "")
OTX_ENABLED = True

GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY", "")
GREYNOISE_ENABLED = bool(GREYNOISE_API_KEY)

# crt.sh and URLhaus are public endpoints.
CRTSH_ENABLED = True
URLHAUS_ENABLED = True

# ipapi can be used as free fallback geolocation service.
IPAPI_ENABLED = True

# External APIs resilienza
EXTERNAL_API_TIMEOUT = float(os.getenv("EXTERNAL_API_TIMEOUT", "10"))
EXTERNAL_API_RETRIES = int(os.getenv("EXTERNAL_API_RETRIES", "2"))
EXTERNAL_API_RETRY_BACKOFF = float(os.getenv("EXTERNAL_API_RETRY_BACKOFF", "0.75"))
EXTERNAL_API_CACHE_TTL = int(os.getenv("EXTERNAL_API_CACHE_TTL", "86400"))  # 24h

# Alert System Configuration
# Soglie per generare alert automatici
ALERT_CONFIG = {
    "min_found_pct_threshold": 50.0,  # Alert se % profili trovati > 50%
    "verified_account_alert": True,   # Alert se account verificato
    "high_follower_threshold": 10000, # Alert se followers > 10k
    "enable_alerts": True              # Master toggle
}

# Deduplication
SKIP_DUPLICATE_DAYS = 7  # Considera duplicate se scansionato negli ultimi 7 giorni

# Account Correlation
CORRELATION_MIN_PLATFORMS = 3  # Min comuni per suggerire correlazione
CORRELATION_MIN_SIMILARITY = 0.70  # Min score di similarità (0-1)

# Rate Limiting Domains (secondi tra richieste)
DOMAIN_RATE_LIMITS = {
    "instagram.com": 0.8,
    "facebook.com": 0.8,
    "twitter.com": 0.5,
    "x.com": 0.5,
    "github.com": 0.3,
    "reddit.com": 0.4,
    "linkedin.com": 1.0,
    "tiktok.com": 1.0,
    "youtube.com": 0.5,
    "twitch.tv": 0.6,
    "default": 0.25
}

# ==================== HTTP CONFIGURATION ====================
# Timeouts e delays centralizzati (secondi)
HTTP_TIMEOUT = 8  # Timeout per HTTP requests
SCRAPE_DELAY = 0.8  # Delay tra scraping requests
STATUS_CHECK_DELAY = 0.6  # Delay tra status check requests
MAX_DOMAIN_CACHE_SIZE = 1000  # Max domains cached per rate limiting
CSV_BATCH_SIZE = 100  # Rows per chunk in CSV batch processing

# Creazione automatica delle cartelle necessarie
if not os.path.exists(REPORTS_PATH):
    os.makedirs(REPORTS_PATH, exist_ok=True)