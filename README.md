# ArgAtlas (Beta)

ArgAtlas is a Streamlit dashboard for OSINT workflows on usernames, emails, domains, and IP indicators.
The project combines multi-platform discovery, external API enrichment, local SQLite persistence,
visual analytics, and exports suitable for technical analysis and reporting.

## Table of contents

- [Purpose](#purpose)
- [Core features](#core-features)
- [Architecture](#architecture)
- [Project structure](#project-structure)
- [Requirements](#requirements)
- [Setup and run](#setup-and-run)
- [Environment configuration (`.env`)](#environment-configuration-env)
- [Application configuration (`config.py`)](#application-configuration-configpy)
- [Operational workflows](#operational-workflows)
- [Data model and persistence](#data-model-and-persistence)
- [Exports and artifacts](#exports-and-artifacts)
- [Tests](#tests)
- [Performance and resilience](#performance-and-resilience)
- [Troubleshooting](#troubleshooting)
- [Security and compliance](#security-and-compliance)
- [Suggested roadmap](#suggested-roadmap)

## Purpose

ArgAtlas is designed to:

- map the digital footprint of an identifier
- correlate indicators across multiple platforms
- support OSINT investigations from a single UI
- keep a local history of scans
- produce portable outputs (PDF/Excel/JSON/CSV/JSONL/HTML)

The project is local-first and does not require an external backend.

## Core features

### 1) Intelligence dashboard

- operational KPIs (volume, coverage, risk)
- global map with points, heatmap, clustering, and threat zones
- combined filters by username, date range, found percentage, risk, and verified state
- daily timeline, weekly trend, platform distribution
- user-platform entity graph
- HTML snapshot export of visualizations

### 2) Quick Scan

- fast scan for a single input
- profile status checks across many platforms
- optional scraping preview
- optional GitHub enrichment
- optional external API enrichment

### 3) Full Scan

- extended scan with deeper control
- scan parameter tuning (for example max profiles)
- risk assessment computed at the end of each run
- persistent storage with temporal deduplication

### 4) Batch CSV

- CSV ingestion using a `username` column
- memory-safe chunking (`CSV_BATCH_SIZE`) for larger files
- processed/saved/skipped summary
- deduplication support by time window

### 5) Reports Center

- recent scan review
- on-demand export preparation
- PDF, Excel, JSON, and profile CSV downloads
- bulk exports (JSONL, CSV summary, Excel)

### 6) Advanced Analysis

- email reverse lookup (Hunter.io)
- account correlation
- naming and platform-preference pattern detection
- alert generation and alert state tracking (OPEN/RESOLVED)
- scan-to-scan comparison (added/removed platforms, risk delta)

### 7) System Insights

- total scans and unique users
- reports folder size
- API integration status
- quick operational health metrics

## Architecture

### Components

- `ArgAtlas_v4.py`: Streamlit UI and workflow orchestration
- `engine_core.py`: scan engine, API integrations, risk scoring
- `datastore.py`: SQLite persistence, filtering, bulk operations, alert storage
- `analysis_tools.py`: correlation, pattern analysis, alert logic, scan comparison
- `exporters.py`: report file generation
- `viz.py`: Plotly visual layers and HTML snapshots
- `utils.py`: HTTP/rate limiting, input validation, metadata extraction
- `config.py`: app configuration and feature flags

### End-to-end flow

```text
User input
  -> validate_username (utils)
  -> run_scan_for_input (engine_core)
      -> build_services_for_username
      -> check_profiles_exist (HTTP status)
      -> scrape_social_preview (metadata)
      -> github_lookup + external enrichments
      -> compute_risk_assessment
  -> save_scan (datastore)
  -> generate_alerts / analysis_tools
  -> dashboard rendering
  -> file export (exporters / viz)
```

## Project structure

```text
osint_suite_pro/
|-- .env.example
|-- ArgAtlas_v4.py
|-- analysis_tools.py
|-- config.py
|-- datastore.py
|-- engine_core.py
|-- exporters.py
|-- requirements.txt
|-- utils.py
|-- viz.py
|-- data/
|   `-- capitals.json
|-- tests/
|   |-- test_analysis_tools.py
|   `-- test_datastore.py
|-- reports/
|-- fonts/
|-- backup_unused/
`-- osint_scans.db
```

## Requirements

- Python 3.10+ (3.11 recommended)
- dedicated virtual environment
- internet connectivity for external lookups
- font available at `fonts/NotoSans-Regular.ttf` for Unicode PDF export

Main dependencies:

- `streamlit>=1.20`
- `requests`
- `beautifulsoup4`
- `pandas`
- `fpdf`
- `plotly`
- `openpyxl`
- `networkx`
- `python-dotenv`

## Setup and run

### Windows PowerShell (recommended)

1. Move to project folder:

```powershell
cd .\osint_suite_pro
```

2. Create and activate a virtual environment.

If you are in the workspace root (`Project_Sherlook`):

```powershell
python -m venv myenv
.\myenv\Scripts\Activate.ps1
```

If you are already inside `osint_suite_pro`:

```powershell
python -m venv ..\myenv
.\..\myenv\Scripts\Activate.ps1
```

3. Install dependencies:

```powershell
pip install -r requirements.txt
```

4. Configure `.env`:

```powershell
Copy-Item .env.example .env
```

5. Start app:

```powershell
streamlit run ArgAtlas_v4.py
```

Typical UI URL: `http://localhost:8501`

### Recommended quick start (workspace root)

```powershell
cd .\osint_suite_pro
.\..\myenv\Scripts\Activate.ps1
streamlit run ArgAtlas_v4.py
```

## Environment configuration (`.env`)

The `.env.example` file includes all supported variables.

### Core integrations

- `HUNTER_IO_API_KEY`
- `GITHUB_API_TOKEN`
- `ABUSEIPDB_API_KEY`
- `VIRUSTOTAL_API_KEY`
- `IPINFO_TOKEN`
- `REDDIT_CLIENT_ID`
- `REDDIT_CLIENT_SECRET`
- `REDDIT_USER_AGENT`
- `YOUTUBE_API_KEY`

### Additional OSINT APIs

- `URLSCAN_API_KEY`
- `OTX_API_KEY`
- `GREYNOISE_API_KEY`

### API behavior

- `EXTERNAL_API_TIMEOUT` (default: `10`)
- `EXTERNAL_API_RETRIES` (default: `2`)
- `EXTERNAL_API_RETRY_BACKOFF` (default: `0.75`)
- `EXTERNAL_API_CACHE_TTL` (default: `86400`)

Important notes:

- some integrations can still work without keys (for example limited URLScan, baseline OTX, crt.sh, URLhaus, ipapi)
- when a key is missing, the related module returns `enabled: false` or `skipped` without breaking the pipeline

## Application configuration (`config.py`)

### Paths and UI

- `BASE_DIR`
- `DB_PATH`
- `REPORTS_PATH`
- `ACCENT_COLOR`
- `PAGE_TITLE`

### Performance and dashboard

- `CACHE_LIMIT`
- `CLUSTER_LEVELS`
- `DEFAULT_MAP_ZOOM`
- `DEFAULT_MAP_CENTER`
- `THREAT_ZONES`

### CSV and scanning

- `MAX_CSV_ROWS`
- `CSV_ENCODING`
- `CSV_BATCH_SIZE`
- `DEFAULT_MAX_PROFILES`
- `MAX_CONCURRENT_CHECKS`
- `SKIP_DUPLICATE_DAYS`

### HTTP and rate limiting

- `HTTP_TIMEOUT`
- `SCRAPE_DELAY`
- `STATUS_CHECK_DELAY`
- `MAX_DOMAIN_CACHE_SIZE`
- `DOMAIN_RATE_LIMITS`

### Alerting and analysis

- `ALERT_CONFIG`
- `CORRELATION_MIN_PLATFORMS`
- `CORRELATION_MIN_SIMILARITY`

## Operational workflows

### Supported inputs

- username
- email
- handle with allowed symbols
- IP (for threat intel modules)
- domain/URL (for reputation modules)

Input validation (`utils.validate_username`):

- maximum length: 100
- allowed charset: letters, digits, `._-@+`, spaces
- reserved username blocklist (`admin`, `root`, `system`, `null`, `undefined`)

### Base scan

`run_scan_for_input` performs:

1. input normalization (base username)
2. social service map generation (`build_services_for_username`)
3. profile status checks (`check_profiles_exist`)
4. metadata scraping (`scrape_social_preview`)
5. GitHub lookup (`github_lookup`)
6. external enrichment (`run_external_enrichment`)
7. risk scoring (`compute_risk_assessment`)
8. username variant generation (`brute_username`)

### Batch CSV

`run_batch_scan_from_csv` uses `pandas.read_csv(..., chunksize=CSV_BATCH_SIZE)`:

- more stable memory profile on larger files
- chunk-level logging
- skips empty rows and repeated header rows

### Risk assessment

Weighted score (0-100) based on:

- found profile percentage (`found_profiles_pct`)
- VirusTotal findings (`malicious`, `suspicious`)
- AbuseIPDB confidence score

Levels:

- `High` >= 70
- `Medium` >= 40
- `Low` < 40

## Integration details

### Social/profile checks

`build_services_for_username` covers many platforms, including:

- GitHub, X/Twitter, Instagram, Facebook, TikTok, YouTube, LinkedIn, Reddit, Telegram
- Twitch, Mastodon, Discord, Bluesky, Threads, Pinterest, Tumblr, Medium, Dev.to
- Stack Overflow, Quora
- Steam, PlayStation, Xbox, Roblox
- DeviantArt, ArtStation, Flickr, Behance
- Spotify, SoundCloud, Bandcamp, Last.fm
- GitLab, Kaggle, Replit, Codepen, and more

### Threat intel / enrichment

- GitHub API
- Reddit API (OAuth with public fallback)
- YouTube Data API v3
- AbuseIPDB
- IPinfo
- VirusTotal
- URLScan.io
- AlienVault OTX
- GreyNoise
- crt.sh
- URLhaus
- ipapi

All lookups use a resilient wrapper (`_api_request_json`) with:

- centralized timeout
- retry for retryable statuses (`408`, `425`, `429`, `500`, `502`, `503`, `504`)
- progressive backoff
- in-memory TTL cache for GET requests

## Data model and persistence

Local SQLite database: `osint_scans.db`

### `scans` table

Main fields:

- `id`
- `username`
- `queried_at`
- `result_json`
- `found_pct`
- `risk_score`
- `verified`

Main indexes:

- `idx_username`
- `idx_queried_at`
- `idx_found_pct`
- `idx_risk_score`
- `idx_verified`

### `scan_alerts` table

Main fields:

- `id`
- `scan_id` (FK -> scans)
- `alert_type`
- `alert_msg`
- `severity`
- `status`
- `created_at`

### `searched_people` table

Aggregated per-username registry:

- `username` (unique)
- `first_seen`
- `last_seen`
- `scans_count`
- `last_found_pct`
- `last_risk_score`
- `last_result_json`

### Deduplication

`save_scan` blocks duplicate inserts when the same username was scanned within
`SKIP_DUPLICATE_DAYS`.

## Exports and artifacts

Output directory: `reports/`

### Single-record exports

- PDF: `generate_pdf_report`
- Excel: `generate_excel`
- JSON: `generate_json`
- Profile CSV: `generate_csv_profiles`

### Bulk exports

- JSONL: `generate_jsonl_bulk`
- CSV summary: `generate_csv_bulk_summary`
- Bulk Excel (from UI)

### HTML snapshot

Handled through `viz.export_snapshot_html` in the dashboard.

Filename policy: prefix, safe username, and timestamp (`YYYYMMDD_HHMMSS`).

## Tests

Current suite: `unittest`

- `tests/test_analysis_tools.py`
  - account correlations
  - pattern detection
  - alert generation
  - scan comparison
- `tests/test_datastore.py`
  - save deduplication
  - alert lifecycle (OPEN -> RESOLVED)

Run tests:

```powershell
cd .\osint_suite_pro
.\..\myenv\Scripts\python.exe -m unittest discover -s tests -v
```

## Performance and resilience

### Implemented strategies

- per-domain rate limiting (with LRU domain cache)
- retry + backoff for transient failures
- API response caching with configurable TTL
- CSV chunking to reduce memory pressure
- prepared export cleanup in UI session

### Operational recommendations

- reduce `do_preview` for very large runs
- lower `max_profiles` in slow or heavily rate-limited environments
- increase `EXTERNAL_API_TIMEOUT` on high-latency networks
- keep `EXTERNAL_API_RETRIES` conservative to avoid long blocking runs

## Troubleshooting

### 1) PowerShell script activation blocked

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### 2) Streamlit port already in use

```powershell
streamlit run ArgAtlas_v4.py --server.port 8502
```

### 3) APIs returning no data

- check keys in `.env`
- verify provider quotas/rate limits
- ensure input type matches module expectations (IP, domain, username)

### 4) Database appears empty

- confirm `DB_PATH` in `config.py`
- verify app points to the intended SQLite file
- check whether deduplication is skipping recent saves

### 5) PDF export failure

- verify font exists at `fonts/NotoSans-Regular.ttf`
- verify write permissions on `reports/`

## Security and compliance

- do not hardcode secrets in source code
- always use environment variables for tokens/API keys
- run only for authorized use cases
- respect provider ToS, privacy requirements, and local regulations

## Known limitations

- many profile checks are heuristic (HTTP status + URL patterns)
- metadata scraping quality depends on platform markup changes
- external enrichment quality depends on third-party provider quality/availability
- advanced sections provide baseline analytics, not a full forensic pipeline

## Suggested roadmap

- broader test coverage across engine and UI logic
- additional providers with quota-aware scheduling
- STIX/TAXII or SOC-oriented export formats
- recurring scan scheduler
- authentication/roles for multi-user deployments

## Legal notice

Use ArgAtlas only for subjects, accounts, and domains where you have legal basis or authorization.
The operator is responsible for compliance with applicable laws, privacy rules, and platform terms.
