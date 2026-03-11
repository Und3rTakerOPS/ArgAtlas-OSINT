# ArgAtlas v4

ArgAtlas e una dashboard Streamlit per workflow OSINT su username, email, dominio e indicatori IP.
Il progetto unisce acquisizione multi-piattaforma, arricchimento con API esterne, persistenza locale
su SQLite, visual analytics e export in formati utili per analisi tecnica e reporting.

## Indice

- [Obiettivo](#obiettivo)
- [Feature principali](#feature-principali)
- [Architettura](#architettura)
- [Struttura progetto](#struttura-progetto)
- [Requisiti](#requisiti)
- [Setup e avvio](#setup-e-avvio)
- [Configurazione `.env`](#configurazione-env)
- [Configurazione applicativa (`config.py`)](#configurazione-applicativa-configpy)
- [Workflow operativi](#workflow-operativi)
- [Data model e persistenza](#data-model-e-persistenza)
- [Export e artefatti](#export-e-artefatti)
- [Test](#test)
- [Prestazioni e resilienza](#prestazioni-e-resilienza)
- [Troubleshooting](#troubleshooting)
- [Sicurezza e compliance](#sicurezza-e-compliance)
- [Roadmap suggerita](#roadmap-suggerita)

## Obiettivo

ArgAtlas e pensato per:

- mappare la presenza digitale di un identificativo
- correlare indicatori tra piu piattaforme
- supportare investigazioni OSINT con una UI unica
- mantenere storico locale delle scansioni
- produrre output portabili (PDF/Excel/JSON/CSV/JSONL/HTML)

Il progetto e orientato a uso operativo locale e non richiede backend esterno.

## Feature principali

### 1) Dashboard intelligence

- KPI operativi (volumi, copertura, rischio)
- mappa globale con punti, heatmap, clustering e threat zones
- filtri combinati per username, date, percentuale trovati, rischio, stato verified
- timeline giornaliera, trend settimanale, distribuzione piattaforme
- grafo entita utente-piattaforma
- snapshot HTML delle visualizzazioni

### 2) Quick Scan

- scansione rapida di un singolo input
- controlli stato profilo su molte piattaforme
- scraping preview opzionale
- enrichment GitHub opzionale
- enrichment API esterne opzionale

### 3) Full Scan

- scansione estesa con maggiore controllo
- tuning dei parametri di scansione (es. max profili)
- risk assessment calcolato a fine esecuzione
- salvataggio persistente con deduplicazione temporale

### 4) Batch CSV

- ingest da CSV con colonna `username`
- chunking in memoria (`CSV_BATCH_SIZE`) per file grandi
- riepilogo processate/salvate/skippate
- supporto deduplicazione su finestra temporale

### 5) Reports Center

- visualizzazione risultati recenti
- preparazione export on-demand
- download PDF, Excel, JSON, CSV profili
- export bulk (JSONL, CSV summary, Excel)

### 6) Advanced Analysis

- email reverse lookup (Hunter.io)
- correlation tra account
- pattern detection su naming e preferenze piattaforma
- alert generation e stato alert (OPEN/RESOLVED)
- confronto tra scansioni (added/removed platforms, delta rischio)

### 7) System Insights

- numero scansioni e utenti unici
- peso cartella reports
- stato integrazioni API
- metriche rapide di salute operativa

## Architettura

### Componenti

- `ArgAtlas_v4.py`: UI Streamlit e orchestrazione workflow
- `engine_core.py`: motore di scansione, integrazioni API, risk assessment
- `datastore.py`: persistenza SQLite, filtri, bulk ops, alert store
- `analysis_tools.py`: correlazioni, pattern, alert logici, confronto scan
- `exporters.py`: generazione file di report
- `viz.py`: grafici Plotly e snapshot HTML
- `utils.py`: HTTP/rate limiting, validazione input, scraping metadata
- `config.py`: configurazioni applicative e feature flags

### Flusso end-to-end

```text
Input utente
	-> validate_username (utils)
	-> run_scan_for_input (engine_core)
			-> build_services_for_username
			-> check_profiles_exist (HTTP status)
			-> scrape_social_preview (metadata)
			-> github_lookup + external enrichments
			-> compute_risk_assessment
	-> save_scan (datastore)
	-> generate_alerts / analysis_tools
	-> visualizzazione in dashboard
	-> export file (exporters / viz)
```

## Struttura progetto

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

## Requisiti

- Python 3.10+ (consigliato 3.11)
- Ambiente virtuale dedicato
- Connettivita internet per lookup esterni
- Font presente in `fonts/NotoSans-Regular.ttf` per export PDF Unicode

Dipendenze principali:

- `streamlit>=1.20`
- `requests`
- `beautifulsoup4`
- `pandas`
- `fpdf`
- `plotly`
- `openpyxl`
- `networkx`
- `python-dotenv`

## Setup e avvio

### Windows PowerShell (raccomandato)

1. Posizionati nella cartella del progetto:

```powershell
cd .\osint_suite_pro
```

2. Crea e attiva il virtual environment.

Se sei nella root workspace (`Project_Sherlook`):

```powershell
python -m venv myenv
.\myenv\Scripts\Activate.ps1
```

Se sei dentro `osint_suite_pro`:

```powershell
python -m venv ..\myenv
.\..\myenv\Scripts\Activate.ps1
```

3. Installa dipendenze:

```powershell
pip install -r requirements.txt
```

4. Configura `.env`:

```powershell
Copy-Item .env.example .env
```

5. Avvia:

```powershell
streamlit run ArgAtlas_v4.py
```

Accesso UI tipico: `http://localhost:8501`

### Avvio rapido consigliato (workspace root)

```powershell
cd .\osint_suite_pro
.\..\myenv\Scripts\Activate.ps1
streamlit run ArgAtlas_v4.py
```

## Configurazione `.env`

Il file `.env.example` include tutte le variabili supportate:

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

Note importanti:

- alcune integrazioni sono utilizzabili anche senza chiave (es. URLScan in forma limitata, OTX base, crt.sh, URLhaus, ipapi)
- quando una chiave manca, il modulo relativo ritorna stato `enabled: false` o `skipped` senza bloccare il flusso

## Configurazione applicativa (`config.py`)

### Path e UI

- `BASE_DIR`
- `DB_PATH`
- `REPORTS_PATH`
- `ACCENT_COLOR`
- `PAGE_TITLE`

### Performance e dashboard

- `CACHE_LIMIT`
- `CLUSTER_LEVELS`
- `DEFAULT_MAP_ZOOM`
- `DEFAULT_MAP_CENTER`
- `THREAT_ZONES`

### CSV e scanning

- `MAX_CSV_ROWS`
- `CSV_ENCODING`
- `CSV_BATCH_SIZE`
- `DEFAULT_MAX_PROFILES`
- `MAX_CONCURRENT_CHECKS`
- `SKIP_DUPLICATE_DAYS`

### HTTP e rate limiting

- `HTTP_TIMEOUT`
- `SCRAPE_DELAY`
- `STATUS_CHECK_DELAY`
- `MAX_DOMAIN_CACHE_SIZE`
- `DOMAIN_RATE_LIMITS`

### Alert e analisi

- `ALERT_CONFIG`
- `CORRELATION_MIN_PLATFORMS`
- `CORRELATION_MIN_SIMILARITY`

## Workflow operativi

### Input supportati

- username
- email
- handle con simboli consentiti
- IP (per moduli threat intel)
- domini/URL (per moduli reputation)

Validazione input (`utils.validate_username`):

- lunghezza max 100
- charset consentito: lettere, numeri, `._-@+` e spazi
- blocco username riservati (`admin`, `root`, `system`, `null`, `undefined`)

### Scansione base

La funzione `run_scan_for_input` esegue:

1. normalizzazione input (`username` base)
2. generazione servizi social (`build_services_for_username`)
3. status check profili (`check_profiles_exist`)
4. scraping metadata (`scrape_social_preview`)
5. lookup GitHub (`github_lookup`)
6. enrichment esterno (`run_external_enrichment`)
7. risk assessment (`compute_risk_assessment`)
8. generazione varianti username (`brute_username`)

### Batch CSV

`run_batch_scan_from_csv` usa `pandas.read_csv(..., chunksize=CSV_BATCH_SIZE)`:

- migliore uso memoria su file grandi
- log per chunk processato
- skip righe vuote/header ripetuto

### Risk assessment

Formula pesata (0-100) basata su:

- percentuale profili trovati (`found_profiles_pct`)
- segnalazioni VirusTotal (`malicious`, `suspicious`)
- abuse confidence score da AbuseIPDB

Livelli:

- `High` >= 70
- `Medium` >= 40
- `Low` < 40

## Integrations dettagliate

### Social/profile checks

`build_services_for_username` copre molte piattaforme, tra cui:

- GitHub, X/Twitter, Instagram, Facebook, TikTok, YouTube, LinkedIn, Reddit, Telegram
- Twitch, Mastodon, Discord, Bluesky, Threads, Pinterest, Tumblr, Medium, Dev.to
- Stack Overflow, Quora
- Steam, PlayStation, Xbox, Roblox
- DeviantArt, ArtStation, Flickr, Behance
- Spotify, SoundCloud, Bandcamp, Last.fm
- GitLab, Kaggle, Replit, Codepen e altre

### Threat intel / enrichment

- GitHub API
- Reddit API (OAuth con fallback pubblico)
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

Tutti i lookup usano wrapper resiliente `_api_request_json` con:

- timeout centralizzato
- retry su status retryable (`408`, `425`, `429`, `500`, `502`, `503`, `504`)
- backoff progressivo
- cache in memoria TTL per GET

## Data model e persistenza

SQLite locale: `osint_scans.db`

### Tabella `scans`

Campi principali:

- `id`
- `username`
- `queried_at`
- `result_json`
- `found_pct`
- `risk_score`
- `verified`

Indici principali:

- `idx_username`
- `idx_queried_at`
- `idx_found_pct`
- `idx_risk_score`
- `idx_verified`

### Tabella `scan_alerts`

Campi principali:

- `id`
- `scan_id` (FK -> scans)
- `alert_type`
- `alert_msg`
- `severity`
- `status`
- `created_at`

### Tabella `searched_people`

Registro aggregato per username:

- `username` (unique)
- `first_seen`
- `last_seen`
- `scans_count`
- `last_found_pct`
- `last_risk_score`
- `last_result_json`

### Deduplicazione

`save_scan` evita inserimenti duplicati se stesso username e stato scansionato
negli ultimi `SKIP_DUPLICATE_DAYS`.

## Export e artefatti

Directory output: `reports/`

### Export singolo

- PDF: `generate_pdf_report`
- Excel: `generate_excel`
- JSON: `generate_json`
- CSV profili: `generate_csv_profiles`

### Export bulk

- JSONL: `generate_jsonl_bulk`
- CSV summary: `generate_csv_bulk_summary`
- Excel bulk (da UI)

### Snapshot HTML

Gestito via `viz.export_snapshot_html` dalla dashboard.

Naming file: include prefix, username safe e timestamp (`YYYYMMDD_HHMMSS`).

## Test

Suite attuale: `unittest`

- `tests/test_analysis_tools.py`
	- correlazioni account
	- pattern detection
	- alert generation
	- compare scan results
- `tests/test_datastore.py`
	- deduplicazione salvataggi
	- lifecycle alert (OPEN -> RESOLVED)

Esecuzione:

```powershell
cd .\osint_suite_pro
.\..\myenv\Scripts\python.exe -m unittest discover -s tests -v
```

## Prestazioni e resilienza

### Strategie implementate

- rate limiting per dominio (con cache LRU dei domini)
- retry + backoff su errori transienti
- cache API con TTL configurabile
- chunking CSV per limitare memory pressure
- cleanup export preparati in sessione UI

### Suggerimenti operativi

- riduci `do_preview` per scansioni massive
- abbassa `max_profiles` in reti lente o con rate limit aggressivi
- aumenta `EXTERNAL_API_TIMEOUT` in ambienti con latenza alta
- mantieni `EXTERNAL_API_RETRIES` basso per evitare blocchi prolungati

## Troubleshooting

### 1) Errore attivazione script PowerShell

Se l'esecuzione script e bloccata:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### 2) Porta Streamlit occupata

```powershell
streamlit run ArgAtlas_v4.py --server.port 8502
```

### 3) API senza risultati

- verifica chiavi in `.env`
- controlla limiti quota provider
- controlla che input sia del tipo previsto (IP, dominio, username)

### 4) Database apparentemente vuoto

- conferma `DB_PATH` in `config.py`
- verifica che l'app stia puntando allo stesso file SQLite
- controlla se la deduplicazione sta skippando salvataggi recenti

### 5) PDF export fallisce

- verifica presenza font `fonts/NotoSans-Regular.ttf`
- verifica permessi di scrittura in `reports/`

## Sicurezza e compliance

- non inserire segreti hardcoded nel codice
- usa sempre variabili ambiente per token/API key
- limita l'uso a casi d'uso autorizzati
- rispetta ToS provider, privacy policy e normativa locale

## Limiti noti

- molti check profilo sono euristici (status HTTP + pattern URL)
- metadata scraping dipende dal markup corrente delle piattaforme
- disponibilita e accuratezza enrichment dipendono dai provider esterni
- alcune sezioni avanzate sono baseline analitica, non pipeline forense completa

## Roadmap suggerita

- test coverage piu ampia su engine e UI logic
- integrazione provider aggiuntivi con quota awareness
- export STIX/TAXII o formati SOC-oriented
- scheduler scansioni ricorrenti
- autenticazione/ruoli per ambienti multi-utente

## Avviso legale

Usa ArgAtlas solo su soggetti, account e domini per cui hai base legale o autorizzazione.
L'utente e responsabile della conformita normativa (privacy, termini d'uso, leggi locali).