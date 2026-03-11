import sqlite3
import os
from datetime import datetime, timedelta, timezone
import json
import logging
from typing import Any, Optional, List, Dict, Tuple
from config import DB_PATH

logger = logging.getLogger(__name__)

# Crea tabelle nel database se non esistono (con indexing)
CREATE_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    queried_at TEXT NOT NULL,
    result_json TEXT NOT NULL,
    found_pct REAL,
    risk_score REAL,
    verified BOOLEAN DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_username ON scans(username);
CREATE INDEX IF NOT EXISTS idx_queried_at ON scans(queried_at DESC);
CREATE INDEX IF NOT EXISTS idx_found_pct ON scans(found_pct DESC);
CREATE INDEX IF NOT EXISTS idx_risk_score ON scans(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_verified ON scans(verified);

CREATE TABLE IF NOT EXISTS scan_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    alert_type TEXT,
    alert_msg TEXT,
    severity TEXT DEFAULT 'LOW',
    status TEXT DEFAULT 'OPEN',
    created_at TEXT,
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scan_alerts ON scan_alerts(scan_id);

CREATE TABLE IF NOT EXISTS searched_people (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    scans_count INTEGER NOT NULL DEFAULT 1,
    last_found_pct REAL,
    last_risk_score REAL,
    last_result_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_searched_people_username ON searched_people(username);
CREATE INDEX IF NOT EXISTS idx_searched_people_last_seen ON searched_people(last_seen DESC);
"""

def init_db(path: str = DB_PATH) -> None:
    """Inizializza il database con tabelle e indici."""
    try:
        db_dir = os.path.dirname(path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        with sqlite3.connect(path) as conn:
            cur = conn.cursor()
            
            # Esegui ogni statement CREATE separatamente
            for statement in CREATE_SQL.split(';'):
                if statement.strip():
                    try:
                        cur.execute(statement)
                    except sqlite3.OperationalError as e:
                        logger.debug(f"SQL statement skipped (already exists): {e}")
            
            # Ensure legacy installations get the found_pct column if missing
            try:
                cur.execute("ALTER TABLE scans ADD COLUMN found_pct REAL")
                logger.info("Added missing column 'found_pct' to scans table")
            except sqlite3.OperationalError:
                # Column probably already exists
                pass

            try:
                cur.execute("ALTER TABLE scans ADD COLUMN risk_score REAL")
                logger.info("Added missing column 'risk_score' to scans table")
            except sqlite3.OperationalError:
                pass

            try:
                cur.execute("ALTER TABLE searched_people ADD COLUMN last_risk_score REAL")
                logger.info("Added missing column 'last_risk_score' to searched_people table")
            except sqlite3.OperationalError:
                pass

            try:
                cur.execute("ALTER TABLE scan_alerts ADD COLUMN severity TEXT DEFAULT 'LOW'")
                logger.info("Added missing column 'severity' to scan_alerts table")
            except sqlite3.OperationalError:
                pass

            try:
                cur.execute("ALTER TABLE scan_alerts ADD COLUMN status TEXT DEFAULT 'OPEN'")
                logger.info("Added missing column 'status' to scan_alerts table")
            except sqlite3.OperationalError:
                pass
            
            conn.commit()
        logger.info(f"Database initialized at {path}")
    except Exception as e:
        logger.exception(f"Error initializing database at {path}")
        raise


def save_scan(result: dict, path: str = DB_PATH, skip_duplicate_days: int = 7) -> bool:
    """
    Salva uno scan. Se lo stesso username è stato scansionato negli ultimi N giorni,
    chiede conferma (ritorna False se dovrebbe skippare).
    
    Args:
        result: Dizionario con risultati scan
        path: Percorso database
        skip_duplicate_days: Numero giorni per considerare duplicate
    
    Returns:
        True se salvato, False se duplicate trovato
    """
    try:
        with sqlite3.connect(path) as conn:
            cur = conn.cursor()
            
            username = result.get("username")
            queried_at = result.get("queried_at", datetime.now(timezone.utc).isoformat())
            
            # Calcola percentuale profili trovati
            profile_status = result.get("profile_status", {})
            found_pct = 0.0
            if profile_status:
                found = sum(1 for v in profile_status.values() if v.get("exists"))
                found_pct = round(found / len(profile_status) * 100.0, 1)

            risk_score = float((result.get("risk_assessment") or {}).get("score") or 0.0)
            
            # Verifica scan duplicate recente
            cutoff = (datetime.fromisoformat(queried_at.replace('Z', '+00:00')) - timedelta(days=skip_duplicate_days)).isoformat()
            cur.execute(
                "SELECT id, queried_at FROM scans WHERE username = ? AND queried_at > ? ORDER BY queried_at DESC LIMIT 1",
                (username, cutoff)
            )
            existing = cur.fetchone()
            
            if existing:
                logger.warning(f"Username {username} scansionato recentemente ({existing[1]}). Considerare come duplicate.")
                return False
            
            # Salva lo scan
            cur.execute(
                "INSERT INTO scans (username, queried_at, result_json, found_pct, risk_score, verified) VALUES (?, ?, ?, ?, ?, ?)",
                (username, queried_at, json.dumps(result), found_pct, risk_score, 0)
            )

            # Mantieni un registro aggregato delle persone cercate
            serialized_result = json.dumps(result)
            cur.execute(
                """
                INSERT INTO searched_people (
                    username, first_seen, last_seen, scans_count, last_found_pct, last_risk_score, last_result_json
                )
                VALUES (?, ?, ?, 1, ?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    scans_count = searched_people.scans_count + 1,
                    last_found_pct = excluded.last_found_pct,
                    last_risk_score = excluded.last_risk_score,
                    last_result_json = excluded.last_result_json
                """,
                (username, queried_at, queried_at, found_pct, risk_score, serialized_result)
            )

            conn.commit()
            logger.info(f"Scan salvato: {username} ({found_pct}% profili trovati)")
            return True
    except Exception as e:
        logger.exception(f"Errore salvataggio scan: {e}")
        return False


def load_recent(
    limit: int = 100,
    path: str = DB_PATH,
    filters: Optional[Dict[str, Any]] = None
) -> List[Dict]:
    """
    Carica scansioni recenti con filtri avanzati.
    
    Args:
        limit: Numero max di record
        path: Percorso database
        filters: Dict con chiavi come 'username_regex', 'min_found_pct', 'verified', 'days_back'
    
    Returns:
        Lista di dizionari con scansioni
    """
    try:
        with sqlite3.connect(path) as conn:
            cur = conn.cursor()
            
            query = "SELECT id, username, queried_at, result_json, found_pct, risk_score FROM scans WHERE 1=1"
            params = []
            
            if filters:
                if "username_regex" in filters:
                    # SQLite non ha REGEX di default, usa LIKE come appross
                    query += " AND username LIKE ?"
                    params.append(f"%{str(filters['username_regex'])}%")
                if "min_found_pct" in filters:
                    query += " AND found_pct >= ?"
                    params.append(float(filters['min_found_pct']))
                if "min_risk_score" in filters:
                    query += " AND risk_score >= ?"
                    params.append(float(filters["min_risk_score"]))
                if "verified" in filters and filters["verified"]:
                    query += " AND verified = 1"
                if "days_back" in filters:
                    days_back = int(filters["days_back"])
                    cutoff = (datetime.utcnow() - timedelta(days=days_back)).isoformat()
                    query += " AND queried_at > ?"
                    params.append(cutoff)
            
            query += " ORDER BY queried_at DESC LIMIT ?"
            params.append(limit)
            
            cur.execute(query, params)
            rows = cur.fetchall()
            
            out = []
            for r in rows:
                out.append({
                    "id": r[0],
                    "username": r[1],
                    "queried_at": r[2],
                    "result": json.loads(r[3]),
                    "found_pct": r[4],
                    "risk_score": r[5]
                })
            return out
    except Exception as e:
        logger.exception(f"Errore caricamento scansioni")
        return []


def bulk_delete_username(username: str, path: str = DB_PATH) -> int:
    """Cancella tutti gli scan di uno username. Ritorna numero righe cancellate."""
    try:
        with sqlite3.connect(path) as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM scans WHERE username = ?", (username,))
            conn.commit()
            deleted = cur.rowcount
            logger.info(f"Cancellati {deleted} scan per {username}")
            return deleted
    except Exception as e:
        logger.exception(f"Errore cancellazione scan per {username}")
        return 0


def bulk_mark_verified(ids: List[int], verified: bool = True, path: str = DB_PATH) -> int:
    """Marca scan come verificati. Ritorna numero aggiornati."""
    if not ids:
        return 0
    try:
        with sqlite3.connect(path) as conn:
            cur = conn.cursor()
            placeholders = ",".join("?" * len(ids))
            cur.execute(f"UPDATE scans SET verified = ? WHERE id IN ({placeholders})", [verified] + ids)
            conn.commit()
            updated = cur.rowcount
            logger.info(f"Marcati {updated} scan come verified={verified}")
            return updated
    except Exception as e:
        logger.exception(f"Errore marking scans as verified")
        return 0


def bulk_export_usernames(
    filter_dict: Optional[Dict[str, Any]] = None,
    path: str = DB_PATH
) -> List[str]:
    """Esporta lista di username unici con filtri. Usato per bulk re-scan."""
    try:
        with sqlite3.connect(path) as conn:
            cur = conn.cursor()
            
            query = "SELECT DISTINCT username FROM scans WHERE 1=1"
            params = []
            
            if filter_dict:
                if "min_found_pct" in filter_dict:
                    query += " AND id IN (SELECT id FROM scans WHERE found_pct >= ?)"
                    params.append(float(filter_dict['min_found_pct']))
            
            query += " ORDER BY username ASC"
            
            cur.execute(query, params)
            usernames = [row[0] for row in cur.fetchall()]
            return usernames
    except Exception as e:
        logger.exception(f"Errore esportazione usernames")
        return []


def add_scan_alert(
    scan_id: int,
    alert_type: str,
    alert_msg: str,
    severity: str = "LOW",
    status: str = "OPEN",
    path: str = DB_PATH,
) -> bool:
    """Aggiunge un alert associato a uno scan."""
    try:
        with sqlite3.connect(path) as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO scan_alerts (scan_id, alert_type, alert_msg, severity, status, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (scan_id, alert_type, alert_msg, severity, status, datetime.now(timezone.utc).isoformat())
            )
            conn.commit()
            logger.info(f"Alert aggiunto a scan {scan_id}: {alert_type}")
            return True
    except Exception as e:
        logger.exception(f"Errore aggiunta alert per scan {scan_id}")
        return False


def get_scan_alerts(scan_id: int, path: str = DB_PATH) -> List[Dict]:
    """Recupera tutti gli alert di uno scan."""
    try:
        with sqlite3.connect(path) as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT id, alert_type, alert_msg, severity, status, created_at FROM scan_alerts WHERE scan_id = ? ORDER BY created_at DESC",
                (scan_id,)
            )
            alerts = [
                {"id": r[0], "type": r[1], "message": r[2], "severity": r[3], "status": r[4], "created_at": r[5]}
                for r in cur.fetchall()
            ]
            return alerts
    except Exception as e:
        logger.exception(f"Errore recupero alert per scan {scan_id}")
        return []


def get_all_scan_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 200,
    path: str = DB_PATH,
) -> List[Dict]:
    """Recupera lo storico alert con join sulla tabella scans."""
    try:
        with sqlite3.connect(path) as conn:
            cur = conn.cursor()
            query = (
                "SELECT a.id, a.scan_id, s.username, a.alert_type, a.alert_msg, a.severity, a.status, a.created_at "
                "FROM scan_alerts a JOIN scans s ON s.id = a.scan_id WHERE 1=1"
            )
            params: List[Any] = []

            if status:
                query += " AND a.status = ?"
                params.append(status)
            if severity:
                query += " AND a.severity = ?"
                params.append(severity)

            query += " ORDER BY a.created_at DESC LIMIT ?"
            params.append(limit)
            cur.execute(query, params)

            return [
                {
                    "id": row[0],
                    "scan_id": row[1],
                    "username": row[2],
                    "type": row[3],
                    "message": row[4],
                    "severity": row[5],
                    "status": row[6],
                    "created_at": row[7],
                }
                for row in cur.fetchall()
            ]
    except Exception:
        logger.exception("Errore recupero storico alert")
        return []


def update_scan_alert_status(alert_id: int, status: str, path: str = DB_PATH) -> bool:
    """Aggiorna lo stato di un alert esistente."""
    try:
        with sqlite3.connect(path) as conn:
            cur = conn.cursor()
            cur.execute("UPDATE scan_alerts SET status = ? WHERE id = ?", (status, alert_id))
            conn.commit()
            return cur.rowcount > 0
    except Exception:
        logger.exception(f"Errore aggiornamento stato alert {alert_id}")
        return False


if __name__ == "__main__":
    init_db()
    print("Database initialized at", DB_PATH)