import os
import json
import csv
from fpdf import FPDF
from openpyxl import Workbook
from datetime import datetime
from config import REPORTS_PATH
import logging
import re

logger = logging.getLogger(__name__)


def _safe_filename_part(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "unknown")).strip("._")
    return cleaned or "unknown"


def _build_output_path(prefix: str, username: str, extension: str, output_dir: str = REPORTS_PATH) -> str:
    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{prefix}_{_safe_filename_part(username)}_{timestamp}.{extension}"
    return os.path.join(output_dir, filename)

# ---------------------------------------------------
# Genera report PDF della scansione
# ---------------------------------------------------
def generate_pdf_report(result):
    pdf = FPDF()
    pdf.add_page()
    font_path = os.path.join(os.path.dirname(__file__), "fonts", "NotoSans-Regular.ttf")
    pdf.add_font("NotoSans", "", font_path, uni=True)
    pdf.set_font("NotoSans", size=11)
    risk = result.get("risk_assessment", {}) or {}
    risk_score = risk.get("score", 0)
    risk_level = risk.get("level", "Low")
    pdf.multi_cell(0, 8, f"Risk Score: {risk_score}/100 | Risk Level: {risk_level}")
    pdf.ln(2)
    text = json.dumps(result, indent=2, ensure_ascii=False)
    pdf.multi_cell(0, 8, text)
    output_path = _build_output_path("osint_report", result.get("username", "scan"), "pdf")
    pdf.output(output_path)
    logger.info(f"PDF report generato: {output_path}")
    return output_path

# ---------------------------------------------------
# Genera file Excel della scansione
# ---------------------------------------------------
def generate_excel(result: dict, output_dir: str = REPORTS_PATH) -> str:
    wb = Workbook()
    ws = wb.active
    ws.title = "OSINT Scan Result"

    ws.append(["Chiave", "Valore"])

    risk = result.get("risk_assessment", {}) or {}
    ws.append(["risk_score", risk.get("score", 0)])
    ws.append(["risk_level", risk.get("level", "Low")])

    for key, val in result.items():
        try:
            ws.append([key, json.dumps(val, ensure_ascii=False)])
        except Exception:
            ws.append([key, str(val)])

    output_path = _build_output_path("osint_report", result.get("username", "unknown"), "xlsx", output_dir)
    wb.save(output_path)
    logger.info(f"Excel report generato: {output_path}")
    return output_path

# ---------------------------------------------------
# Genera file JSON della scansione (ripulito e strutturato)
# ---------------------------------------------------
def generate_json(result: dict, output_dir: str = REPORTS_PATH) -> str:
    """
    Esporta risultato scan come JSON formattato e leggibile.
    Utile per importazione in altri strumenti OSINT o analisi esterne.
    """
    output_path = _build_output_path("osint_report", result.get("username", "unknown"), "json", output_dir)
    
    # Struttura il JSON con indentazione per leggibilità
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    
    logger.info(f"JSON report generato: {output_path}")
    return output_path

# ---------------------------------------------------
# Genera CSV con i profili trovati
# ---------------------------------------------------
def generate_csv_profiles(result: dict, output_dir: str = REPORTS_PATH) -> str:
    """
    Esporta tabella CSV con piattaforma, URL e status per ogni profilo trovato.
    Formato: Platform | URL | Status | Found
    """
    output_path = _build_output_path("profiles", result.get("username", "unknown"), "csv", output_dir)
    
    profile_status = result.get("profile_status", {})
    social_profiles = result.get("social_profiles", {})
    
    with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Piattaforma", "URL", "Status", "Trovato"])
        
        for platform, url in social_profiles.items():
            status_info = profile_status.get(platform, {})
            status = status_info.get("status", "Unknown")
            exists = status_info.get("exists", False)
            
            writer.writerow([
                platform,
                url,
                status,
                "Sì" if exists else "No"
            ])
    
    logger.info(f"CSV profiles generato: {output_path}")
    return output_path

# ---------------------------------------------------
# Bulk Export in formato strutturato (JSON Lines)
# ---------------------------------------------------
def generate_jsonl_bulk(results: list, output_dir: str = REPORTS_PATH) -> str:
    """
    Esporta multiple scansioni in formato JSONL (JSON Lines).
    Una linea = uno scan. Utile per big data analysis e import in database.
    
    Args:
        results: Lista di dizionari risultati scan
        output_dir: Directory di output
    
    Returns:
        Path del file JSONL generato
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
    
    output_path = os.path.join(
        output_dir,
        f"bulk_scans_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
    )
    
    with open(output_path, "w", encoding="utf-8") as f:
        for result in results:
            f.write(json.dumps(result, ensure_ascii=False) + "\n")
    
    logger.info(f"JSONL bulk generato: {output_path} ({len(results)} record)")
    return output_path

# ---------------------------------------------------
# Export CSV bulk con summary per ogni username
# ---------------------------------------------------
def generate_csv_bulk_summary(results: list, output_dir: str = REPORTS_PATH) -> str:
    """
    Esporta CSV con sommario di tutte le scansioni.
    Colonne: Username | Data | % Profili Trovati | Piattaforme Attive | URL
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
    
    output_path = os.path.join(
        output_dir,
        f"bulk_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    )
    
    with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Username", "Data Scansione", "% Profili Trovati", "Risk Score", "Risk Level", "Piattaforme Attive", "Attività"])
        
        for result in results:
            username = result.get("username")
            queried_at = result.get("queried_at", "")
            profile_status = result.get("profile_status", {})
            
            found_count = sum(1 for v in profile_status.values() if v.get("exists"))
            total_count = len(profile_status)
            found_pct = (found_count / total_count * 100.0) if total_count > 0 else 0
            
            active_platforms = [p for p, v in profile_status.items() if v.get("exists")]
            risk = result.get("risk_assessment", {}) or {}
            risk_score = risk.get("score", 0)
            risk_level = risk.get("level", "Low")
            
            # Livello attività
            activity = "Basso"
            if found_count >= 6:
                activity = "Molto alto"
            elif found_count >= 3:
                activity = "Medio"
            
            writer.writerow([
                username,
                queried_at[:10] if queried_at else "",  # Estrai solo data
                f"{found_pct:.1f}%",
                risk_score,
                risk_level,
                ", ".join(active_platforms[:5]) + ("..." if len(active_platforms) > 5 else ""),
                activity
            ])
    
    logger.info(f"CSV bulk summary generato: {output_path}")
    return output_path