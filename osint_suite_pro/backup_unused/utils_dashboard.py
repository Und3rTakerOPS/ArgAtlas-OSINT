import re
import logging
from typing import Optional, Dict, Any

# Configurazione logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('osint_dashboard.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Validazione username sicura — permette emails, social handles, numeri di telefono, e simboli comuni
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9._\-@\s\+]{1,100}$')

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

    if not USERNAME_PATTERN.match(username):
        return False, "Input contiene caratteri non validi. Usa lettere, numeri, @, +, punti, trattini, underscore e spazi"

    # Controllachè non sia un numero di telefono troppo corto
    is_phone = username.startswith('+') or (username.isdigit() and len(username) >= 7)
    is_email = '@' in username
    is_username = not is_phone and not is_email
    
    # Controlli aggiuntivi per sicurezza
    if is_username and username.lower() in ['admin', 'root', 'system', 'null', 'undefined']:
        return False, "Username riservato non permesso"

    return True, ""

def sanitize_for_display(text: str, max_length: int = 100) -> str:
    """
    Sanitizza testo per display sicuro, limita lunghezza e previene XSS.
    """
    if not text:
        return ""
    text = str(text).strip()
    if len(text) > max_length:
        text = text[:max_length] + "..."
    import html
    return html.escape(text)

def validate_file_path(file_path: str) -> bool:
    """
    Valida che il path del file sia sicuro (previene directory traversal).
    """
    import os.path
    # Normalizza il path e controlla che non contenga .. o altri caratteri pericolosi
    normalized = os.path.normpath(file_path)
    if ".." in normalized or normalized.startswith("/"):
        return False
    return True

def setup_logging():
    """Configura logging per l'applicazione."""
    return logger

def _display_scan_results(result: Dict[str, Any], auto_report: bool = False, key_prefix: str = ""):
    """
    Funzione unificata per mostrare risultati di scansione.
    Elimina duplicazione di codice tra Quick Scan, Single Scan, Batch Scan.
    """
    import streamlit as st
    import pandas as pd
    import os

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

        # Dettagli GitHub
        gh = result.get("github_api")
        if gh:
            st.subheader("Dettagli GitHub")
            st.table(pd.DataFrame([gh]))

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
            pdf = generate_pdf_report(result)
            xlsx = generate_excel(result)
            if auto_report:
                st.success("Report salvati automaticamente (PDF/Excel).")
            else:
                with open(pdf,"rb") as f:
                    st.download_button("📄 Download PDF", f, file_name=os.path.basename(pdf), key=f"pdf_{key_prefix}")
                with open(xlsx,"rb") as f:
                    st.download_button("📊 Download Excel", f, file_name=os.path.basename(xlsx), key=f"xlsx_{key_prefix}")
        except Exception as e:
            logger.error(f"Errore export report per {result.get('username')}: {e}")
            st.warning(f"Export report non riuscito: {str(e)}")

    except Exception as e:
        logger.error(f"Errore generale display risultati: {e}")
        st.error("Errore nella visualizzazione dei risultati")