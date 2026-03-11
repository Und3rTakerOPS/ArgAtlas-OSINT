# app_ui.py
"""
OSINT Suite Pro - Intelligence Center (Dashboard + Quick Scan + Live Monitor)
Versione riparata: blocchi indentati correttamente e struttura stabile.
"""

import os
import json
import math
import hashlib
from datetime import datetime
from typing import List, Dict

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from engine_core import run_scan_for_input, run_batch_scan_from_csv
from datastore import init_db, save_scan, load_recent
from exporters import generate_pdf_report, generate_excel
from config import REPORTS_PATH

# ---------------------------
# Init
# ---------------------------
st.set_page_config(page_title="OSINT Suite Pro - Intelligence Center", layout="wide")
init_db()

# ---------------------------
# Capitals dataset (reference layer)
# ---------------------------
CAPITALS = [
    ("Italy", "Rome", 41.9028, 12.4964),
    ("France", "Paris", 48.8566, 2.3522),
    ("USA", "Washington D.C.", 38.9072, -77.0369),
    ("Canada", "Ottawa", 45.4215, -75.6972),
    ("Germany", "Berlin", 52.52, 13.4050),
    ("Spain", "Madrid", 40.4168, -3.7038),
    ("United Kingdom", "London", 51.5074, -0.1278),
    ("Japan", "Tokyo", 35.6895, 139.6917),
    ("Brazil", "Brasília", -15.8267, -47.9218),
    ("Australia", "Canberra", -35.2809, 149.1300),
    ("India", "New Delhi", 28.6139, 77.2090),
    ("China", "Beijing", 39.9042, 116.4074),
    ("Russia", "Moscow", 55.7558, 37.6173),
    ("Mexico", "Mexico City", 19.4326, -99.1332),
    ("Argentina", "Buenos Aires", -34.6037, -58.3816),
    ("Turkey", "Ankara", 39.9208, 32.8541),
    ("Egypt", "Cairo", 30.0444, 31.2357),
    ("South Africa", "Pretoria", -25.7479, 28.2293),
]
cap_df = pd.DataFrame(CAPITALS, columns=["country", "capital", "lat", "lon"])

# ---------------------------
# Utils locali
# ---------------------------
def deterministic_capital_for_username(username: str):
    """Capitale deterministica (hash) per username — fallback utile."""
    if not username:
        return {"city": None, "country": None, "lat": None, "lon": None}
    idx = int(hashlib.sha256(username.encode("utf-8")).hexdigest(), 16) % len(cap_df)
    r = cap_df.iloc[idx]
    return {"city": r["capital"], "country": r["country"], "lat": float(r["lat"]), "lon": float(r["lon"])}

def extract_geo_from_result(r: dict):
    """Usa result['geo'] se presente, altrimenti fallback su capitale deterministica."""
    if not isinstance(r, dict):
        return None
    geo = r.get("geo") or {}
    lat = geo.get("lat")
    lon = geo.get("lon")
    if lat is not None and lon is not None:
        return {"city": geo.get("city"), "country": geo.get("country"), "lat": float(lat), "lon": float(lon)}
    # fallback semplice
    return deterministic_capital_for_username(str(r.get("username", "")))

def compute_profile_found_ratio(result: dict) -> float:
    """Percentuale (0..100) di profili 'exists' tra le piattaforme scansionate."""
    ps = result.get("profile_status", {}) or {}
    if not ps:
        return 0.0
    total = len(ps)
    found = sum(1 for v in ps.values() if v.get("exists"))
    return round(found / total * 100.0, 1)

# ---------------------------
# Sidebar: theme + navigation
# ---------------------------
if "theme" not in st.session_state:
    st.session_state.theme = "dark"

theme_choice = st.sidebar.selectbox("Tema", ["Dark", "Light"], index=0 if st.session_state.theme == "dark" else 1)
st.session_state.theme = "dark" if theme_choice == "Dark" else "light"

st.sidebar.title("OSINT Suite Pro")
menu = st.sidebar.radio("Sezione", ["Dashboard", "Single Scan", "Batch CSV", "Reports"])

# Theme CSS minimal
if st.session_state.theme == "dark":
    st.markdown("""
    <style>
    body {background-color:#0E1117;color:#FAFAFA;}
    .stButton>button {background-color:#0B3948;color:#fff;}
    .stMetricValue {color:#00ADB5 !important;}
    </style>
    """, unsafe_allow_html=True)
else:
    st.markdown("""
    <style>
    body {background-color:#FFFFFF;color:#0b1220;}
    .stButton>button {background-color:#E6EEF3;color:#0b1220;}
    </style>
    """, unsafe_allow_html=True)

# ---------------------------
# Dashboard: Centro di Controllo OSINT
# ---------------------------
if menu == "Dashboard":
    import time

    st.title("Intelligence Center — Dashboard")
    st.write("Centro di controllo: Quick Scan, attività live, statistiche e mappa.")

    # -------------------------
    # 🌍 Mappa globale (in alto)
    # -------------------------
    st.subheader("🌍 Mappa globale OSINT – capitali e scansioni recenti")

    scans = load_recent(300)
    if scans:
        df = pd.DataFrame(scans)
        df["queried_at"] = pd.to_datetime(df["queried_at"], errors="coerce")

        points = []
        for _, row in df.iterrows():
            r = row.get("result", {})
            geo = extract_geo_from_result(r) if isinstance(r, dict) else None
            if not geo or geo.get("lat") is None:
                geo = deterministic_capital_for_username(str(row.get("username", "")))
            found_pct = compute_profile_found_ratio(r if isinstance(r, dict) else {})
            points.append({
                "username": row.get("username"),
                "lat": geo.get("lat"),
                "lon": geo.get("lon"),
                "city": geo.get("city"),
                "country": geo.get("country"),
                "found_pct": found_pct
            })

        points_df = pd.DataFrame(points).dropna(subset=["lat", "lon"])
        cap_layer = cap_df.rename(columns={"capital": "city"})
        map_style = "carto-darkmatter" if st.session_state.theme == "dark" else "carto-positron"

        fig_map = go.Figure()

        # Livello capitali
        fig_map.add_trace(go.Scattermapbox(
            lat=cap_layer["lat"],
            lon=cap_layer["lon"],
            text=cap_layer["city"] + " (" + cap_layer["country"] + ")",
            mode="markers",
            marker=go.scattermapbox.Marker(size=6, color="lightgray"),
            hoverinfo="text",
            name="Capitali"
        ))

        # Livello punti OSINT
        if not points_df.empty:
            sizes = points_df["found_pct"].fillna(0).astype(float) + 6
            fig_map.add_trace(go.Scattermapbox(
                lat=points_df["lat"],
                lon=points_df["lon"],
                text=points_df.apply(
                    lambda r: f"{r['username']} — {r.get('city','')} ({r.get('country','')}) — {r['found_pct']}%",
                    axis=1
                ),
                mode="markers",
                marker=go.scattermapbox.Marker(size=sizes, color="cyan", opacity=0.8),
                hoverinfo="text",
                name="OSINT Points"
            ))

        fig_map.update_layout(
            mapbox_style=map_style,
            mapbox_zoom=1.1,
            mapbox_center={"lat": 20, "lon": 0},
            margin={"l": 0, "r": 0, "t": 0, "b": 0},
            height=500
        )

        st.plotly_chart(fig_map, use_container_width=True)
    else:
        st.info("Nessuna scansione disponibile per la mappa globale.")

    # -------------------------
    # 🔍 Quick Single Scan nella Dashboard
    # -------------------------
    with st.expander("⚡ Esegui una nuova scansione OSINT", expanded=False):
        st.markdown("Avvia una scansione senza uscire dalla dashboard.")
        col_in1, col_in2, col_in3 = st.columns([3, 1, 1])
        with col_in1:
            quick_user = st.text_input("Username o email da analizzare:", key="dash_quick_user")
        with col_in2:
            do_preview = st.checkbox("Preview", value=True, key="dash_preview")
        with col_in3:
            do_github = st.checkbox("GitHub", value=True, key="dash_gh")
        do_status = st.checkbox("Controllo stato profili", value=True, key="dash_status")
        max_profiles = st.slider("Max profili simultanei", 1, 30, 8, key="dash_maxprof")

        if st.button("🚀 Avvia Scansione Rapida", key="dash_run"):
            if not quick_user or not quick_user.strip():
                st.error("Inserisci uno username valido.")
            else:
                with st.spinner("Esecuzione scansione in corso..."):
                    result = run_scan_for_input(
                        quick_user.strip(),
                        do_status=do_status,
                        do_preview=do_preview,
                        do_github=do_github,
                        max_profiles=max_profiles
                    )
                    save_scan(result)
                    st.success(f"Scansione completata per {quick_user} ✅")

                    # Profilazione sintetica
                    try:
                        from engine_core import build_osint_profile_summary
                        profile_summary = build_osint_profile_summary(result)
                        st.subheader("🧠 Profilazione automatica")
                        st.write(f"**Attività:** {profile_summary['activity_level']}")
                        st.write(f"**Categorie:** {', '.join(profile_summary['categories']) or 'Nessuna'}")
                        st.info(profile_summary["summary"])
                    except Exception:
                        pass

                    # Tabella risultati profili
                    profile_status = result.get("profile_status", {})
                    if profile_status:
                        st.subheader("Risultati trovati")
                        df_profiles = pd.DataFrame([
                            {
                                "Piattaforma": p,
                                "URL": d.get("url", ""),
                                "Profilo trovato": "✅" if d.get("exists") else "❌"
                            }
                            for p, d in profile_status.items()
                        ])
                        st.dataframe(df_profiles, use_container_width=True)
                    else:
                        st.warning("Nessun profilo rilevato.")

                    # Export
                    try:
                        pdf = generate_pdf_report(result)
                        xlsx = generate_excel(result)
                        with open(pdf, "rb") as f:
                            st.download_button("📄 Scarica PDF", f, file_name=os.path.basename(pdf))
                        with open(xlsx, "rb") as f:
                            st.download_button("📊 Scarica Excel", f, file_name=os.path.basename(xlsx))
                    except Exception as e:
                        st.warning(f"Export non riuscito: {e}")

    # -------------------------
    # 🔄 Auto Refresh + Live Activity Monitor
    # -------------------------
    refresh_col1, refresh_col2 = st.columns([1, 4])
    with refresh_col1:
        auto_refresh = st.toggle("🔁 Auto-refresh Dashboard", value=False)
    with refresh_col2:
        refresh_interval = st.slider("Intervallo aggiornamento (sec)", 5, 60, 15)

    if auto_refresh:
        st.markdown(f"<i>La dashboard si aggiorna automaticamente ogni {refresh_interval} secondi...</i>", unsafe_allow_html=True)
        import time
        time.sleep(refresh_interval)
        st.rerun()

    st.markdown("---")
    st.markdown("### 📡 Live Activity Monitor")
    recent_scans = load_recent(10)
    if recent_scans:
        df_recent = pd.DataFrame(recent_scans)[["username", "queried_at"]]
        df_recent["queried_at"] = pd.to_datetime(df_recent["queried_at"]).dt.strftime("%d %b %Y %H:%M:%S")
        st.dataframe(df_recent.rename(columns={
            "username": "Utente",
            "queried_at": "Data/Ora Scansione"
        }), use_container_width=True, height=250)

        df_recent_sorted = df_recent.sort_values("queried_at")
        fig_recent = px.line(
            df_recent_sorted,
            x="queried_at",
            y=df_recent_sorted.index,
            markers=True,
            title="Attività Scansioni Live",
            color_discrete_sequence=["#00ADB5"]
        )
        fig_recent.update_layout(
            template="plotly_dark" if st.session_state.theme == "dark" else "plotly_white",
            showlegend=False,
            xaxis_title="Tempo",
            yaxis_title="Index",
            height=300
        )
        st.plotly_chart(fig_recent, use_container_width=True)
    else:
        st.info("Nessuna scansione recente trovata.")

    # -------------------------
    # Intelligence Summary + Filtri + Timeline + Tabella
    # -------------------------
    scans = load_recent(500)
    if not scans:
        st.info("Nessuna scansione ancora registrata.")
    else:
        df = pd.DataFrame(scans)
        df["queried_at"] = pd.to_datetime(df["queried_at"], errors="coerce")

        # Metrics
        total_scans = len(df)
        unique_users = df["username"].nunique()
        df["found_pct"] = df["result"].apply(lambda r: compute_profile_found_ratio(r if isinstance(r, dict) else {}))
        avg_found_pct = round(df["found_pct"].mean(), 1)

        platform_counts = {}
        for r in df["result"]:
            if not isinstance(r, dict):
                continue
            for platform, s in (r.get("profile_status") or {}).items():
                if s.get("exists"):
                    platform_counts[platform] = platform_counts.get(platform, 0) + 1
        platform_counts_series = pd.Series(platform_counts).sort_values(ascending=False)

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Totale scansioni", total_scans)
        col2.metric("Utenti unici", unique_users)
        col3.metric("Media % profili trovati", f"{avg_found_pct}%")
        col4.metric("Top piattaforma", platform_counts_series.index[0] if not platform_counts_series.empty else "N/A")

        st.markdown("#### Fonti più attive")
        st.bar_chart(platform_counts_series.head(10))

        st.divider()

        # Filtri
        st.markdown("#### Filtri")
        c1, c2 = st.columns([2, 1])
        with c1:
            search = st.text_input("Cerca username (parziale o completo)", key="dash_search")
        with c2:
            min_date = df["queried_at"].min().date()
            max_date = df["queried_at"].max().date()
            daterange = st.date_input("Intervallo date", value=(min_date, max_date))

        mask = (df["queried_at"].dt.date >= daterange[0]) & (df["queried_at"].dt.date <= daterange[1])
        if search:
            mask &= df["username"].str.contains(search, case=False, na=False)
        df_filtered = df[mask]

        st.info(f"Risultati nel filtro: {len(df_filtered)} scansioni")

        # Timeline
        df_timeline = df_filtered.groupby(df_filtered["queried_at"].dt.date).size().reset_index(name="count")
        fig_timeline = px.line(df_timeline, x="queried_at", y="count", title="Scansioni giornaliere", markers=True)
        fig_timeline.update_layout(template="plotly_dark" if st.session_state.theme == "dark" else "plotly_white")
        st.plotly_chart(fig_timeline, use_container_width=True)

        # Tabella
        st.subheader("Elenco dettagliato scansioni")
        st.dataframe(
            df_filtered[["id", "username", "queried_at"]].sort_values("queried_at", ascending=False),
            use_container_width=True,
            height=300
        )

# ---------------------------
# Single Scan (pagina classica)
# ---------------------------
elif menu == "Single Scan":
    st.title("Single Scan")
    user_input = st.text_input("Username o email:")
    do_preview = st.checkbox("Scraping preview", value=True)
    do_status = st.checkbox("Check profili (HTTP)", value=True)
    do_github = st.checkbox("GitHub API", value=True)
    max_profiles = st.number_input("Max concurrent checks", 1, 50, 8)

    if st.button("Run Scan"):
        if not user_input or not user_input.strip():
            st.error("Inserisci username o email valida.")
        else:
            with st.spinner("Eseguendo scan..."):
                result = run_scan_for_input(
                    user_input.strip(),
                    do_status=do_status,
                    do_preview=do_preview,
                    do_github=do_github,
                    max_profiles=max_profiles
                )
                save_scan(result)
                st.success("Scansione completata ✅")

                # Profilatore automatico
                try:
                    from engine_core import build_osint_profile_summary
                    profile_summary = build_osint_profile_summary(result)
                    st.subheader("🧠 Profilazione automatica")
                    st.write(f"**Livello attività:** {profile_summary['activity_level']}")
                    st.write(f"**Piattaforme attive:** {', '.join(profile_summary['active_platforms']) or 'Nessuna'}")
                    st.write(f"**Categorie rilevate:** {', '.join(profile_summary['categories']) or 'Nessuna'}")
                    st.info(profile_summary["summary"])
                except Exception:
                    pass

                # TABELLA profili
                profile_status = result.get("profile_status", {})
                if profile_status:
                    st.subheader("Risultati dei profili trovati")
                    df_profiles = pd.DataFrame([
                        {
                            "Piattaforma": platform,
                            "URL": data.get("url", ""),
                            "Stato": data.get("status", ""),
                            "Profilo trovato": "✅" if data.get("exists") else "❌"
                        }
                        for platform, data in profile_status.items()
                    ])
                    st.dataframe(df_profiles, use_container_width=True)
                else:
                    st.warning("Nessun profilo rilevato o sezione 'profile_status' vuota.")

                # GitHub info
                github_info = result.get("github_api")
                if github_info:
                    st.subheader("Dettagli GitHub")
                    df_github = pd.DataFrame([github_info])
                    st.table(df_github)

                # Meta preview
                scraping_preview = result.get("scraping_preview", {})
                if scraping_preview:
                    st.subheader("Informazioni di preview (meta/og)")
                    preview_rows = []
                    for site, content in scraping_preview.items():
                        meta = content.get("meta_preview", {})
                        preview_rows.append({
                            "Sito": site,
                            "Titolo": meta.get("title"),
                            "Descrizione": meta.get("description"),
                            "Dominio": meta.get("base")
                        })
                    st.dataframe(pd.DataFrame(preview_rows), use_container_width=True)

                # Varianti
                variants = result.get("variants", [])
                if variants:
                    st.subheader("Varianti di username generate")
                    st.write(", ".join(variants))

                # Export
                try:
                    pdf = generate_pdf_report(result)
                    xlsx = generate_excel(result)
                    with open(pdf, "rb") as f:
                        st.download_button("📄 Download PDF", f, file_name=os.path.basename(pdf))
                    with open(xlsx, "rb") as f:
                        st.download_button("📊 Download Excel", f, file_name=os.path.basename(xlsx))
                except Exception as e:
                    st.warning(f"Export non riuscito: {e}")

# ---------------------------
# Batch CSV
# ---------------------------
elif menu == "Batch CSV":
    st.title("Batch Scan (CSV)")
    st.write("Carica un CSV con una username/email per riga (prima colonna).")
    uploaded = st.file_uploader("Upload CSV", type=["csv"])
    if uploaded:
        tmp_path = "batch_list.csv"
        with open(tmp_path, "wb") as f:
            f.write(uploaded.getbuffer())
        if st.button("Start Batch Scan"):
            with st.spinner("Esecuzione batch..."):
                results = run_batch_scan_from_csv(tmp_path)
                for r in results:
                    save_scan(r)
                st.success(f"Batch completato: {len(results)} scansioni.")
                st.dataframe(pd.DataFrame(results)[["username", "queried_at"]], use_container_width=True)

# ---------------------------
# Reports
# ---------------------------
elif menu == "Reports":
    st.title("Reports")
    scans = load_recent(200)
    if scans:
        df = pd.DataFrame(scans)
        sel = st.selectbox("Seleziona username per dettaglio:", sorted(df["username"].unique()))
        match = next((r for r in scans if r["username"] == sel), None)
        if match:
            st.json(match["result"])
            try:
                pdf = generate_pdf_report(match["result"])
                xlsx = generate_excel(match["result"])
                with open(pdf, "rb") as f:
                    st.download_button("Download PDF", f, file_name=os.path.basename(pdf))
                with open(xlsx, "rb") as f:
                    st.download_button("Download Excel", f, file_name=os.path.basename(xlsx))
            except Exception as e:
                st.warning(f"Export non riuscito: {e}")
    else:
        st.info("Nessun report disponibile.")
