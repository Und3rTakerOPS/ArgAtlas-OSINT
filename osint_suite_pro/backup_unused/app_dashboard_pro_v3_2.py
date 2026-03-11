# app_dashboard_pro_v3_3.py — OSINT Intelligence Dashboard v3.3
# Dark theme | Smart Cache | Combined Filters | Map Zoom/Drag | Heatmap/Clustering
# Quick Scan + Full Single Scan (statici in Dashboard) | Entity Graph | Reports/Batch | Snapshot HTML
# Navbar sticky auto-hide (sparisce in scroll-down, riappare in scroll-up)

import os
import io
import json
import time
import hashlib
from datetime import datetime
from typing import Dict, List, Tuple

import networkx as nx
import streamlit as st
import streamlit.components.v1 as components
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import plotly.io as pio

from engine_core import run_scan_for_input, run_batch_scan_from_csv, build_osint_profile_summary
from datastore import init_db, save_scan, load_recent
from exporters import generate_pdf_report, generate_excel
from config import REPORTS_PATH

# =============================================================================
# CONFIG
# =============================================================================
ACCENT = "#007BFF"
PAGE_TITLE = "OSINT Intelligence Dashboard v3.3"
st.set_page_config(page_title=PAGE_TITLE, page_icon="🛰️", layout="wide")
init_db()

# seed session
st.session_state.setdefault("data_nonce", 0)
st.session_state.setdefault("filters", {})

# =============================================================================
# THEME + NAVBAR (auto-hide)
# =============================================================================
st.markdown(f"""
<style>
:root {{
  --bg:#0B0E13; --card:#121721; --muted:#9AA7B1; --border:#1E2732; --accent:{ACCENT};
}}
html, body {{
  background:linear-gradient(180deg, #0B0E13 0%, #0C1118 100%) !important;
  color:#E6EDF3; font-family:'Poppins',system-ui,Segoe UI,Roboto,Arial,sans-serif;
}}
.block-container {{ padding-top: 4.5rem; }} /* spazio per navbar sticky */

.nav-sticky {{
  position: fixed; top: 0; left: 0; right: 0; z-index: 9999;
  backdrop-filter: saturate(160%) blur(8px);
  background: rgba(18, 23, 33, .86);
  border-bottom: 1px solid var(--border);
  height: 56px; display:flex; align-items:center; justify-content:space-between;
  padding: 8px 18px;
  transition: transform .28s ease-in-out, box-shadow .28s ease-in-out, background .28s ease-in-out;
  box-shadow: 0 8px 24px rgba(0,0,0,.25);
}}
.nav-sticky.hide {{ transform: translateY(-100%); box-shadow:none; }}
.nav-left {{ display:flex; align-items:center; gap:12px; }}
.nav-title {{ color:var(--accent); font-weight:700; letter-spacing:.5px; }}
.nav-links span {{ color:#C7D1D9; margin-right:20px; cursor:pointer; font-size:.95rem; }}
.nav-links span:hover {{ color:var(--accent); }}

div.stButton > button {{
  background: var(--accent); color:white; border:none; border-radius:10px;
}}
div.stButton > button:hover {{ filter:brightness(1.08); }}

.metric-card {{
  background:linear-gradient(180deg, #121721 0%, #10151D 100%);
  border:1px solid var(--border); border-radius:14px; padding:14px; text-align:center;
}}
.metric-card h3 {{ margin:.2rem 0; color:#FFFFFF; font-weight:700; }}
.metric-card p {{ margin:0; color:var(--muted); }}

div[data-testid="stDataFrame"] {{
  background:#0f141a; border:1px solid var(--border); border-radius:12px;
}}
h1,h2,h3,h4,h5 {{ color:var(--accent); }}
hr {{ border:1px solid var(--border); }}
</style>

<!-- Navbar sticky markup -->
<div id="nav" class="nav-sticky">
  <div class="nav-left">
    <span style="font-size:1.2rem;">🛰️</span>
    <div class="nav-title">OSINT INTELLIGENCE DASHBOARD</div>
  </div>
  <div class="nav-links">
    <span>Dashboard</span><span>Reports</span><span>Network</span><span>Alerts</span>
  </div>
</div>
""", unsafe_allow_html=True)

# JS per auto-hide navbar (funziona dentro iframe root della pagina Streamlit)
components.html("""
<script>
(function(){
  let lastY = window.scrollY, nav = parent.document.getElementById('nav');
  function onScroll(){
    const y = window.scrollY;
    if(!nav) { nav = parent.document.getElementById('nav'); }
    if(!nav) return;
    if (y > lastY + 4 && y > 60) { nav.classList.add('hide'); }   // scroll down
    else if (y < lastY - 4) { nav.classList.remove('hide'); }     // scroll up
    lastY = y;
  }
  window.addEventListener('scroll', onScroll, { passive:true });
})();
</script>
""", height=0)

# =============================================================================
# DATA / HELPERS
# =============================================================================
CAPITALS: List[Tuple[str, str, float, float]] = [
    # lista compatta (puoi sostituire con 195 capitali ONU)
    ("Italy","Rome",41.9028,12.4964), ("France","Paris",48.8566,2.3522),
    ("USA","Washington D.C.",38.9072,-77.0369), ("Canada","Ottawa",45.4215,-75.6972),
    ("Germany","Berlin",52.52,13.405), ("Spain","Madrid",40.4168,-3.7038),
    ("United Kingdom","London",51.5074,-0.1278), ("Japan","Tokyo",35.6895,139.6917),
    ("Brazil","Brasília",-15.8267,-47.9218), ("Australia","Canberra",-35.2809,149.1300),
    ("India","New Delhi",28.6139,77.2090), ("China","Beijing",39.9042,116.4074),
    ("Russia","Moscow",55.7558,37.6173), ("Mexico","Mexico City",19.4326,-99.1332),
    ("Egypt","Cairo",30.0444,31.2357), ("South Africa","Pretoria",-25.7479,28.2293),
]
cap_df = pd.DataFrame(CAPITALS, columns=["country","capital","lat","lon"])

def parse_result(val):
    if isinstance(val, dict): return val
    if isinstance(val, str):
        try: return json.loads(val)
        except Exception: return {}
    return {}

def deterministic_capital_for_username(username: str) -> Dict[str, object]:
    if not username:
        return {"city": None, "country": None, "lat": None, "lon": None}
    idx = int(hashlib.sha256(username.encode("utf-8")).hexdigest(), 16) % len(cap_df)
    r = cap_df.iloc[idx]
    return {"city": r["capital"], "country": r["country"], "lat": float(r["lat"]), "lon": float(r["lon"])}

def extract_geo_from_result(result: dict) -> Dict[str, object]:
    if not isinstance(result, dict): return {"city": None, "country": None, "lat": None, "lon": None}
    geo = result.get("geo") or {}
    lat, lon = geo.get("lat"), geo.get("lon")
    if lat is not None and lon is not None:
        return {"city": geo.get("city"), "country": geo.get("country"), "lat": float(lat), "lon": float(lon)}
    return deterministic_capital_for_username(str(result.get("username","")))

def compute_profile_found_ratio(result: dict) -> float:
    ps = result.get("profile_status", {}) or {}
    if not ps: return 0.0
    total = len(ps); found = sum(1 for v in ps.values() if v.get("exists"))
    return round(found/total*100.0, 1)

def cluster_points_grid(df_points: pd.DataFrame, level: int = 2) -> pd.DataFrame:
    if df_points.empty: return df_points
    step_map = {0:1.0,1:0.5,2:0.25,3:0.1,4:0.05}
    step = step_map.get(level,0.25); dfc = df_points.copy()
    dfc["lat_bin"] = (dfc["lat"]/step).round().astype(int)
    dfc["lon_bin"] = (dfc["lon"]/step).round().astype(int)
    return (dfc.groupby(["lat_bin","lon_bin"])
            .agg(lat=("lat","mean"), lon=("lon","mean"),
                 count=("username","count"), avg_found_pct=("found_pct","mean"))
            .reset_index(drop=True))

def to_html_download(figs: List[go.Figure], titles: List[str], filename: str) -> str:
    sections = []
    for fig, title in zip(figs, titles):
        sections.append(f"<h2 style='font-family:Poppins,sans-serif;color:{ACCENT};margin:8px 0 4px'>{title}</h2>")
        sections.append(pio.to_html(fig, include_plotlyjs='cdn', full_html=False))
    html = f"""<!doctype html><html><head><meta charset="utf-8"/>
  <title>OSINT Dashboard Snapshot</title>
  <style>body{{background:#0B0E13;color:#E6EDF3;font-family:Poppins,sans-serif;padding:20px}}</style>
</head><body>
  <h1 style="color:{ACCENT};margin:0 0 10px">OSINT Intelligence Dashboard — Snapshot</h1>
  {''.join(sections)}
  <hr/><small>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</small>
</body></html>"""
    out = os.path.join(os.getcwd(), filename)
    with open(out, "w", encoding="utf-8") as f: f.write(html)
    return out

# =============================================================================
# SMART CACHE (Opzione A — si invalida quando cambia data_nonce)
# =============================================================================
@st.cache_data(show_spinner=False)
def _cached_load_processed(nonce: int):
    scans = load_recent(500)
    df = pd.DataFrame(scans) if scans else pd.DataFrame(columns=["id","username","queried_at","result"])
    if not df.empty:
        df["queried_at"] = pd.to_datetime(df["queried_at"], errors="coerce")
        df["result"] = df["result"].apply(parse_result)
        df["found_pct_calc"] = df["result"].apply(compute_profile_found_ratio)
    return df

def get_df() -> pd.DataFrame:
    return _cached_load_processed(st.session_state["data_nonce"])

# =============================================================================
# SIDEBAR MENU
# =============================================================================
st.sidebar.title("OSINT Suite Pro")
menu = st.sidebar.radio("Sezione", ["Dashboard", "Single Scan", "Batch CSV", "Reports"])

# =============================================================================
# DASHBOARD (static sections)
# =============================================================================
if menu == "Dashboard":
    df = get_df()
    if df.empty:
        st.info("Nessuna scansione disponibile.")
        st.stop()

    # ------------------ Filtri combinati
    st.markdown("### 🔍 Filtri combinati")
    f1, f2, f3, f4, f5 = st.columns([2,2,2,2,1])
    with f1:
        search = st.text_input("Username contiene…", value=st.session_state["filters"].get("search",""))
    all_platforms = sorted({k for r in df["result"] for k in (r.get("profile_status") or {}).keys()})
    with f2:
        platform_sel = st.multiselect("Piattaforme", options=all_platforms,
                                      default=st.session_state["filters"].get("platform_sel", []))
    with f3:
        min_d, max_d = df["queried_at"].min().date(), df["queried_at"].max().date()
        date_range = st.date_input("Intervallo date",
                                   value=st.session_state["filters"].get("date_range", (min_d, max_d)))
        if not (isinstance(date_range, tuple) and len(date_range)==2):
            date_range = (min_d, max_d)
    with f4:
        min_pct = st.slider("Min % profili trovati", 0, 100,
                            st.session_state["filters"].get("min_pct", 0))
        
    with f5:
        if st.button("Reset"):
            st.session_state["filters"] = {}; st.rerun()

    mask = pd.Series([True]*len(df), index=df.index)
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
        "search": search, "platform_sel": platform_sel,
        "date_range": date_range, "min_pct": min_pct
    }

    df_f = df[mask].copy()
    st.caption(f"📌 Risultati nel filtro: **{len(df_f)}** scansioni")

    # ------------------ Mappa Globale
    st.markdown("### 🌍 Mappa Globale — Capitali + Punti OSINT")
    o1, o2, o3, o4 = st.columns([1,1,2,1])
    with o1: use_heatmap = st.toggle("Heatmap", value=False)
    with o2: use_cluster = st.toggle("Clustering", value=False)
    with o3: cluster_level = st.slider("Livello clustering", 0, 4, 2)
    with o4: show_capitals = st.toggle("Mostra capitali", value=True)

    points = []
    for _, row in df_f.iterrows():
        user = str(row.get("username","")); res = row.get("result", {})
        geo = extract_geo_from_result(res); pct = compute_profile_found_ratio(res)
        points.append({"username":user, "lat":geo.get("lat"), "lon":geo.get("lon"),
                       "city":geo.get("city"), "country":geo.get("country"), "found_pct":pct})
    points_df = pd.DataFrame(points).dropna(subset=["lat","lon"])
    map_center = {"lat":20, "lon":0}

    if use_heatmap and not points_df.empty:
        fig_map = px.density_mapbox(points_df, lat="lat", lon="lon", z="found_pct",
                                    radius=20, center=map_center, zoom=1.1,
                                    color_continuous_scale="Blues")
        fig_map.update_layout(mapbox_style="carto-darkmatter",
                              margin=dict(l=0,r=0,t=0,b=0), height=500)
    else:
        fig_map = go.Figure()
        if show_capitals:
            cap = cap_df.copy()
            fig_map.add_trace(go.Scattermapbox(
                lat=cap["lat"], lon=cap["lon"],
                text=cap["capital"] + " (" + cap["country"] + ")",
                mode="markers",
                marker=go.scattermapbox.Marker(size=6, color="#6C7A89"),
                hoverinfo="text", name="Capitali"
            ))
        if not points_df.empty:
            if use_cluster:
                cl = cluster_points_grid(points_df, cluster_level)
                sizes = (cl["count"].astype(float)**0.6)*6+6
                hover = cl.apply(lambda r: f"Cluster ~{int(r['count'])} — avg {r['avg_found_pct']:.1f}%", axis=1)
                fig_map.add_trace(go.Scattermapbox(
                    lat=cl["lat"], lon=cl["lon"], text=hover,
                    mode="markers", marker=go.scattermapbox.Marker(size=sizes, color=ACCENT, opacity=0.85),
                    hoverinfo="text", name="Cluster"
                ))
            else:
                sizes = (points_df["found_pct"].fillna(0).astype(float)/10.0)+6
                hover = points_df.apply(lambda r: f"{r['username']} — {r.get('city','')} ({r.get('country','')}) — {r['found_pct']}%", axis=1)
                fig_map.add_trace(go.Scattermapbox(
                    lat=points_df["lat"], lon=points_df["lon"], text=hover,
                    mode="markers", marker=go.scattermapbox.Marker(size=sizes, color=ACCENT, opacity=0.85),
                    hoverinfo="text", name="OSINT Points"
                ))
        fig_map.update_layout(mapbox_style="carto-darkmatter", mapbox_zoom=1.1,
                              mapbox_center=map_center, dragmode="pan",
                              margin=dict(l=0,r=0,t=0,b=0), height=500)
    st.plotly_chart(fig_map, use_container_width=True,
                    config={"scrollZoom": True, "displayModeBar": True,
                            "modeBarButtonsToAdd": ["zoomInMapbox","zoomOutMapbox","resetViewMapbox"]})

    # ------------------ Statistiche dinamiche
    total = len(df_f); uniq = df_f["username"].nunique()
    avgp = round(df_f["found_pct_calc"].mean() if total else 0.0, 1)
    stdp = round(df_f["found_pct_calc"].std() if total>1 else 0.0, 1)
    m1, m2, m3, m4 = st.columns(4)
    m1.markdown(f"<div class='metric-card'><h3>{total}</h3><p>Scansioni filtrate</p></div>", unsafe_allow_html=True)
    m2.markdown(f"<div class='metric-card'><h3>{uniq}</h3><p>Utenti unici</p></div>", unsafe_allow_html=True)
    m3.markdown(f"<div class='metric-card'><h3>{avgp}%</h3><p>Media profili trovati</p></div>", unsafe_allow_html=True)
    m4.markdown(f"<div class='metric-card'><h3>{stdp}</h3><p>Deviazione standard</p></div>", unsafe_allow_html=True)

    # ------------------ Quick Scan (statico)
    st.markdown("### ⚡ Quick Scan")
    q1, q2, q3 = st.columns([3,1,1])
    with q1: quick_user = st.text_input("Username o email:", key="quick_user_v33")
    with q2: quick_preview = st.checkbox("Preview", value=True, key="quick_prev_v33")
    with q3: quick_github = st.checkbox("GitHub", value=True, key="quick_gh_v33")
    quick_status = st.checkbox("Check profili (HTTP)", value=True, key="quick_status_v33")
    quick_max = st.slider("Max profili simultanei", 1, 30, 8, key="quick_max_v33")
    if st.button("🚀 Avvia Quick Scan", key="quick_run_v33"):
        if not quick_user or not quick_user.strip():
            st.error("Inserisci uno username valido.")
        else:
            with st.spinner("Esecuzione scansione in corso..."):
                result = run_scan_for_input(quick_user.strip(),
                                            do_status=quick_status, do_preview=quick_preview,
                                            do_github=quick_github, max_profiles=quick_max)
                try:
                    save_scan(result); st.session_state["data_nonce"] += 1
                except Exception: pass
                st.success(f"Quick Scan completata per {quick_user} ✅")

    # ------------------ Single Scan completo (statico)
    st.markdown("### 🧪 Single Scan completo")
    d1, d2, d3 = st.columns([3,1,1])
    with d1: full_user = st.text_input("Username o email:", key="full_user_v33")
    with d2: full_preview = st.checkbox("Scraping preview", value=True, key="full_prev_v33")
    with d3: full_github = st.checkbox("GitHub API", value=True, key="full_gh_v33")
    full_status = st.checkbox("Check profili (HTTP)", value=True, key="full_status_v33")
    full_max = st.slider("Max concurrent checks", 1, 50, 8, key="full_max_v33")
    full_auto_report = st.checkbox("Auto-salva PDF/Excel", value=True, key="full_autorep_v33")

    if st.button("🚀 Avvia Scansione (completa)", key="full_run_v33"):
        if not full_user or not full_user.strip():
            st.error("Inserisci username o email valida.")
        else:
            with st.spinner("Eseguendo scan completa..."):
                result = run_scan_for_input(full_user.strip(),
                                            do_status=full_status, do_preview=full_preview,
                                            do_github=full_github, max_profiles=full_max)
                try:
                    save_scan(result); st.session_state["data_nonce"] += 1
                except Exception: pass
                st.success("Scansione completata ✅")

                # Profilazione
                try:
                    prof = build_osint_profile_summary(result)
                    st.subheader("🧠 Profilazione automatica")
                    st.write(f"**Attività:** {prof.get('activity_level','-')}")
                    st.write(f"**Piattaforme attive:** {', '.join(prof.get('active_platforms', [])) or 'Nessuna'}")
                    st.write(f"**Categorie:** {', '.join(prof.get('categories', [])) or 'Nessuna'}")
                    if prof.get("summary"): st.info(prof["summary"])
                except Exception: pass

                # Profili trovati
                ps = result.get("profile_status", {})
                if ps:
                    st.subheader("Risultati profili")
                    dfp = pd.DataFrame([{
                        "Piattaforma": p, "URL": d.get("url",""), "Stato": d.get("status",""),
                        "Profilo trovato": "✅" if d.get("exists") else "❌"
                    } for p,d in ps.items()])
                    st.dataframe(dfp, use_container_width=True)
                else:
                    st.warning("Nessun profilo rilevato.")

                # GitHub
                gh = result.get("github_api")
                if gh:
                    st.subheader("Dettagli GitHub"); st.table(pd.DataFrame([gh]))

                # Preview
                sp = result.get("scraping_preview", {})
                if sp:
                    st.subheader("Informazioni di preview (meta/og)")
                    rows = []
                    for site, content in sp.items():
                        meta = content.get("meta_preview", {})
                        rows.append({"Sito": site, "Titolo": meta.get("title"),
                                     "Descrizione": meta.get("description"), "Dominio": meta.get("base")})
                    st.dataframe(pd.DataFrame(rows), use_container_width=True)

                # Varianti
                if result.get("variants"):
                    st.subheader("Varianti di username")
                    st.write(", ".join(result["variants"]))

                # Export
                try:
                    pdf = generate_pdf_report(result); xlsx = generate_excel(result)
                    if full_auto_report: st.success("Report salvati (PDF/Excel).")
                    with open(pdf,"rb") as f:
                        st.download_button("📄 Download PDF", f, file_name=os.path.basename(pdf), key="pdf_full_v33")
                    with open(xlsx,"rb") as f:
                        st.download_button("📊 Download Excel", f, file_name=os.path.basename(xlsx), key="xlsx_full_v33")
                except Exception as e:
                    st.warning(f"Export non riuscito: {e}")

    # ------------------ Live monitor + snapshot
    st.markdown("---")
    l1, l2, l3 = st.columns([1,2,1])
    with l1: auto_refresh = st.toggle("🔁 Auto-refresh", value=False)
    with l2: refresh_interval = st.slider("Intervallo aggiornamento (sec)", 5, 60, 15)
    with l3: export_snap = st.button("📦 Esporta snapshot (HTML)")
    if auto_refresh:
        st.markdown(f"<i>Aggiornamento automatico ogni {refresh_interval}s…</i>", unsafe_allow_html=True)
        time.sleep(refresh_interval); st.rerun()

    st.markdown("### 📡 Live Activity Monitor")
    recent = load_recent(12); fig_recent = None
    if recent:
        dfr = pd.DataFrame(recent)[["username","queried_at"]]
        dfr["queried_at"] = pd.to_datetime(dfr["queried_at"]).dt.strftime("%d %b %Y %H:%M:%S")
        st.dataframe(dfr.rename(columns={"username":"Utente","queried_at":"Data/Ora"}), use_container_width=True, height=260)
        dfrs = dfr.sort_values("queried_at")
        fig_recent = px.line(dfrs, x="queried_at", y=dfrs.index, markers=True,
                             title="Attività Scansioni Live", color_discrete_sequence=[ACCENT])
        fig_recent.update_layout(template="plotly_dark", showlegend=False,
                                 xaxis_title="Tempo", yaxis_title="Index", height=280)
        st.plotly_chart(fig_recent, use_container_width=True)
    else:
        st.info("Nessuna scansione recente trovata.")

    # ------------------ Intelligence Summary
    st.markdown("---")
    st.markdown("### 📊 Intelligence Summary")
    tl = df_f.groupby(df_f["queried_at"].dt.date).size().reset_index(name="count") if not df_f.empty else pd.DataFrame(columns=["queried_at","count"])
    if not tl.empty:
        fig_tl = px.line(tl, x="queried_at", y="count", title="Scansioni giornaliere", markers=True)
        fig_tl.update_layout(template="plotly_dark")
        st.plotly_chart(fig_tl, use_container_width=True)

    plat = {}
    for r in df_f["result"]:
        for k,v in (r.get("profile_status") or {}).items():
            if v.get("exists"): plat[k] = plat.get(k,0)+1
    if plat:
        pf_df = pd.DataFrame(plat.items(), columns=["Piattaforma","Conteggio"])
        fig_pf = px.pie(pf_df, values="Conteggio", names="Piattaforma", hole=0.55,
                        color_discrete_sequence=px.colors.sequential.Blues)
        fig_pf.update_layout(title="Distribuzione piattaforme", template="plotly_dark")
        st.plotly_chart(fig_pf, use_container_width=True)
    else:
        st.info("Nessuna piattaforma attiva nel filtro.")

    st.subheader("Elenco dettagliato scansioni")
    st.dataframe(df_f[["id","username","queried_at"]].sort_values("queried_at", ascending=False),
                 use_container_width=True, height=300)

    # ------------------ Entity Graph
    st.markdown("---")
    st.subheader("🕸️ Entity Graph — Utenti ↔ Piattaforme")
    show_graph = st.toggle("Mostra Entity Graph", value=False)
    max_users = st.slider("Numero massimo utenti", 10, 200, 50)
    if show_graph:
        edges, seen = [], set()
        for _, row in df.iterrows():
            u = str(row.get("username",""))
            if u in seen: continue
            seen.add(u)
            ps = (row.get("result",{}).get("profile_status") or {})
            for p, v in ps.items():
                if v.get("exists"): edges.append((f"u:{u}", f"p:{p}"))
            if len(seen)>=max_users: break
        if edges:
            G = nx.Graph(); G.add_edges_from(edges)
            pos = nx.spring_layout(G, k=0.6, seed=42)
            nx_x, nx_y, txt, col, sz = [], [], [], [], []
            for node,(x,y) in pos.items():
                nx_x.append(x); nx_y.append(y)
                if node.startswith("u:"): col.append(ACCENT); sz.append(18); txt.append(node[2:])
                else: col.append("#7C8A96"); sz.append(14); txt.append(node[2:])
            ex, ey = [], []
            for s,d in G.edges(): x0,y0=pos[s]; x1,y1=pos[d]; ex += [x0,x1,None]; ey += [y0,y1,None]
            edge = go.Scatter(x=ex, y=ey, line=dict(width=1, color="#4a5562"), mode="lines")
            node = go.Scatter(x=nx_x, y=nx_y, mode="markers+text", text=txt,
                              textposition="bottom center", marker=dict(size=sz, color=col))
            fig_g = go.Figure(data=[edge,node])
            fig_g.update_layout(template="plotly_dark", showlegend=False,
                                margin=dict(l=10,r=10,t=10,b=10), height=520)
            st.plotly_chart(fig_g, use_container_width=True)
        else:
            st.info("Nessuna relazione utente–piattaforma trovata.")

    # ------------------ Export snapshot
    export = export_snap
    if export:
        figs, titles = [fig_map], ["Mappa Globale"]
        if recent: figs.append(fig_recent); titles.append("Live Activity")
        if not tl.empty: figs.append(fig_tl); titles.append("Timeline scansioni")
        if plat: figs.append(fig_pf); titles.append("Piattaforme (filtro)")
        snap = to_html_download(figs, titles, filename=f"dashboard_snapshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        with open(snap, "r", encoding="utf-8") as f:
            st.download_button("⬇️ Scarica snapshot (HTML)", f, file_name=os.path.basename(snap), mime="text/html")

# =============================================================================
# PAGINA: Single Scan classico
# =============================================================================
elif menu == "Single Scan":
    st.title("Single Scan")
    user_input = st.text_input("Username o email:")
    do_preview = st.checkbox("Scraping preview", value=True)
    do_status = st.checkbox("Check profili (HTTP)", value=True)
    do_github = st.checkbox("GitHub API", value=True)
    max_profiles = st.number_input("Max concurrent checks", 1, 50, 8)
    auto_report = st.checkbox("Auto-salva PDF/Excel al termine", value=True)

    if st.button("Run Scan"):
        if not user_input or not user_input.strip():
            st.error("Inserisci username o email valida.")
        else:
            with st.spinner("Eseguendo scan..."):
                result = run_scan_for_input(user_input.strip(),
                                            do_status=do_status, do_preview=do_preview,
                                            do_github=do_github, max_profiles=max_profiles)
                try:
                    save_scan(result); st.session_state["data_nonce"] += 1
                except Exception: pass
                st.success("Scansione completata ✅")

                try:
                    profile_summary = build_osint_profile_summary(result)
                    st.subheader("🧠 Profilazione automatica")
                    st.write(f"**Livello attività:** {profile_summary.get('activity_level','-')}")
                    st.write(f"**Piattaforme attive:** {', '.join(profile_summary.get('active_platforms', [])) or 'Nessuna'}")
                    st.write(f"**Categorie:** {', '.join(profile_summary.get('categories', [])) or 'Nessuna'}")
                    if profile_summary.get('summary'): st.info(profile_summary['summary'])
                except Exception: pass

                ps = result.get("profile_status", {})
                if ps:
                    st.subheader("Risultati dei profili trovati")
                    df_profiles = pd.DataFrame([
                        {"Piattaforma": p, "URL": d.get("url",""), "Stato": d.get("status",""),
                         "Profilo trovato": "✅" if d.get("exists") else "❌"}
                        for p, d in ps.items()
                    ])
                    st.dataframe(df_profiles, use_container_width=True)
                else:
                    st.warning("Nessun profilo rilevato.")

                gh = result.get("github_api")
                if gh:
                    st.subheader("Dettagli GitHub"); st.table(pd.DataFrame([gh]))

                sp = result.get("scraping_preview", {})
                if sp:
                    st.subheader("Informazioni di preview (meta/og)")
                    rows = []
                    for site, content in sp.items():
                        meta = content.get("meta_preview", {})
                        rows.append({"Sito": site, "Titolo": meta.get("title"),
                                     "Descrizione": meta.get("description"), "Dominio": meta.get("base")})
                    st.dataframe(pd.DataFrame(rows), use_container_width=True)

                variants = result.get("variants", [])
                if variants:
                    st.subheader("Varianti di username generate")
                    st.write(", ".join(variants))

                try:
                    pdf = generate_pdf_report(result); xlsx = generate_excel(result)
                    if auto_report: st.success("Report salvati (PDF/Excel).")
                    with open(pdf,"rb") as f:
                        st.download_button("📄 Download PDF", f, file_name=os.path.basename(pdf))
                    with open(xlsx,"rb") as f:
                        st.download_button("📊 Download Excel", f, file_name=os.path.basename(xlsx))
                except Exception as e:
                    st.warning(f"Export non riuscito: {e}")

# =============================================================================
# PAGINA: Batch CSV
# =============================================================================
elif menu == "Batch CSV":
    st.title("Batch Scan (CSV)")
    st.write("Carica un CSV con una username/email per riga (prima colonna).")
    uploaded = st.file_uploader("Upload CSV", type=["csv"])
    do_preview = st.checkbox("Scraping preview", value=True)
    do_status = st.checkbox("Check profili (HTTP)", value=True)
    do_github = st.checkbox("GitHub API", value=True)
    max_profiles = st.number_input("Max concurrent checks", 1, 50, 8)

    if uploaded:
        tmp = "batch_list.csv"
        with open(tmp, "wb") as f: f.write(uploaded.getbuffer())
        if st.button("Start Batch Scan"):
            with st.spinner("Esecuzione batch..."):
                results = run_batch_scan_from_csv(tmp, do_status=do_status,
                                                  do_preview=do_preview, do_github=do_github,
                                                  max_profiles=max_profiles)
                for r in results:
                    try: save_scan(r)
                    except Exception: pass
                st.session_state["data_nonce"] += 1
                st.success(f"Batch completato: {len(results)} scansioni.")
                st.dataframe(pd.DataFrame(results)[["username","queried_at"]], use_container_width=True)

# =============================================================================
# PAGINA: Reports
# =============================================================================
elif menu == "Reports":
    st.title("Reports")
    scans = load_recent(200)
    if scans:
        df = pd.DataFrame(scans)
        users = sorted(df["username"].unique())
        sel = st.selectbox("Seleziona username:", users) if users else None
        rec = next((r for r in scans if r["username"] == sel), None) if sel else None
        if rec:
            res = parse_result(rec.get("result")); st.json(res)
            try:
                pdf = generate_pdf_report(res); xlsx = generate_excel(res)
                with open(pdf,"rb") as f: st.download_button("Download PDF", f, file_name=os.path.basename(pdf))
                with open(xlsx,"rb") as f: st.download_button("Download Excel", f, file_name=os.path.basename(xlsx))
            except Exception as e:
                st.warning(f"Export non riuscito: {e}")
    else:
        st.info("Nessun report disponibile.")

# =============================================================================
# FOOTER
# =============================================================================
st.markdown("<hr>", unsafe_allow_html=True)
st.caption("© 2025 OSINT Suite Pro — Intelligence Dashboard v3.3")
