# app_dashboard_pro_v3_2.py — OSINT Intelligence Dashboard v3.2
# Dark theme | Smart Cache | Combined Filters | Map Zoom/Drag | Heatmap/Clustering
# Quick Scan + **Full Single Scan integrated in Dashboard** | Entity Graph | Reports/Batch | Snapshot HTML

import os
import io
import json
import time
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Tuple

import networkx as nx
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import plotly.io as pio

from engine_core import run_scan_for_input, run_batch_scan_from_csv, build_osint_profile_summary
from datastore import init_db, save_scan, load_recent
from exporters import generate_pdf_report, generate_excel
from config import REPORTS_PATH

# =============================================================================
# CONFIG BASE
# =============================================================================
ACCENT = "#007BFF"
PAGE_TITLE = "OSINT Intelligence Dashboard v3.2"

st.set_page_config(page_title=PAGE_TITLE, page_icon="🛰️", layout="wide")
init_db()

# Seed session state
if "data_nonce" not in st.session_state:
    st.session_state["data_nonce"] = 0
if "filters" not in st.session_state:
    st.session_state["filters"] = {}

# =============================================================================
# DARK THEME CSS
# =============================================================================
st.markdown(f"""
<style>
:root {{
  --bg:#0B0E13; --card:#121721; --muted:#9AA7B1; --border:#1E2732; --accent:{ACCENT};
}}
body {{
  background:linear-gradient(180deg, #0B0E13 0%, #0C1118 100%);
  color:#E6EDF3; font-family:'Poppins',system-ui,Segoe UI,Roboto,Arial,sans-serif;
}}
.block-container {{ padding-top: .6rem; }}
.navbar {{
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 14px; padding: 14px 18px; margin-bottom: 14px;
  display:flex; align-items:center; justify-content:space-between;
  box-shadow: 0 8px 24px rgba(0,0,0,.25);
}}
.nav-left {{ display:flex; align-items:center; gap:12px; }}
.nav-title {{ color:var(--accent); font-weight:700; letter-spacing:.5px; }}
.nav-links span {{ color:#C7D1D9; margin-right:20px; cursor:pointer; }}
.nav-links span:hover {{ color:var(--accent); }}
div.stButton > button {{
  background: var(--accent); color:white; border:none; border-radius:10px;
}}
div.stButton > button:hover {{ filter:brightness(1.1); }}
.metric-card {{
  background:linear-gradient(180deg, #121721 0%, #10151D 100%);
  border:1px solid var(--border); border-radius:14px; padding:14px;
  text-align:center;
}}
.metric-card h3 {{ margin:.2rem 0; color:#FFFFFF; font-weight:700; }}
.metric-card p {{ margin:0; color:var(--muted); }}
div[data-testid="stDataFrame"] {{
  background: #0f141a; border:1px solid var(--border); border-radius:12px;
}}
h1,h2,h3,h4,h5 {{ color: var(--accent); }}
hr {{ border:1px solid var(--border); }}
</style>
""", unsafe_allow_html=True)

# =============================================================================
# NAVBAR
# =============================================================================
col_nav_l, col_nav_r = st.columns([5, 3])
with col_nav_l:
    st.markdown("""
    <div class="navbar">
      <div class="nav-left">
        <span style="font-size:1.3rem;">🛰️</span>
        <div class="nav-title">OSINT INTELLIGENCE DASHBOARD</div>
      </div>
      <div class="nav-links">
        <span>Dashboard</span><span>Reports</span><span>Network</span><span>Alerts</span>
      </div>
    </div>
    """, unsafe_allow_html=True)
with col_nav_r:
    c1, c2 = st.columns([1, 1])
    with c1:
        if st.button("🔄 Aggiorna dati", help="Ricarica i dati dal database"):
            st.session_state["data_nonce"] += 1
            st.rerun()
    with c2:
        st.write("")

# =============================================================================
# HELPERS / UTILITIES
# =============================================================================
CAPITALS: List[Tuple[str, str, float, float]] = [
    # Lista estesa (puoi sostituire con la lista ONU completa)
    ("Italy","Rome",41.9028,12.4964), ("France","Paris",48.8566,2.3522),
    ("USA","Washington D.C.",38.9072,-77.0369), ("Canada","Ottawa",45.4215,-75.6972),
    ("Germany","Berlin",52.52,13.405), ("Spain","Madrid",40.4168,-3.7038),
    ("United Kingdom","London",51.5074,-0.1278), ("Japan","Tokyo",35.6895,139.6917),
    ("Brazil","Brasília",-15.8267,-47.9218), ("Australia","Canberra",-35.2809,149.1300),
    ("India","New Delhi",28.6139,77.2090), ("China","Beijing",39.9042,116.4074),
    ("Russia","Moscow",55.7558,37.6173), ("Mexico","Mexico City",19.4326,-99.1332),
    ("Argentina","Buenos Aires",-34.6037,-58.3816), ("Turkey","Ankara",39.9208,32.8541),
    ("Egypt","Cairo",30.0444,31.2357), ("South Africa","Pretoria",-25.7479,28.2293),
    ("Netherlands","Amsterdam",52.3676,4.9041), ("Belgium","Brussels",50.8503,4.3517),
    ("Portugal","Lisbon",38.7169,-9.1399), ("Sweden","Stockholm",59.3293,18.0686),
    ("Norway","Oslo",59.9139,10.7522), ("Denmark","Copenhagen",55.6761,12.5683),
    ("Greece","Athens",37.9838,23.7275), ("Poland","Warsaw",52.2298,21.0118),
    ("Czech Republic","Prague",50.0755,14.4378), ("Austria","Vienna",48.2082,16.3738),
    ("Switzerland","Bern",46.9481,7.4474), ("Ireland","Dublin",53.3331,-6.2489),
    ("Finland","Helsinki",60.1699,24.9384), ("Hungary","Budapest",47.4979,19.0402),
    ("Romania","Bucharest",44.4268,26.1025), ("Bulgaria","Sofia",42.6977,23.3219),
    ("Serbia","Belgrade",44.7866,20.4489), ("Croatia","Zagreb",45.815,15.9819),
    ("Slovakia","Bratislava",48.1486,17.1077), ("Slovenia","Ljubljana",46.0569,14.5058),
    ("Bosnia and Herzegovina","Sarajevo",43.8563,18.4131), ("North Macedonia","Skopje",41.9981,21.4254),
    ("Albania","Tirana",41.3275,19.8189), ("Montenegro","Podgorica",42.4411,19.2627),
    ("Iceland","Reykjavík",64.1466,-21.9426), ("Ukraine","Kyiv",50.45,30.5236),
    ("Belarus","Minsk",53.9,27.5667), ("Lithuania","Vilnius",54.6872,25.2797),
    ("Latvia","Riga",56.9496,24.1052), ("Estonia","Tallinn",59.437,24.7535),
    ("Moldova","Chisinau",47.0105,28.8638), ("Georgia","Tbilisi",41.7151,44.8271),
    ("Armenia","Yerevan",40.1776,44.5126), ("Azerbaijan","Baku",40.4093,49.8671),
    ("Kazakhstan","Astana",51.1694,71.4491), ("Uzbekistan","Tashkent",41.2995,69.2401),
    ("Turkmenistan","Ashgabat",37.9601,58.3261), ("Kyrgyzstan","Bishkek",42.8746,74.5698),
    ("Tajikistan","Dushanbe",38.5598,68.787), ("Mongolia","Ulaanbaatar",47.9212,106.9186),
    ("Iran","Tehran",35.6892,51.389), ("Iraq","Baghdad",33.3152,44.3661),
    ("Syria","Damascus",33.5138,36.2765), ("Jordan","Amman",31.9539,35.9106),
    ("Lebanon","Beirut",33.8938,35.5018), ("Israel","Jerusalem",31.7683,35.2137),
    ("Saudi Arabia","Riyadh",24.7136,46.6753), ("United Arab Emirates","Abu Dhabi",24.4539,54.3773),
    ("Qatar","Doha",25.276987,51.520008), ("Bahrain","Manama",26.2235,50.5876),
    ("Kuwait","Kuwait City",29.3759,47.9774), ("Oman","Muscat",23.5859,58.4059),
    ("Yemen","Sana’a",15.3694,44.191), ("Pakistan","Islamabad",33.6844,73.0479),
    ("Afghanistan","Kabul",34.5167,69.1833), ("Bangladesh","Dhaka",23.8103,90.4125),
    ("Nepal","Kathmandu",27.7172,85.324), ("Bhutan","Thimphu",27.4728,89.639),
    ("Sri Lanka","Colombo",6.9271,79.8612), ("Maldives","Malé",4.1755,73.5093),
    ("Thailand","Bangkok",13.7563,100.5018), ("Myanmar","Naypyidaw",19.7633,96.0785),
    ("Laos","Vientiane",17.9757,102.6331), ("Cambodia","Phnom Penh",11.5564,104.9282),
    ("Vietnam","Hanoi",21.0285,105.8542), ("Malaysia","Kuala Lumpur",3.139,101.6869),
    ("Singapore","Singapore",1.3521,103.8198), ("Indonesia","Jakarta",-6.2088,106.8456),
    ("Philippines","Manila",14.5995,120.9842), ("Brunei","Bandar Seri Begawan",4.9031,114.9398),
    ("Papua New Guinea","Port Moresby",-9.4438,147.18), ("New Zealand","Wellington",-41.2865,174.7762),
    ("Fiji","Suva",-18.1416,178.4419), ("Samoa","Apia",-13,-171.75),
    ("Tonga","Nukuʻalofa",-21.1394,-175.2018), ("Vanuatu","Port Vila",-17.7338,168.3219),
    ("Solomon Islands","Honiara",-9.433,159.95), ("Australia","Canberra",-35.2809,149.1300),
    ("Morocco","Rabat",34.0209,-6.8416), ("Algeria","Algiers",36.7538,3.0588),
    ("Tunisia","Tunis",36.8065,10.1815), ("Libya","Tripoli",32.8872,13.1913),
    ("Egypt","Cairo",30.0444,31.2357), ("Sudan","Khartoum",15.5007,32.5599),
    ("South Sudan","Juba",4.8594,31.5713), ("Ethiopia","Addis Ababa",9.03,38.74),
    ("Eritrea","Asmara",15.3333,38.9333), ("Djibouti","Djibouti",11.5883,43.145),
    ("Somalia","Mogadishu",2.0469,45.3182), ("Kenya","Nairobi",-1.2864,36.8172),
    ("Uganda","Kampala",0.3476,32.5825), ("Tanzania","Dodoma",-6.162,35.7516),
    ("Rwanda","Kigali",-1.95,30.0588), ("Burundi","Gitega",-3.4264,29.9306),
    ("DR Congo","Kinshasa",-4.4419,15.2663), ("Congo","Brazzaville",-4.2634,15.2429),
    ("Gabon","Libreville",0.4162,9.4673), ("Cameroon","Yaoundé",3.848,11.5021),
    ("Central African Republic","Bangui",4.3667,18.5833), ("Chad","N'Djamena",12.1348,15.0557),
    ("Niger","Niamey",13.5127,2.112), ("Nigeria","Abuja",9.0765,7.3986),
    ("Ghana","Accra",5.6037,-0.187), ("Côte d'Ivoire","Yamoussoukro",6.8276,-5.2893),
    ("Burkina Faso","Ouagadougou",12.3714,-1.5197), ("Mali","Bamako",12.6392,-8.0029),
    ("Senegal","Dakar",14.6928,-17.4467), ("Guinea","Conakry",9.6412,-13.5784),
    ("Sierra Leone","Freetown",8.4657,-13.2317), ("Liberia","Monrovia",6.3,-10.797),
    ("Togo","Lomé",6.1319,1.2228), ("Benin","Porto-Novo",6.4969,2.6289),
    ("Gambia","Banjul",13.4549,-16.579), ("Guinea-Bissau","Bissau",11.8636,-15.5977),
    ("Cape Verde","Praia",14.933,-23.5133), ("Equatorial Guinea","Malabo",3.75,8.7833),
    ("São Tomé and Príncipe","São Tomé",0.3365,6.7273), ("Madagascar","Antananarivo",-18.8792,47.5079),
    ("Mozambique","Maputo",-25.9655,32.5832), ("Angola","Luanda",-8.8383,13.2344),
    ("Zambia","Lusaka",-15.3875,28.3228), ("Zimbabwe","Harare",-17.8292,31.0522),
    ("Malawi","Lilongwe",-13.9626,33.7741), ("Namibia","Windhoek",-22.5609,17.0658),
    ("Botswana","Gaborone",-24.6583,25.9122), ("Eswatini","Mbabane",-26.3167,31.1333),
    ("Lesotho","Maseru",-29.3167,27.4833),
]
cap_df = pd.DataFrame(CAPITALS, columns=["country", "capital", "lat", "lon"])

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
    return deterministic_capital_for_username(str(result.get("username", "")))

def compute_profile_found_ratio(result: dict) -> float:
    ps = result.get("profile_status", {}) or {}
    if not ps: return 0.0
    total = len(ps)
    found = sum(1 for v in ps.values() if v.get("exists"))
    return round(found / total * 100.0, 1)

def cluster_points_grid(df_points: pd.DataFrame, level: int = 2) -> pd.DataFrame:
    """Raggruppa i punti su una griglia geospaziale arrotondando lat/lon."""
    if df_points.empty:
        return df_points
    step_map = {0: 1.0, 1: 0.5, 2: 0.25, 3: 0.1, 4: 0.05}
    step = step_map.get(level, 0.25)
    dfc = df_points.copy()
    dfc["lat_bin"] = (dfc["lat"] / step).round().astype(int)
    dfc["lon_bin"] = (dfc["lon"] / step).round().astype(int)
    grouped = (
        dfc.groupby(["lat_bin", "lon_bin"])
           .agg(lat=("lat", "mean"), lon=("lon", "mean"),
                count=("username", "count"), avg_found_pct=("found_pct", "mean"))
           .reset_index(drop=True)
    )
    return grouped

def to_html_download(figs: List[go.Figure], titles: List[str], filename: str = "dashboard_snapshot.html") -> str:
    """Crea un HTML auto-contenuto con una griglia di figure Plotly e ritorna il percorso del file."""
    assert len(figs) == len(titles)
    sections = []
    for fig, title in zip(figs, titles):
        sections.append(f"<h2 style='font-family: Poppins, sans-serif; color:{ACCENT};'>{title}</h2>")
        sections.append(pio.to_html(fig, include_plotlyjs='cdn', full_html=False))
    html = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>OSINT Dashboard Snapshot</title>
  <style> body {{ background:#0B0E13; color:#E6EDF3; font-family: Poppins, sans-serif; padding:20px; }} </style>
</head>
<body>
  <h1 style="color:{ACCENT};">OSINT Intelligence Dashboard — Snapshot</h1>
  {''.join(sections)}
  <hr/>
  <small>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</small>
</body>
</html>
"""
    out_path = os.path.join(os.getcwd(), filename)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    return out_path

# =============================================================================
# SMART CACHE LAYER (Opzione A)
# =============================================================================
@st.cache_data(show_spinner=False)
def _cached_load_processed(nonce: int):
    """Smart cache: invalidata quando cambia 'nonce' (aggiornato dopo scan/batch/refresh)."""
    scans = load_recent(500)
    df = pd.DataFrame(scans) if scans else pd.DataFrame(columns=["id","username","queried_at","result"])
    if not df.empty:
        df["queried_at"] = pd.to_datetime(df["queried_at"], errors="coerce")
        df["result"] = df["result"].apply(parse_result)
        df["found_pct_calc"] = df["result"].apply(compute_profile_found_ratio)
    return df

def get_df():
    return _cached_load_processed(st.session_state["data_nonce"])

# =============================================================================
# MENU SIDEBAR
# =============================================================================
st.sidebar.title("OSINT Suite Pro")
menu = st.sidebar.radio("Sezione", ["Dashboard", "Single Scan", "Batch CSV", "Reports"])

# =============================================================================
# DASHBOARD
# =============================================================================
if menu == "Dashboard":
    df = get_df()
    if df.empty:
        st.info("Nessuna scansione disponibile.")
        st.stop()

    # =======================
    # 🔍 FILTRI COMBINATI
    # =======================
    st.markdown("### 🔍 Filtri combinati")
    fcol1, fcol2, fcol3, fcol4, fcol5 = st.columns([2,2,2,2,1])

    with fcol1:
        search = st.text_input("Username contiene…", value=st.session_state["filters"].get("search",""))
    all_platforms = sorted({k for r in df["result"] for k in (r.get("profile_status") or {}).keys()})
    with fcol2:
        platform_sel = st.multiselect("Piattaforme", options=all_platforms, default=st.session_state["filters"].get("platform_sel", []))
    with fcol3:
        min_d, max_d = df["queried_at"].min().date(), df["queried_at"].max().date()
        date_range = st.date_input("Intervallo date", value=st.session_state["filters"].get("date_range", (min_d, max_d)))
        if not (isinstance(date_range, tuple) and len(date_range)==2):
            date_range = (min_d, max_d)
    with fcol4:
        min_pct = st.slider("Min % profili trovati", 0, 100, st.session_state["filters"].get("min_pct", 0))
    with fcol5:
        if st.button("Reset"):
            st.session_state["filters"] = {}
            st.rerun()

    # Applica filtro
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

    # =======================
    # 🌍 MAPPA GLOBALE IN ALTO
    # =======================
    st.subheader("🌍 Mappa Globale — Capitali + Punti OSINT")
    opt_col1, opt_col2, opt_col3, opt_col4 = st.columns([1, 1, 2, 1])
    with opt_col1: use_heatmap = st.toggle("Heatmap", value=False)
    with opt_col2: use_cluster = st.toggle("Clustering", value=False)
    with opt_col3: cluster_level = st.slider("Livello clustering", 0, 4, 2)
    with opt_col4: show_capitals = st.toggle("Mostra capitali", value=True)

    points = []
    for _, row in df_f.iterrows():
        username = str(row.get("username", ""))
        res = row.get("result", {})
        geo = extract_geo_from_result(res)
        found_pct = compute_profile_found_ratio(res)
        points.append({
            "username": username, "lat": geo.get("lat"), "lon": geo.get("lon"),
            "city": geo.get("city"), "country": geo.get("country"), "found_pct": found_pct
        })
    points_df = pd.DataFrame(points).dropna(subset=["lat", "lon"])

    map_center = {"lat": 20, "lon": 0}
    if use_heatmap and not points_df.empty:
        fig_map = px.density_mapbox(
            points_df, lat="lat", lon="lon", z="found_pct",
            radius=20, center=map_center, zoom=1.1, color_continuous_scale="Blues"
        )
        fig_map.update_layout(mapbox_style="carto-darkmatter",
                              margin=dict(l=0, r=0, t=0, b=0), height=500)
    else:
        fig_map = go.Figure()
        if show_capitals:
            cap_layer = pd.DataFrame(cap_df)
            fig_map.add_trace(go.Scattermapbox(
                lat=cap_layer["lat"], lon=cap_layer["lon"],
                text=cap_layer["capital"] + " (" + cap_layer["country"] + ")",
                mode="markers",
                marker=go.scattermapbox.Marker(size=6, color="#6C7A89"),
                hoverinfo="text", name="Capitali"
            ))
        if not points_df.empty:
            if use_cluster:
                clustered = cluster_points_grid(points_df, cluster_level)
                sizes = (clustered["count"].astype(float)**0.6)*6+6
                hover_txt = clustered.apply(lambda r: f"Cluster ~{int(r['count'])} — avg {r['avg_found_pct']:.1f}%", axis=1)
                fig_map.add_trace(go.Scattermapbox(
                    lat=clustered["lat"], lon=clustered["lon"], text=hover_txt,
                    mode="markers",
                    marker=go.scattermapbox.Marker(size=sizes, color=ACCENT, opacity=0.85),
                    hoverinfo="text", name="Cluster"
                ))
            else:
                sizes = (points_df["found_pct"].fillna(0).astype(float)/10.0)+6
                hover_txt = points_df.apply(lambda r: f"{r['username']} — {r.get('city','')} ({r.get('country','')}) — {r['found_pct']}%", axis=1)
                fig_map.add_trace(go.Scattermapbox(
                    lat=points_df["lat"], lon=points_df["lon"], text=hover_txt,
                    mode="markers",
                    marker=go.scattermapbox.Marker(size=sizes, color=ACCENT, opacity=0.85),
                    hoverinfo="text", name="OSINT Points"
                ))

        fig_map.update_layout(
            mapbox_style="carto-darkmatter",
            mapbox_zoom=1.1,
            mapbox_center=map_center,
            dragmode="pan",
            margin=dict(l=0, r=0, t=0, b=0),
            height=500
        )

    config = {
        "scrollZoom": True,
        "displayModeBar": True,
        "modeBarButtonsToAdd": ["zoomInMapbox", "zoomOutMapbox", "resetViewMapbox"],
    }
    st.plotly_chart(fig_map, use_container_width=True, config=config)

    # =======================
    # 📊 STATISTICHE DINAMICHE
    # =======================
    total_scans = len(df_f)
    unique_users = df_f["username"].nunique()
    avg_found_pct = round(df_f["found_pct_calc"].mean() if total_scans else 0.0, 1)
    std_found_pct = round(df_f["found_pct_calc"].std() if total_scans > 1 else 0.0, 1)

    mc1, mc2, mc3, mc4 = st.columns(4)
    mc1.markdown(f"<div class='metric-card'><h3>{total_scans}</h3><p>Scansioni filtrate</p></div>", unsafe_allow_html=True)
    mc2.markdown(f"<div class='metric-card'><h3>{unique_users}</h3><p>Utenti unici</p></div>", unsafe_allow_html=True)
    mc3.markdown(f"<div class='metric-card'><h3>{avg_found_pct}%</h3><p>Media profili trovati</p></div>", unsafe_allow_html=True)
    mc4.markdown(f"<div class='metric-card'><h3>{std_found_pct}</h3><p>Deviazione standard</p></div>", unsafe_allow_html=True)

    # Top piattaforme (5)
    platforms = {}
    for r in df_f["result"]:
        for k, v in (r.get("profile_status") or {}).items():
            if v.get("exists"): platforms[k] = platforms.get(k, 0) + 1
    st.markdown("---")
    st.markdown("#### 🧭 Top piattaforme (Top 5)")
    if platforms:
        top_pf = sorted(platforms.items(), key=lambda x: x[1], reverse=True)[:5]
        top_pf_df = pd.DataFrame(top_pf, columns=["Piattaforma", "Conteggio"])
        top_fig = px.bar(top_pf_df, x="Piattaforma", y="Conteggio", text="Conteggio", color="Piattaforma",
                         color_discrete_sequence=px.colors.sequential.Blues)
        top_fig.update_traces(textposition="outside")
        top_fig.update_layout(template="plotly_dark", showlegend=False, height=320, margin=dict(l=10,r=10,t=30,b=10))
        st.plotly_chart(top_fig, use_container_width=True)
    else:
        st.info("Nessuna piattaforma attiva nei dati filtrati.")

    # Trend settimanale
    st.markdown("#### 📈 Trend settimanale")
    if not df_f.empty:
        df_f["week"] = df_f["queried_at"].dt.to_period("W").apply(lambda r: r.start_time)
        wk = df_f.groupby("week").size().reset_index(name="count")
        wk = wk.sort_values("week")
        fig_wk = px.line(wk, x="week", y="count", markers=True, color_discrete_sequence=[ACCENT])
        fig_wk.update_layout(template="plotly_dark", height=300, margin=dict(l=10,r=10,t=10,b=10))
        st.plotly_chart(fig_wk, use_container_width=True)
        if len(wk) >= 2:
            delta = wk["count"].iloc[-1] - wk["count"].iloc[-2]
            st.caption(f"Δ ultimo periodo: **{delta:+d}** scansioni")
    else:
        st.info("Nessun dato per calcolare il trend.")

    # =======================
    # ⚡ QUICK SCAN (light)
    # =======================
    with st.expander("⚡ Quick Scan", expanded=False):
        col_in1, col_in2, col_in3 = st.columns([3, 1, 1])
        with col_in1:
            quick_user = st.text_input("Username o email:", key="dash_quser_v32")
        with col_in2:
            do_preview_quick = st.checkbox("Preview", value=True, key="dash_prev_v32")
        with col_in3:
            do_github_quick = st.checkbox("GitHub", value=True, key="dash_gh_v32")
        do_status_quick = st.checkbox("Controllo stato profili", value=True, key="dash_status_v32")
        max_profiles_quick = st.slider("Max profili simultanei", 1, 30, 8, key="dash_max_v32")

        if st.button("🚀 Avvia Quick Scan", key="dash_run_quick_v32"):
            if not quick_user or not quick_user.strip():
                st.error("Inserisci uno username valido.")
            else:
                with st.spinner("Esecuzione scansione in corso..."):
                    result = run_scan_for_input(
                        quick_user.strip(),
                        do_status=do_status_quick, do_preview=do_preview_quick,
                        do_github=do_github_quick, max_profiles=max_profiles_quick
                    )
                    try:
                        save_scan(result)
                        st.session_state["data_nonce"] += 1
                    except Exception:
                        pass
                    st.success(f"Scansione completata per {quick_user} ✅")

    # =======================
    # 🧪 SINGLE SCAN COMPLETO — Integrato in Dashboard
    # =======================
    st.markdown("---")
    with st.expander("⚡ Esegui una nuova scansione OSINT (completa)", expanded=False):
        dcol1, dcol2, dcol3 = st.columns([3, 1, 1])
        with dcol1:
            dash_user = st.text_input("Username o email:", key="dash_full_user_v32")
        with dcol2:
            dash_preview = st.checkbox("Scraping preview", value=True, key="dash_full_prev_v32")
        with dcol3:
            dash_github = st.checkbox("GitHub API", value=True, key="dash_full_gh_v32")
        dash_status = st.checkbox("Check profili (HTTP)", value=True, key="dash_full_status_v32")
        dash_max = st.slider("Max concurrent checks", 1, 50, 8, key="dash_full_max_v32")
        dash_auto_report = st.checkbox("Auto-salva PDF/Excel dopo la scansione", value=True, key="dash_full_autoreport_v32")

        if st.button("🚀 Avvia Scansione (completa)", key="dash_full_run_v32"):
            if not dash_user or not dash_user.strip():
                st.error("Inserisci username o email valida.")
            else:
                with st.spinner("Eseguendo scan completa..."):
                    result = run_scan_for_input(
                        dash_user.strip(),
                        do_status=dash_status, do_preview=dash_preview,
                        do_github=dash_github, max_profiles=dash_max
                    )
                    try:
                        save_scan(result)
                        st.session_state["data_nonce"] += 1  # invalidate smart cache
                    except Exception:
                        pass
                    st.success("Scansione completata ✅")

                    # Profilazione automatica
                    try:
                        profile_summary = build_osint_profile_summary(result)
                        st.subheader("🧠 Profilazione automatica")
                        st.write(f"**Livello attività:** {profile_summary.get('activity_level','-')}")
                        st.write(f"**Piattaforme attive:** {', '.join(profile_summary.get('active_platforms', [])) or 'Nessuna'}")
                        st.write(f"**Categorie:** {', '.join(profile_summary.get('categories', [])) or 'Nessuna'}")
                        if profile_summary.get("summary"):
                            st.info(profile_summary["summary"])
                    except Exception:
                        pass

                    # Profili trovati
                    ps = result.get("profile_status", {})
                    if ps:
                        st.subheader("Risultati profili")
                        df_profiles = pd.DataFrame([
                            {"Piattaforma": p, "URL": d.get("url",""), "Stato": d.get("status",""),
                             "Profilo trovato": "✅" if d.get("exists") else "❌"}
                            for p, d in ps.items()
                        ])
                        st.dataframe(df_profiles, use_container_width=True)
                    else:
                        st.warning("Nessun profilo rilevato.")

                    # GitHub
                    gh = result.get("github_api")
                    if gh:
                        st.subheader("Dettagli GitHub")
                        st.table(pd.DataFrame([gh]))

                    # Preview
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

                    # Varianti
                    variants = result.get("variants", [])
                    if variants:
                        st.subheader("Varianti di username generate")
                        st.write(", ".join(variants))

                    # Export
                    try:
                        pdf = generate_pdf_report(result)
                        xlsx = generate_excel(result)
                        if dash_auto_report:
                            st.success("Report salvati (PDF/Excel).")
                        with open(pdf, "rb") as f:
                            st.download_button("📄 Download PDF", f, file_name=os.path.basename(pdf), key="dash_full_pdf_v32")
                        with open(xlsx, "rb") as f:
                            st.download_button("📊 Download Excel", f, file_name=os.path.basename(xlsx), key="dash_full_xlsx_v32")
                    except Exception as e:
                        st.warning(f"Export non riuscito: {e}")

    # =======================
    # 🔄 LIVE MONITOR + AUTO-REFRESH
    # =======================
    st.markdown("---")
    lm1, lm2, lm3 = st.columns([1, 2, 1])
    with lm1: auto_refresh = st.toggle("🔁 Auto-refresh", value=False)
    with lm2: refresh_interval = st.slider("Intervallo aggiornamento (sec)", 5, 60, 15)
    with lm3:
        st.write("")
        export_snap = st.button("📦 Esporta snapshot dashboard (HTML)")
    if auto_refresh:
        st.markdown(f"<i>Aggiornamento automatico ogni {refresh_interval} secondi…</i>", unsafe_allow_html=True)
        time.sleep(refresh_interval); st.rerun()

    st.markdown("### 📡 Live Activity Monitor")
    recent_scans = load_recent(12)
    fig_recent = None
    if recent_scans:
        df_recent = pd.DataFrame(recent_scans)[["username", "queried_at"]]
        df_recent["queried_at"] = pd.to_datetime(df_recent["queried_at"]).dt.strftime("%d %b %Y %H:%M:%S")
        st.dataframe(df_recent.rename(columns={"username":"Utente","queried_at":"Data/Ora"}), use_container_width=True, height=260)
        df_recent_sorted = df_recent.sort_values("queried_at")
        fig_recent = px.line(df_recent_sorted, x="queried_at", y=df_recent_sorted.index,
                             markers=True, title="Attività Scansioni Live",
                             color_discrete_sequence=[ACCENT])
        fig_recent.update_layout(template="plotly_dark", showlegend=False,
                                 xaxis_title="Tempo", yaxis_title="Index", height=280)
        st.plotly_chart(fig_recent, use_container_width=True)
    else:
        st.info("Nessuna scansione recente trovata.")

    # =======================
    # 📊 Intelligence Summary (Timeline, Donut)
    # =======================
    st.markdown("---")
    st.markdown("### 📊 Intelligence Summary")
    tl = df_f.groupby(df_f["queried_at"].dt.date).size().reset_index(name="count") if not df_f.empty else pd.DataFrame(columns=["queried_at","count"])
    if not tl.empty:
        fig_tl = px.line(tl, x="queried_at", y="count", title="Scansioni giornaliere", markers=True)
        fig_tl.update_layout(template="plotly_dark")
        st.plotly_chart(fig_tl, use_container_width=True)

    platforms_f = {}
    for r in df_f["result"]:
        for k, v in (r.get("profile_status") or {}).items():
            if v.get("exists"): platforms_f[k] = platforms_f.get(k, 0) + 1
    fig_pf_f = None
    if platforms_f:
        pf_df = pd.DataFrame(platforms_f.items(), columns=["Piattaforma", "Conteggio"])
        fig_pf_f = px.pie(pf_df, values="Conteggio", names="Piattaforma", hole=0.55,
                          color_discrete_sequence=px.colors.sequential.Blues)
        fig_pf_f.update_layout(title="Distribuzione piattaforme", template="plotly_dark")
        st.plotly_chart(fig_pf_f, use_container_width=True)
    else:
        st.info("Nessuna piattaforma attiva nel filtro.")

    st.subheader("Elenco dettagliato scansioni")
    st.dataframe(
        df_f[["id", "username", "queried_at"]].sort_values("queried_at", ascending=False),
        use_container_width=True, height=300
    )

    # =======================
    # 🕸️ ENTITY GRAPH — utenti ↔ piattaforme
    # =======================
    st.markdown("---")
    st.subheader("🕸️ Entity Graph — Utenti ↔ Piattaforme")
    enable_graph = st.toggle("Mostra Entity Graph", value=False)
    max_users = st.slider("Numero massimo utenti", 10, 200, 50)
    fig_graph = None
    if enable_graph:
        edges, users_seen = [], set()
        for _, row in df.iterrows():
            username = str(row.get("username", ""))
            if username in users_seen: continue
            users_seen.add(username)
            res = row.get("result", {})
            ps = res.get("profile_status", {}) or {}
            for platform, v in ps.items():
                if v.get("exists"): edges.append((f"u:{username}", f"p:{platform}"))
            if len(users_seen) >= max_users: break
        if edges:
            G = nx.Graph(); G.add_edges_from(edges)
            pos = nx.spring_layout(G, k=0.6, seed=42)
            node_x, node_y, node_text, node_color, node_size = [], [], [], [], []
            for node, (x, y) in pos.items():
                node_x.append(x); node_y.append(y)
                if node.startswith("u:"):
                    node_color.append(ACCENT); node_size.append(18); node_text.append(node[2:])
                else:
                    node_color.append("#7C8A96"); node_size.append(14); node_text.append(node[2:])
            edge_x, edge_y = [], []
            for src, dst in G.edges():
                x0, y0 = pos[src]; x1, y1 = pos[dst]
                edge_x += [x0, x1, None]; edge_y += [y0, y1, None]
            edge_trace = go.Scatter(x=edge_x, y=edge_y, line=dict(width=1, color="#4a5562"), mode="lines")
            node_trace = go.Scatter(x=node_x, y=node_y, mode="markers+text", text=node_text,
                                    textposition="bottom center",
                                    marker=dict(size=node_size, color=node_color),
                                    hoverinfo="text")
            fig_graph = go.Figure(data=[edge_trace, node_trace])
            fig_graph.update_layout(showlegend=False, template="plotly_dark",
                                    margin=dict(l=10, r=10, t=10, b=10), height=520)
            st.plotly_chart(fig_graph, use_container_width=True)
        else:
            st.info("Nessuna relazione utente–piattaforma trovata.")

    # =======================
    # 📦 Esporta snapshot dashboard (HTML)
    # =======================
    if export_snap:
        figs, titles = [fig_map], ["Mappa Globale"]
        if fig_recent is not None: figs.append(fig_recent); titles.append("Live Activity")
        if not tl.empty: figs.append(fig_tl); titles.append("Timeline scansioni")
        if fig_pf_f is not None: figs.append(fig_pf_f); titles.append("Piattaforme (filtro)")
        if fig_graph is not None: figs.append(fig_graph); titles.append("Entity Graph")
        out_html = to_html_download(figs, titles, filename=f"dashboard_snapshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        with open(out_html, "r", encoding="utf-8") as f:
            st.download_button("⬇️ Scarica snapshot (HTML)", f, file_name=os.path.basename(out_html), mime="text/html")

# =============================================================================
# SINGLE SCAN (pagina dedicata resta disponibile)
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
                result = run_scan_for_input(
                    user_input.strip(),
                    do_status=do_status, do_preview=do_preview,
                    do_github=do_github, max_profiles=max_profiles
                )
                try:
                    save_scan(result)
                    st.session_state["data_nonce"] += 1  # invalidate cache
                except Exception:
                    pass
                st.success("Scansione completata ✅")

                try:
                    profile_summary = build_osint_profile_summary(result)
                    st.subheader("🧠 Profilazione automatica")
                    st.write(f"**Livello attività:** {profile_summary.get('activity_level','-')}")
                    st.write(f"**Piattaforme attive:** {', '.join(profile_summary.get('active_platforms', [])) or 'Nessuna'}")
                    st.write(f"**Categorie:** {', '.join(profile_summary.get('categories', [])) or 'Nessuna'}")
                    if profile_summary.get('summary'):
                        st.info(profile_summary['summary'])
                except Exception:
                    pass

                ps = result.get("profile_status", {})
                if ps:
                    st.subheader("Risultati dei profili trovati")
                    df_profiles = pd.DataFrame([
                        {"Piattaforma": p, "URL": d.get("url",""), "Stato": d.get("status",""), "Profilo trovato": "✅" if d.get("exists") else "❌"}
                        for p, d in ps.items()
                    ])
                    st.dataframe(df_profiles, use_container_width=True)
                else:
                    st.warning("Nessun profilo rilevato.")

                gh = result.get("github_api")
                if gh:
                    st.subheader("Dettagli GitHub")
                    st.table(pd.DataFrame([gh]))

                sp = result.get("scraping_preview", {})
                if sp:
                    st.subheader("Informazioni di preview (meta/og)")
                    rows = []
                    for site, content in sp.items():
                        meta = content.get("meta_preview", {})
                        rows.append({"Sito": site, "Titolo": meta.get("title"), "Descrizione": meta.get("description"), "Dominio": meta.get("base")})
                    st.dataframe(pd.DataFrame(rows), use_container_width=True)

                variants = result.get("variants", [])
                if variants:
                    st.subheader("Varianti di username generate")
                    st.write(", ".join(variants))

                try:
                    pdf = generate_pdf_report(result)
                    xlsx = generate_excel(result)
                    if auto_report:
                        st.success("Report salvati (PDF/Excel).")
                    with open(pdf, "rb") as f:
                        st.download_button("📄 Download PDF", f, file_name=os.path.basename(pdf))
                    with open(xlsx, "rb") as f:
                        st.download_button("📊 Download Excel", f, file_name=os.path.basename(xlsx))
                except Exception as e:
                    st.warning(f"Export non riuscito: {e}")

# =============================================================================
# BATCH CSV
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
        tmp_path = "batch_list.csv"
        with open(tmp_path, "wb") as f:
            f.write(uploaded.getbuffer())
        if st.button("Start Batch Scan"):
            with st.spinner("Esecuzione batch..."):
                results = run_batch_scan_from_csv(
                    tmp_path,
                    do_status=do_status, do_preview=do_preview,
                    do_github=do_github, max_profiles=max_profiles
                )
                for r in results:
                    try:
                        save_scan(r)
                    except Exception:
                        pass
                st.session_state["data_nonce"] += 1
                st.success(f"Batch completato: {len(results)} scansioni.")
                st.dataframe(pd.DataFrame(results)[["username", "queried_at"]], use_container_width=True)

# =============================================================================
# REPORTS
# =============================================================================
elif menu == "Reports":
    st.title("Reports")
    scans = load_recent(200)
    if scans:
        df = pd.DataFrame(scans)
        users = sorted(df["username"].unique())
        sel = st.selectbox("Seleziona username per dettaglio:", users) if users else None
        sel_rec = next((r for r in scans if r["username"] == sel), None) if sel else None
        if sel_rec:
            res = parse_result(sel_rec.get("result"))
            st.json(res)
            try:
                pdf = generate_pdf_report(res)
                xlsx = generate_excel(res)
                with open(pdf, "rb") as f:
                    st.download_button("Download PDF", f, file_name=os.path.basename(pdf))
                with open(xlsx, "rb") as f:
                    st.download_button("Download Excel", f, file_name=os.path.basename(xlsx))
            except Exception as e:
                st.warning(f"Export non riuscito: {e}")
    else:
        st.info("Nessun report disponibile.")

# =============================================================================
# FOOTER
# =============================================================================
st.markdown("<hr>", unsafe_allow_html=True)
st.caption("© 2025 OSINT Suite Pro — Intelligence Dashboard v3.2")
