# viz.py — Visualization utilities for OSINT Dashboard
"""
Modulo centralizzato per la generazione di grafici e visualizzazioni.
Riduce duplicazione di codice nel file principale.
"""

from typing import List, Dict, Tuple, Optional
from datetime import datetime
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import networkx as nx
import plotly.io as pio
import os

from config import ACCENT_COLOR as ACCENT


def create_heatmap_figure(
    points_df: pd.DataFrame,
    map_center: Dict[str, float],
    zoom: int = 1
) -> go.Figure:
    """
    Crea una heatmap su mappa per punti OSINT.
    
    Args:
        points_df: DataFrame con colonne [lat, lon, found_pct]
        map_center: Centro della mappa {"lat": float, "lon": float}
        zoom: Livello di zoom
    
    Returns:
        Plotly Figure object
    """
    fig = px.density_mapbox(
        points_df,
        lat="lat",
        lon="lon",
        z="found_pct",
        radius=20,
        center=map_center,
        zoom=zoom,
        color_continuous_scale="Blues"
    )
    fig.update_layout(
        mapbox_style="carto-darkmatter",
        margin=dict(l=0, r=0, t=0, b=0),
        height=520
    )
    return fig


def create_cluster_map_figure(
    points_df: pd.DataFrame,
    clusters_df: pd.DataFrame,
    capitals_df: pd.DataFrame,
    map_center: Dict[str, float],
    show_capitals: bool = True,
    threat_zones: List[Tuple[float, float]] = None,
    zoom: int = 1
) -> go.Figure:
    """
    Crea una mappa con clustering e threat zones.
    
    Args:
        points_df: DataFrame con punti originali
        clusters_df: DataFrame con cluster aggregati
        capitals_df: DataFrame con capitali mondiali
        map_center: Centro della mappa
        show_capitals: Mostrare capitali
        threat_zones: Lista di tuple (lat, lon) per zone minaccia
        zoom: Livello zoom
    
    Returns:
        Plotly Figure object
    """
    fig = go.Figure()
    
    # Capitali
    if show_capitals:
        cap = capitals_df.copy()
        fig.add_trace(go.Scattermapbox(
            lat=cap["lat"],
            lon=cap["lon"],
            text=cap["capital"] + " (" + cap["country"] + ")",
            mode="markers",
            marker=go.scattermapbox.Marker(size=6, color="#6C7A89"),
            hoverinfo="text",
            name="Capitali"
        ))
    
    # Cluster
    sizes = (clusters_df["count"].astype(float) ** 0.6) * 6 + 6
    hover = clusters_df.apply(
        lambda r: f"Cluster ~{int(r['count'])} — avg {r['avg_found_pct']:.1f}%",
        axis=1
    )
    fig.add_trace(go.Scattermapbox(
        lat=clusters_df["lat"],
        lon=clusters_df["lon"],
        text=hover,
        mode="markers",
        marker=go.scattermapbox.Marker(size=sizes, color=ACCENT, opacity=0.85),
        hoverinfo="text",
        name="Cluster"
    ))
    
    # Threat zones
    if threat_zones:
        for lat, lon in threat_zones:
            fig.add_trace(go.Scattermapbox(
                lat=[lat],
                lon=[lon],
                mode="markers",
                marker=go.scattermapbox.Marker(size=24, color="rgba(255,0,0,0.25)"),
                hoverinfo="skip",
                name="Threat Zone"
            ))
    
    fig.update_layout(
        mapbox_style="carto-darkmatter",
        mapbox_zoom=zoom,
        mapbox_center=map_center,
        dragmode="pan",
        margin=dict(l=0, r=0, t=0, b=0),
        height=520
    )
    
    return fig


def create_points_map_figure(
    points_df: pd.DataFrame,
    capitals_df: pd.DataFrame,
    map_center: Dict[str, float],
    show_capitals: bool = True,
    threat_zones: List[Tuple[float, float]] = None,
    zoom: int = 1
) -> go.Figure:
    """
    Crea una mappa con punti OSINT individuali.
    
    Args:
        points_df: DataFrame con [username, lat, lon, city, country, found_pct]
        capitals_df: DataFrame con capitali
        map_center: Centro della mappa
        show_capitals: Mostrare capitali
        threat_zones: Liste di threat zones
        zoom: Livello zoom
    
    Returns:
        Plotly Figure object
    """
    fig = go.Figure()
    
    # Capitali
    if show_capitals:
        cap = capitals_df.copy()
        fig.add_trace(go.Scattermapbox(
            lat=cap["lat"],
            lon=cap["lon"],
            text=cap["capital"] + " (" + cap["country"] + ")",
            mode="markers",
            marker=go.scattermapbox.Marker(size=6, color="#6C7A89"),
            hoverinfo="text",
            name="Capitali"
        ))
    
    # OSINT Points
    sizes = (points_df["found_pct"].fillna(0).astype(float) / 10.0) + 6
    hover = points_df.apply(
        lambda r: f"{r['username']} — {r.get('city','')} ({r.get('country','')}) — {r['found_pct']}%",
        axis=1
    )
    fig.add_trace(go.Scattermapbox(
        lat=points_df["lat"],
        lon=points_df["lon"],
        text=hover,
        mode="markers",
        marker=go.scattermapbox.Marker(size=sizes, color=ACCENT, opacity=0.85),
        hoverinfo="text",
        name="OSINT Points"
    ))
    
    # Threat zones
    if threat_zones:
        for lat, lon in threat_zones:
            fig.add_trace(go.Scattermapbox(
                lat=[lat],
                lon=[lon],
                mode="markers",
                marker=go.scattermapbox.Marker(size=24, color="rgba(255,0,0,0.25)"),
                hoverinfo="skip",
                name="Threat Zone"
            ))
    
    fig.update_layout(
        mapbox_style="carto-darkmatter",
        mapbox_zoom=zoom,
        mapbox_center=map_center,
        dragmode="pan",
        margin=dict(l=0, r=0, t=0, b=0),
        height=520
    )
    
    return fig


def create_platform_bar_chart(
    platform_counts: Dict[str, int],
    top_n: int = 10
) -> go.Figure:
    """Grafico a barre per piattaforme più comuni."""
    top_pf = sorted(platform_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
    df = pd.DataFrame(top_pf, columns=["Piattaforma", "Conteggio"])
    
    fig = px.bar(
        df,
        x="Piattaforma",
        y="Conteggio",
        text="Conteggio",
        color="Piattaforma",
        color_discrete_sequence=px.colors.sequential.Blues
    )
    fig.update_traces(textposition="outside")
    fig.update_layout(
        template="plotly_dark",
        showlegend=False,
        height=360,
        margin=dict(l=10, r=10, t=30, b=10)
    )
    return fig


def create_hourly_area_chart(df: pd.DataFrame) -> go.Figure:
    """Grafico ad area per scansioni per ora."""
    if df.empty:
        return None
    
    tmp = df.copy()
    tmp["hour"] = tmp["queried_at"].dt.hour
    by_hour = tmp.groupby("hour").size().reset_index(name="count")
    
    fig = px.area(
        by_hour,
        x="hour",
        y="count",
        markers=True,
        color_discrete_sequence=[ACCENT]
    )
    fig.update_layout(
        template="plotly_dark",
        height=360,
        margin=dict(l=10, r=10, t=30, b=10),
        xaxis=dict(dtick=2)
    )
    return fig


def create_weekly_trend_chart(df: pd.DataFrame) -> Optional[Tuple]:
    """Grafico trend settimanale. Ritorna (fig, dataframe_aggregato)."""
    if df.empty:
        return None
    
    df_copy = df.copy()
    df_copy["week"] = df_copy["queried_at"].dt.to_period("W").apply(lambda r: r.start_time)
    wk = df_copy.groupby("week").size().reset_index(name="count").sort_values("week")
    
    if wk.empty:
        return None
    
    fig = px.line(
        wk,
        x="week",
        y="count",
        markers=True,
        color_discrete_sequence=[ACCENT]
    )
    fig.update_layout(
        template="plotly_dark",
        height=320,
        margin=dict(l=10, r=10, t=10, b=10)
    )
    return fig, wk


def create_daily_timeline_chart(df: pd.DataFrame) -> Optional[go.Figure]:
    """Grafico timeline giornaliera."""
    if df.empty:
        return None
    
    tl = df.groupby(df["queried_at"].dt.date).size().reset_index(name="count")
    
    if tl.empty:
        return None
    
    fig = px.line(
        tl,
        x="queried_at",
        y="count",
        title="Scansioni giornaliere",
        markers=True
    )
    fig.update_layout(template="plotly_dark")
    return fig


def create_platform_pie_chart(platform_counts: Dict[str, int]) -> go.Figure:
    """Grafico a torta per distribuzione piattaforme."""
    pf_df = pd.DataFrame(platform_counts.items(), columns=["Piattaforma", "Conteggio"])
    
    fig = px.pie(
        pf_df,
        values="Conteggio",
        names="Piattaforma",
        hole=0.55,
        color_discrete_sequence=px.colors.sequential.Blues
    )
    fig.update_layout(
        title="Distribuzione piattaforme",
        template="plotly_dark"
    )
    return fig


def create_entity_graph(edges: List[Tuple[str, str]], accent: str = ACCENT) -> go.Figure:
    """
    Crea grafo entità (utenti ↔ piattaforme).
    
    Args:
        edges: Lista di tuple (source, destination)
        accent: Colore accent per i nodi utente
    
    Returns:
        Plotly Figure object
    """
    G = nx.Graph()
    G.add_edges_from(edges)
    pos = nx.spring_layout(G, k=0.6, seed=42)
    
    nx_x, nx_y, txt, col, sz = [], [], [], [], []
    for node, (x, y) in pos.items():
        nx_x.append(x)
        nx_y.append(y)
        if node.startswith("u:"):
            col.append(accent)
            sz.append(18)
            txt.append(node[2:])
        else:
            col.append("#7C8A96")
            sz.append(14)
            txt.append(node[2:])
    
    # Edge lines
    ex, ey = [], []
    for s, d in G.edges():
        x0, y0 = pos[s]
        x1, y1 = pos[d]
        ex += [x0, x1, None]
        ey += [y0, y1, None]
    
    edge = go.Scatter(
        x=ex,
        y=ey,
        line=dict(width=1, color="#4a5562"),
        mode="lines"
    )
    
    node = go.Scatter(
        x=nx_x,
        y=nx_y,
        mode="markers+text",
        text=txt,
        textposition="bottom center",
        marker=dict(size=sz, color=col)
    )
    
    fig = go.Figure(data=[edge, node])
    fig.update_layout(
        template="plotly_dark",
        showlegend=False,
        margin=dict(l=10, r=10, t=10, b=10),
        height=540
    )
    
    return fig


def create_live_activity_chart(df: pd.DataFrame) -> go.Figure:
    """Grafico attività live."""
    fig = px.line(
        df,
        x="queried_at_dt",
        y=df.index,
        markers=True,
        title="Attività Scansioni Live",
        color_discrete_sequence=[ACCENT]
    )
    fig.update_layout(
        template="plotly_dark",
        showlegend=False,
        xaxis_title="Tempo",
        yaxis_title="Index",
        height=280
    )
    return fig


def export_snapshot_html(
    figs: List[go.Figure],
    titles: List[str],
    filename: str
) -> str:
    """
    Esporta snapshot HTML con grafici multipli.
    
    Args:
        figs: Lista di figure Plotly
        titles: Titoli per ogni figura
        filename: Nome file output
    
    Returns:
        Percorso file creato
    """
    sections = []
    for fig, title in zip(figs, titles):
        sections.append(
            f"<h2 style='font-family:Poppins,sans-serif;color:{ACCENT};margin:8px 0 4px'>{title}</h2>"
        )
        sections.append(pio.to_html(fig, include_plotlyjs=True, full_html=False))
    
    html = f"""<!doctype html><html><head><meta charset="utf-8"/>
  <title>OSINT Dashboard Snapshot</title>
  <style>body{{background:#0B0E13;color:#E6EDF3;font-family:Poppins,sans-serif;padding:20px}}</style>
</head><body>
  <h1 style="color:{ACCENT};margin:0 0 10px">OSINT Intelligence Dashboard — Snapshot</h1>
  {''.join(sections)}
  <hr/><small>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</small>
</body></html>"""
    
    out = os.path.join(os.getcwd(), filename)
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    
    return out
