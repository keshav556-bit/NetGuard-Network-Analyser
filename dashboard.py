"""
NetGuard Dashboard — Stage 7
Run with VS Code play button OR:
streamlit run dashboard.py
No sudo needed!
"""
import streamlit as st
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import os, time
from collections import Counter
from datetime import datetime

# ── Page config ───────────────────────────────────────
st.set_page_config(
    page_title="NetGuard Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ── Custom CSS ────────────────────────────────────────
st.markdown("""
<style>
    .main { background-color: #0e1117; }
    .metric-card {
        background: #1e2130;
        border-radius: 10px;
        padding: 20px;
        text-align: center;
        border: 1px solid #2d3250;
    }
    .metric-val {
        font-size: 36px;
        font-weight: bold;
        color: #1D9E75;
    }
    .metric-label {
        font-size: 14px;
        color: #888;
        margin-top: 4px;
    }
    .alert-high     { color: #ff4b4b; font-weight: bold; }
    .alert-medium   { color: #ffa500; font-weight: bold; }
    .alert-critical { color: #ff00ff; font-weight: bold; }
    .alert-low      { color: #00cc66; }
    h1, h2, h3 { color: #1D9E75 !important; }
</style>
""", unsafe_allow_html=True)

# ── Paths ─────────────────────────────────────────────
PROJECT_DIR  = "/Users/keshavagrawal/Desktop/TRAFFIC ANALYZER"
PACKETS_CSV  = PROJECT_DIR + "/packets.csv"
ALERTS_LOG   = PROJECT_DIR + "/alerts.log"
MAP_HTML     = PROJECT_DIR + "/map.html"

# ── Header ────────────────────────────────────────────
st.markdown("# 🛡️ NetGuard — Intelligent Network Analyser")
st.markdown("*Real-time packet capture, attack detection, and traffic analysis*")
st.markdown("---")

# ── Check if data exists ──────────────────────────────
if not os.path.exists(PACKETS_CSV):
    st.error("⚠️ No data found! Run this first in your terminal:")
    st.code("sudopy netguard.py")
    st.info("Then come back here — the dashboard will update automatically.")
    st.stop()

# ── Load data ─────────────────────────────────────────
@st.cache_data(ttl=5)   # refresh every 5 seconds
def load_data():
    try:
        df = pd.read_csv(PACKETS_CSV)
        return df
    except:
        return pd.DataFrame()

@st.cache_data(ttl=5)
def load_alerts():
    try:
        with open(ALERTS_LOG, "r") as f:
            return f.readlines()
    except:
        return []

df      = load_data()
alerts  = load_alerts()

if len(df) == 0:
    st.warning("Waiting for packets... Make sure netguard.py is running.")
    st.stop()

# ── Threat score calculation ──────────────────────────
threat_score = len(alerts) * 10
if threat_score >= 70:
    threat_level = "HIGH"
    threat_color = "#ff4b4b"
elif threat_score >= 30:
    threat_level = "MEDIUM"
    threat_color = "#ffa500"
else:
    threat_level = "LOW"
    threat_color = "#1D9E75"

# ── Row 1 — Key metrics ───────────────────────────────
st.markdown("### 📊 Live Statistics")
col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.metric("Total Packets",   f"{len(df):,}")
with col2:
    st.metric("Alerts Fired",    len(alerts))
with col3:
    st.metric("Threat Level",    threat_level)
with col4:
    unique_ips = df["src_ip"].nunique()
    st.metric("Unique IPs",      unique_ips)
with col5:
    countries = df[df["country"] != "local"]["country"].nunique() if "country" in df.columns else 0
    st.metric("Countries",       countries)

st.markdown("---")

# ── Row 2 — Bandwidth graph ───────────────────────────
st.markdown("### 📈 Real-time Bandwidth")

try:
    df2 = df.copy()
    df2["timestamp"] = pd.to_datetime(df2["timestamp"], unit="s")
    df2 = df2.set_index("timestamp")
    bw  = df2["size"].resample("1s").sum() / 1024

    fig, ax = plt.subplots(figsize=(14, 3))
    fig.patch.set_facecolor('#0e1117')
    ax.set_facecolor('#1e2130')
    ax.plot(bw.index, bw.values, color="#1D9E75", linewidth=2)
    ax.fill_between(bw.index, bw.values, alpha=0.3, color="#1D9E75")
    ax.set_ylabel("KB/s", color="#888")
    ax.set_xlabel("Time", color="#888")
    ax.tick_params(colors="#888")
    ax.spines['bottom'].set_color('#2d3250')
    ax.spines['left'].set_color('#2d3250')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.grid(True, alpha=0.1, color="#444")
    fig.tight_layout()
    st.pyplot(fig)
    plt.close(fig)
except Exception as e:
    st.error(f"Bandwidth graph error: {e}")

st.markdown("---")

# ── Row 3 — Protocol + Traffic type ───────────────────
col_left, col_right = st.columns(2)

with col_left:
    st.markdown("### 🔵 Protocol Distribution")
    try:
        proto = df["protocol"].value_counts()
        fig, ax = plt.subplots(figsize=(5, 4))
        fig.patch.set_facecolor('#0e1117')
        ax.set_facecolor('#0e1117')
        ax.pie(
            proto.values,
            labels=proto.index,
            autopct="%1.1f%%",
            colors=["#1D9E75","#7F77DD","#D85A30"],
            textprops={"color":"white"}
        )
        ax.set_title("TCP vs UDP vs OTHER", color="#888")
        fig.tight_layout()
        st.pyplot(fig)
        plt.close(fig)
    except Exception as e:
        st.error(f"Protocol chart error: {e}")

with col_right:
    st.markdown("### 🏷️ Traffic Classification")
    try:
        if "traffic_type" in df.columns:
            tc = df["traffic_type"].value_counts()
            cm = {"streaming":"#D85A30","browsing":"#1D9E75",
                  "dns":"#7F77DD","ssh":"#FAC775","control":"#888780",
                  "voip_video":"#534AB7","remote_desktop":"#993C1D",
                  "other":"#B4B2A9"}
            fig, ax = plt.subplots(figsize=(5, 4))
            fig.patch.set_facecolor('#0e1117')
            ax.set_facecolor('#1e2130')
            bars = ax.bar(tc.index, tc.values,
                          color=[cm.get(t,"#888") for t in tc.index])
            ax.set_ylabel("Packets", color="#888")
            ax.tick_params(colors="#888", axis='y')
            ax.tick_params(colors="#888", axis='x', rotation=30)
            ax.spines['bottom'].set_color('#2d3250')
            ax.spines['left'].set_color('#2d3250')
            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)
            fig.tight_layout()
            st.pyplot(fig)
            plt.close(fig)
        else:
            st.info("Run netguard.py (Stage 6+) for traffic classification")
    except Exception as e:
        st.error(f"Traffic type error: {e}")

st.markdown("---")

# ── Row 4 — Top IPs + Top Ports ───────────────────────
col_l, col_r = st.columns(2)

with col_l:
    st.markdown("### 🖥️ Top 10 Source IPs")
    try:
        top_ips = df["src_ip"].value_counts().head(10).reset_index()
        top_ips.columns = ["IP Address", "Packets"]
        st.dataframe(top_ips, use_container_width=True, hide_index=True)
    except Exception as e:
        st.error(f"Top IPs error: {e}")

with col_r:
    st.markdown("### 🔌 Top 10 Destination Ports")
    try:
        pnames = {443:"HTTPS",80:"HTTP",53:"DNS",22:"SSH",21:"FTP",
                  3389:"RDP",8080:"HTTP-Alt",1900:"SSDP",5353:"mDNS"}
        top_ports = df["dst_port"].value_counts().head(10).reset_index()
        top_ports.columns = ["Port", "Packets"]
        top_ports["Service"] = top_ports["Port"].apply(
            lambda p: pnames.get(int(p), "Unknown")
        )
        st.dataframe(top_ports, use_container_width=True, hide_index=True)
    except Exception as e:
        st.error(f"Top ports error: {e}")

st.markdown("---")

# ── Row 5 — Countries ─────────────────────────────────
if "country" in df.columns:
    st.markdown("### 🌍 Top Countries")
    try:
        countries = df[df["country"] != "local"]["country"] \
                      .value_counts().head(10).reset_index()
        countries.columns = ["Country", "Packets"]
        if len(countries) > 0:
            fig, ax = plt.subplots(figsize=(14, 3))
            fig.patch.set_facecolor('#0e1117')
            ax.set_facecolor('#1e2130')
            ax.barh(countries["Country"], countries["Packets"],
                    color="#1D9E75")
            ax.set_xlabel("Packets", color="#888")
            ax.tick_params(colors="#888")
            ax.spines['bottom'].set_color('#2d3250')
            ax.spines['left'].set_color('#2d3250')
            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)
            ax.invert_yaxis()
            fig.tight_layout()
            st.pyplot(fig)
            plt.close(fig)
    except Exception as e:
        st.error(f"Countries error: {e}")
    st.markdown("---")

# ── Row 6 — Alert feed ────────────────────────────────
st.markdown("### 🚨 Alert Feed")

if not alerts:
    st.success("✅ No alerts — network looks clean!")
else:
    st.warning(f"⚠️ {len(alerts)} alerts detected!")
    for line in reversed(alerts[-20:]):
        line = line.strip()
        if not line:
            continue
        if "CRITICAL" in line:
            st.markdown(f'<p class="alert-critical">🔴 {line}</p>',
                        unsafe_allow_html=True)
        elif "HIGH" in line:
            st.markdown(f'<p class="alert-high">🟠 {line}</p>',
                        unsafe_allow_html=True)
        elif "MEDIUM" in line:
            st.markdown(f'<p class="alert-medium">🟡 {line}</p>',
                        unsafe_allow_html=True)
        else:
            st.markdown(f'<p class="alert-low">🟢 {line}</p>',
                        unsafe_allow_html=True)

st.markdown("---")

# ── Row 7 — World map link ────────────────────────────
st.markdown("### 🗺️ World Map")
if os.path.exists(MAP_HTML):
    st.success("✅ World map is ready!")
    st.markdown(f"[🌍 Open Interactive World Map]({MAP_HTML})")

    # Show map inline using iframe
    with open(MAP_HTML, "r") as f:
        map_html = f.read()
    st.components.v1.html(map_html, height=400)
else:
    st.info("Run netguard.py and press Ctrl+C to generate the world map")

st.markdown("---")

# ── Footer + auto refresh ─────────────────────────────
st.markdown(
    f"<p style='color:#444;text-align:center'>"
    f"Last updated: {datetime.now().strftime('%H:%M:%S')} | "
    f"Auto-refreshes every 5 seconds"
    f"</p>",
    unsafe_allow_html=True
)

# Auto refresh every 5 seconds
time.sleep(5)
st.rerun()