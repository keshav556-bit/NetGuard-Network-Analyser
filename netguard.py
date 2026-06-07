"""
NetGuard — Intelligent Network Traffic Analyser & IDS
Version: 1.0
Author: Keshav Agrawal
Institution: Jaypee Institute of Information Technology
Subject: Telecommunication Networks / Digital Communication

Run: sudopy netguard.py
"""

"""
NetGuard - Complete Network Analyser
Run: sudopy netguard.py
Press Ctrl+C to stop
"""
import os, sys, signal, threading, time, datetime

sys.path.insert(0, '/opt/miniconda3/lib/python3.13/site-packages')
os.environ['MPLCONFIGDIR'] = '/tmp'

PROJECT_DIR = "/Users/keshavagrawal/Desktop/TRAFFIC ANALYZER"

if os.geteuid() != 0:
    print("ERROR: Run with sudopy!")
    sys.exit(1)

# Stop flag
stop_flag = threading.Event()
def signal_handler(sig, frame):
    stop_flag.set()
signal.signal(signal.SIGINT, signal_handler)

# Imports
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import folium
import geoip2.database
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, ARP
from collections import defaultdict, Counter

# GeoIP
try:
    geo_reader  = geoip2.database.Reader(PROJECT_DIR + "/GeoLite2-City.mmdb")
    GEO_ENABLED = True
except:
    GEO_ENABLED = False

# Storage
rows = []; alert_log = []; geo_data = []
lock = threading.Lock()
threat_score = 0

def add_threat(s):
    global threat_score
    threat_score += s

def get_level():
    if threat_score >= 70: return ("HIGH",   "\033[91m")
    if threat_score >= 30: return ("MEDIUM", "\033[93m")
    return                        ("LOW",    "\033[92m")

def alert(msg, severity="HIGH", score=30):
    add_threat(score)
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    _, color = get_level()
    print(f"{color}[{severity}] {ts} — {msg}\033[0m")
    with lock:
        alert_log.append({"time":ts,"severity":severity,"message":msg,"score":threat_score})
    with open(PROJECT_DIR + "/alerts.log", "a") as f:
        f.write(f"[{severity}] {ts} — {msg}\n")

# Trackers
syn_tracker   = defaultdict(list)
port_tracker  = defaultdict(set)
brute_tracker = defaultdict(int)
arp_table     = {}

def detect_syn_flood(src):
    now = time.time()
    syn_tracker[src].append(now)
    syn_tracker[src] = [t for t in syn_tracker[src] if now-t < 5]
    if len(syn_tracker[src]) > 100:
        alert(f"SYN FLOOD from {src} — {len(syn_tracker[src])} SYNs in 5s", score=40)

def detect_port_scan(src, dport):
    port_tracker[src].add(dport)
    if len(port_tracker[src]) > 15:
        alert(f"PORT SCAN from {src} — {len(port_tracker[src])} ports", score=30)

def detect_brute_force(src, dport):
    if dport in [22,21,3389,5900,23]:
        key = f"{src}:{dport}"
        brute_tracker[key] += 1
        if brute_tracker[key] > 20:
            names = {22:"SSH",21:"FTP",3389:"RDP",5900:"VNC",23:"Telnet"}
            alert(f"BRUTE FORCE on {names.get(dport,str(dport))} from {src}", score=25)

def detect_arp_spoof(packet):
    if packet[ARP].op != 2: return
    ip = packet[ARP].psrc; mac = packet[ARP].hwsrc
    if ip in arp_table and arp_table[ip] != mac:
        alert(f"ARP SPOOF! {ip} MAC changed: {arp_table[ip]} → {mac}", severity="CRITICAL", score=50)
    else:
        arp_table[ip] = mac

def detect_dns_tunnel(packet, src):
    try:
        q = packet[DNSQR].qname.decode()
        if len(q) > 60:
            alert(f"DNS TUNNEL? {len(q)} chars from {src}", severity="MEDIUM", score=35)
    except: pass

def get_location(ip):
    if any(ip.startswith(r) for r in ["192.168.","10.","172.16.","127.","0.","169."]):
        return None
    if not GEO_ENABLED: return None
    try:
        r = geo_reader.city(ip)
        if not r.location.latitude: return None
        return {"ip":ip,"country":r.country.name or "Unknown",
                "city":r.city.name or "Unknown",
                "lat":r.location.latitude,"lon":r.location.longitude}
    except: return None

def classify(size, dport, proto):
    if dport in [443,80] and size > 900: return "streaming"
    if dport == 53:                       return "dns"
    if dport == 22:                       return "ssh"
    if dport in [3389,5900]:             return "remote_desktop"
    if size < 100:                        return "control"
    if proto == "TCP":                    return "browsing"
    if proto == "UDP" and size > 500:     return "voip_video"
    return "other"

def handle_packet(packet):
    if IP in packet:
        src   = packet[IP].src
        dst   = packet[IP].dst
        size  = len(packet)
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "OTHER"
        dport = (packet[TCP].dport if TCP in packet else
                 packet[UDP].dport if UDP in packet else 0)
        ttype    = classify(size, dport, proto)
        location = get_location(dst)
        if location:
            with lock: geo_data.append(location)
        with lock:
            rows.append({"timestamp":time.time(),"src_ip":src,"dst_ip":dst,
                         "protocol":proto,"size":size,"dst_port":dport,
                         "traffic_type":ttype,
                         "country":location["country"] if location else "local"})
        if TCP in packet:
            flags = packet[TCP].flags
            if flags == 0x002: detect_syn_flood(src)
            detect_port_scan(src, dport)
            detect_brute_force(src, dport)
        elif UDP in packet:
            if DNS in packet and DNSQR in packet:
                detect_dns_tunnel(packet, src)
    if ARP in packet:
        detect_arp_spoof(packet)

def make_graphs(df):
    print("\nGenerating graphs...")

    try:
        df2 = df.copy()
        df2["timestamp"] = pd.to_datetime(df2["timestamp"], unit="s")
        df2 = df2.set_index("timestamp")
        bw  = df2["size"].resample("1s").sum() / 1024
        fig, ax = plt.subplots(figsize=(12,4))
        ax.plot(bw.index, bw.values, color="#1D9E75", linewidth=2)
        ax.fill_between(bw.index, bw.values, alpha=0.2, color="#1D9E75")
        ax.set_title("Bandwidth KB/s"); ax.set_ylabel("KB/s"); ax.grid(True, alpha=0.3)
        fig.tight_layout()
        p = PROJECT_DIR + "/graph1_bandwidth.png"
        fig.savefig(p, dpi=150); plt.close(fig)
        os.system(f"open '{p}'"); print("  ✓ graph1_bandwidth.png")
    except Exception as e: print(f"  ✗ Graph 1: {e}")

    try:
        proto = df["protocol"].value_counts()
        fig, ax = plt.subplots(figsize=(6,6))
        ax.pie(proto.values, labels=proto.index, autopct="%1.1f%%",
               colors=["#1D9E75","#7F77DD","#D85A30"])
        ax.set_title("Protocol Distribution")
        fig.tight_layout()
        p = PROJECT_DIR + "/graph2_protocols.png"
        fig.savefig(p, dpi=150); plt.close(fig)
        os.system(f"open '{p}'"); print("  ✓ graph2_protocols.png")
    except Exception as e: print(f"  ✗ Graph 2: {e}")

    try:
        top_ips = df["src_ip"].value_counts().head(10)
        fig, ax = plt.subplots(figsize=(10,5))
        ax.barh(top_ips.index, top_ips.values, color="#534AB7")
        ax.set_title("Top 10 Source IPs"); ax.set_xlabel("Packets"); ax.invert_yaxis()
        fig.tight_layout()
        p = PROJECT_DIR + "/graph3_top_ips.png"
        fig.savefig(p, dpi=150); plt.close(fig)
        os.system(f"open '{p}'"); print("  ✓ graph3_top_ips.png")
    except Exception as e: print(f"  ✗ Graph 3: {e}")

    try:
        tp = df["dst_port"].value_counts().head(10)
        pn = {443:"HTTPS",80:"HTTP",53:"DNS",22:"SSH",21:"FTP",
              3389:"RDP",8080:"HTTP-Alt",1900:"SSDP",5353:"mDNS"}
        labels = [f"{int(p)} ({pn.get(int(p),str(int(p)))})" for p in tp.index]
        fig, ax = plt.subplots(figsize=(10,5))
        ax.barh(labels, tp.values, color="#D85A30")
        ax.set_title("Top 10 Ports"); ax.set_xlabel("Packets"); ax.invert_yaxis()
        fig.tight_layout()
        p = PROJECT_DIR + "/graph4_top_ports.png"
        fig.savefig(p, dpi=150); plt.close(fig)
        os.system(f"open '{p}'"); print("  ✓ graph4_top_ports.png")
    except Exception as e: print(f"  ✗ Graph 4: {e}")

    try:
        tc = df["traffic_type"].value_counts()
        cm = {"streaming":"#D85A30","browsing":"#1D9E75","dns":"#7F77DD",
              "ssh":"#FAC775","control":"#888780","voip_video":"#534AB7",
              "remote_desktop":"#993C1D","other":"#B4B2A9"}
        fig, ax = plt.subplots(figsize=(10,5))
        ax.bar(tc.index, tc.values, color=[cm.get(t,"#888") for t in tc.index])
        ax.set_title("Traffic Types"); ax.set_xlabel("Type"); ax.set_ylabel("Packets")
        fig.tight_layout()
        p = PROJECT_DIR + "/graph5_traffic_types.png"
        fig.savefig(p, dpi=150); plt.close(fig)
        os.system(f"open '{p}'"); print("  ✓ graph5_traffic_types.png")
    except Exception as e: print(f"  ✗ Graph 5: {e}")

    try:
        c = df[df["country"] != "local"]["country"].value_counts().head(10)
        if len(c) > 0:
            fig, ax = plt.subplots(figsize=(10,5))
            ax.barh(c.index, c.values, color="#1D9E75")
            ax.set_title("Top Countries"); ax.set_xlabel("Packets"); ax.invert_yaxis()
            fig.tight_layout()
            p = PROJECT_DIR + "/graph6_countries.png"
            fig.savefig(p, dpi=150); plt.close(fig)
            os.system(f"open '{p}'"); print("  ✓ graph6_countries.png")
    except Exception as e: print(f"  ✗ Graph 6: {e}")

def make_map(geo_data):
    print("\nGenerating map...")
    try:
        lc = Counter((d["country"],d["city"],d["lat"],d["lon"])
                     for d in geo_data if d["lat"] and d["lon"])
        if not lc: print("  ✗ No locations"); return
        m = folium.Map(location=[20,0], zoom_start=2, tiles="CartoDB dark_matter")
        for (country,city,lat,lon), count in lc.items():
            folium.CircleMarker(
                location=[lat,lon], radius=min(5+count*0.5,30),
                color="#1D9E75", fill=True, fill_color="#1D9E75", fill_opacity=0.7,
                popup=folium.Popup(f"<b>{city},{country}</b><br>Packets:{count}", max_width=200),
                tooltip=f"{city},{country} — {count} packets"
            ).add_to(m)
        mp = PROJECT_DIR + "/map.html"
        m.save(mp); os.system(f"open '{mp}'")
        print(f"  ✓ map.html — {len(lc)} locations")
    except Exception as e: print(f"  ✗ Map: {e}")

def status_thread():
    while not stop_flag.is_set():
        time.sleep(10)
        _, color = get_level()
        with lock: pkts=len(rows); alts=len(alert_log); locs=len(geo_data)
        print(f"\n{color}── {pkts} pkts | {alts} alerts | {locs} geo | score:{threat_score} ──\033[0m\n")

def autosave_thread():
    while not stop_flag.is_set():
        time.sleep(5)
        with lock:
            if rows: pd.DataFrame(rows).to_csv(PROJECT_DIR+"/packets.csv", index=False)
        print("  [saved]")

threading.Thread(target=status_thread,  daemon=True).start()
threading.Thread(target=autosave_thread, daemon=True).start()

print("\033[92m"+"="*50)
print("     NetGuard — Network Analyser")
print("="*50+"\033[0m")
print(f"  GeoIP : {'ON' if GEO_ENABLED else 'OFF'}")
print(f"  Folder: {PROJECT_DIR}")
print("\n  Capturing... Press Ctrl+C to stop\n")

sniff(prn=handle_packet, store=False, iface="en0",
      stop_filter=lambda p: stop_flag.is_set())

print("\nStopped. Saving and generating output...")
time.sleep(1)

df = pd.DataFrame(rows)
if len(df) == 0:
    print("No packets captured!"); sys.exit(0)

df.to_csv(PROJECT_DIR + "/packets.csv", index=False)
print(f"Saved {len(df)} packets")

if alert_log:
    pd.DataFrame(alert_log).to_csv(PROJECT_DIR + "/alerts.csv", index=False)

make_graphs(df)
make_map(geo_data) if geo_data else print("No public IPs for map")

level, color = get_level()
print(f"\n{color}{'='*40}")
print(f"  Packets : {len(df)}")
print(f"  Alerts  : {len(alert_log)}")
print(f"  Threat  : {threat_score} ({level})")
print(f"  Geo     : {len(set(d['country'] for d in geo_data))} countries")
print(f"{'='*40}\033[0m")

print("\nTraffic breakdown:")
for t, c in df["traffic_type"].value_counts().items():
    pct = c/len(df)*100
    print(f"  {t:20} {'█'*int(pct/5):20} {c:5} ({pct:.1f}%)")

print(f"\n✓ Done! Check your TRAFFIC ANALYZER folder.")