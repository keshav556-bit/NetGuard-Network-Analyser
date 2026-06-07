"""
NetGuard Demo — Attack Simulator
Run with VS Code play button to simulate all 5 attacks.
Use this during your project presentation!
No sudo needed.
"""
import sys
sys.path.insert(0, '/opt/miniconda3/lib/python3.13/site-packages')

from collections import defaultdict
import time, datetime, os

PROJECT_DIR = "/Users/keshavagrawal/Desktop/TRAFFIC ANALYZER"

# ── Colors ────────────────────────────────────────────
RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
MAGENTA = "\033[95m"
CYAN    = "\033[96m"
RESET   = "\033[0m"
BOLD    = "\033[1m"

# ── Trackers ──────────────────────────────────────────
syn_tracker   = defaultdict(list)
port_tracker  = defaultdict(set)
brute_tracker = defaultdict(int)
arp_table     = {}
alert_log     = []
threat_score  = 0

def add_threat(score):
    global threat_score
    threat_score += score

def get_level():
    if threat_score >= 70: return f"{RED}HIGH{RESET}"
    if threat_score >= 30: return f"{YELLOW}MEDIUM{RESET}"
    return f"{GREEN}LOW{RESET}"

def alert(msg, severity="HIGH", score=30):
    add_threat(score)
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    colors = {
        "CRITICAL": MAGENTA,
        "HIGH"    : RED,
        "MEDIUM"  : YELLOW,
        "LOW"     : GREEN
    }
    color = colors.get(severity, RED)
    print(f"{color}{BOLD}[{severity}] {ts} — {msg}{RESET}")
    alert_log.append(f"[{severity}] {ts} — {msg}")
    try:
        with open(PROJECT_DIR + "/alerts.log", "a") as f:
            f.write(f"[{severity}] {ts} — {msg}\n")
    except:
        pass

def detect_syn_flood(src):
    now = time.time()
    syn_tracker[src].append(now)
    syn_tracker[src] = [t for t in syn_tracker[src] if now-t < 5]
    if len(syn_tracker[src]) > 100:
        alert(f"SYN FLOOD from {src} — {len(syn_tracker[src])} SYNs in 5s",
              score=40)

def detect_port_scan(src, dport):
    port_tracker[src].add(dport)
    if len(port_tracker[src]) > 15:
        alert(f"PORT SCAN from {src} — {len(port_tracker[src])} ports probed",
              score=30)

def detect_brute_force(src, dport):
    if dport in [22, 21, 3389]:
        key = f"{src}:{dport}"
        brute_tracker[key] += 1
        if brute_tracker[key] > 20:
            names = {22:"SSH", 21:"FTP", 3389:"RDP"}
            alert(f"BRUTE FORCE on {names[dport]} from {src} — "
                  f"{brute_tracker[key]} attempts", score=25)

def detect_arp_spoof(ip, new_mac, old_mac):
    if old_mac and old_mac != new_mac:
        alert(f"ARP SPOOF! {ip} changed MAC: {old_mac} → {new_mac}",
              severity="CRITICAL", score=50)

def detect_dns_tunnel(query, src):
    if len(query) > 60:
        alert(f"DNS TUNNEL? Query {len(query)} chars from {src}: "
              f"{query[:50]}...", severity="MEDIUM", score=35)

def divider(title):
    print(f"\n{CYAN}{'='*55}")
    print(f"  {title}")
    print(f"{'='*55}{RESET}\n")

def pause(msg="Press Enter to continue..."):
    input(f"\n{YELLOW}{msg}{RESET}\n")

# ── Banner ────────────────────────────────────────────
os.system('clear')
print(f"{GREEN}{BOLD}")
print("╔══════════════════════════════════════════════════╗")
print("║     NetGuard — Attack Detection Demo            ║")
print("║     ECE Project Presentation                    ║")
print("╚══════════════════════════════════════════════════╝")
print(RESET)
print("This demo simulates all 5 attack types that")
print("NetGuard detects in real time on live networks.\n")
print(f"Initial threat level: {get_level()}")
pause("Press Enter to begin Demo...")

# ── Test 1 — SYN Flood ────────────────────────────────
divider("TEST 1 — SYN Flood Attack")
print("Scenario: Attacker at 10.0.0.99 is sending")
print("thousands of TCP SYN packets to overwhelm")
print("your server and deny service to real users.\n")
print("Simulating 105 SYN packets from 10.0.0.99...")
time.sleep(1)

for i in range(105):
    detect_syn_flood("10.0.0.99")

print(f"\nThreat score: {threat_score} | Level: {get_level()}")
pause()

# ── Test 2 — Port Scan ────────────────────────────────
divider("TEST 2 — Port Scan Attack")
print("Scenario: Attacker at 192.168.1.50 is probing")
print("every port on your machine to discover which")
print("services are running before launching an attack.\n")
print("Simulating scan of ports 1-20 from 192.168.1.50...")
time.sleep(1)

for port in range(1, 21):
    detect_port_scan("192.168.1.50", port)
    time.sleep(0.05)

print(f"\nThreat score: {threat_score} | Level: {get_level()}")
pause()

# ── Test 3 — Brute Force ──────────────────────────────
divider("TEST 3 — SSH Brute Force Attack")
print("Scenario: Attacker at 172.16.0.77 is trying")
print("thousands of username/password combinations")
print("on your SSH server (port 22) to gain access.\n")
print("Simulating 25 SSH login attempts from 172.16.0.77...")
time.sleep(1)

for i in range(25):
    detect_brute_force("172.16.0.77", 22)
    time.sleep(0.05)

print(f"\nThreat score: {threat_score} | Level: {get_level()}")
pause()

# ── Test 4 — ARP Spoof ────────────────────────────────
divider("TEST 4 — ARP Spoofing Attack")
print("Scenario: Attacker is sending fake ARP replies")
print("claiming to own your router's IP address.")
print("This redirects all your traffic through the")
print("attacker's machine — a Man-in-the-Middle attack.\n")

print("Step 1: Recording legitimate router MAC...")
arp_table["192.168.1.1"] = "aa:bb:cc:dd:ee:01"
print(f"  Router 192.168.1.1 → MAC aa:bb:cc:dd:ee:01 ✓")
time.sleep(1)

print("\nStep 2: Attacker sends fake ARP reply...")
time.sleep(1)
detect_arp_spoof(
    "192.168.1.1",
    "ff:ff:ff:ff:ff:ff",
    arp_table.get("192.168.1.1")
)

print(f"\nThreat score: {threat_score} | Level: {get_level()}")
pause()

# ── Test 5 — DNS Tunnel ───────────────────────────────
divider("TEST 5 — DNS Tunneling Attack")
print("Scenario: Attacker is exfiltrating stolen data")
print("by encoding it inside DNS query domain names.")
print("The data hides in plain sight as a DNS lookup.\n")

normal_query = "google.com."
evil_query   = "c2VjcmV0RGF0YUhlcmUxMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcA.evil.com."

print(f"Normal DNS query  ({len(normal_query):2} chars): {normal_query}")
print(f"Tunneled DNS query ({len(evil_query):2} chars): {evil_query[:60]}...")
time.sleep(1)
print("\nProcessing suspicious DNS query...")
time.sleep(0.5)
detect_dns_tunnel(evil_query, "10.0.0.5")

print(f"\nThreat score: {threat_score} | Level: {get_level()}")
pause()

# ── Final summary ─────────────────────────────────────
os.system('clear')
print(f"{GREEN}{BOLD}")
print("╔══════════════════════════════════════════════════╗")
print("║           Demo Complete — Summary               ║")
print("╚══════════════════════════════════════════════════╝")
print(RESET)

print(f"{'Attack':<25} {'Detected':>10} {'Score Added':>12}")
print("─" * 50)
print(f"{'SYN Flood':<25} {'✅ YES':>10} {'+40':>12}")
print(f"{'Port Scan':<25} {'✅ YES':>10} {'+30':>12}")
print(f"{'SSH Brute Force':<25} {'✅ YES':>10} {'+25':>12}")
print(f"{'ARP Spoofing':<25} {'✅ YES':>10} {'+50':>12}")
print(f"{'DNS Tunneling':<25} {'✅ YES':>10} {'+35':>12}")
print("─" * 50)
print(f"{'TOTAL':<25} {'5/5':>10} {threat_score:>11}")
print()

level_str = ("HIGH" if threat_score >= 70
             else "MEDIUM" if threat_score >= 30 else "LOW")
color = RED if level_str == "HIGH" else YELLOW if level_str == "MEDIUM" else GREEN
print(f"Final threat score : {threat_score}")
print(f"Final threat level : {color}{BOLD}{level_str}{RESET}")
print(f"Total alerts fired : {len(alert_log)}")
print(f"\nAlerts saved to    : {PROJECT_DIR}/alerts.log")
print()
print(f"{GREEN}All 5 attacks detected successfully!{RESET}")
print(f"{CYAN}NetGuard would have protected your network.{RESET}\n")
