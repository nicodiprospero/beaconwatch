"""
mitre_mapper.py
---------------
Standalone module (also importable).
  - Maps executed commands to ATT&CK techniques in real-time
  - Renders a colour heatmap to the terminal
  - Serves /mitre endpoint for the dashboard (if run as __main__)
  - Provides hardening recommendations ranked by observed frequency

Run standalone: python mitre_mapper.py
Import:         from mitre_mapper import map_command, get_heatmap_data
"""

import json
import os
import sqlite3
import datetime
import time
import sys
import threading

# -----------------------------------------------------------------------
# Full ATT&CK technique registry used in this lab
# -----------------------------------------------------------------------
TECHNIQUES = {
    "T1033":  {"name": "System Owner/User Discovery",         "tactic": "Discovery",          "risk": 2, "color": 2},
    "T1082":  {"name": "System Information Discovery",         "tactic": "Discovery",          "risk": 2, "color": 2},
    "T1016":  {"name": "System Network Config Discovery",      "tactic": "Discovery",          "risk": 2, "color": 2},
    "T1049":  {"name": "System Network Connections Discovery", "tactic": "Discovery",          "risk": 3, "color": 3},
    "T1087":  {"name": "Account Discovery",                    "tactic": "Discovery",          "risk": 3, "color": 3},
    "T1069":  {"name": "Permission Groups Discovery",          "tactic": "Discovery",          "risk": 3, "color": 3},
    "T1057":  {"name": "Process Discovery",                    "tactic": "Discovery",          "risk": 2, "color": 2},
    "T1007":  {"name": "System Service Discovery",             "tactic": "Discovery",          "risk": 2, "color": 2},
    "T1083":  {"name": "File and Directory Discovery",         "tactic": "Discovery",          "risk": 2, "color": 2},
    "T1012":  {"name": "Query Registry",                       "tactic": "Discovery",          "risk": 3, "color": 3},
    "T1053":  {"name": "Scheduled Task/Job",                   "tactic": "Persistence",        "risk": 4, "color": 4},
    "T1135":  {"name": "Network Share Discovery",              "tactic": "Discovery",          "risk": 3, "color": 3},
    "T1018":  {"name": "Remote System Discovery",              "tactic": "Discovery",          "risk": 3, "color": 3},
    "T1555":  {"name": "Credentials from Password Stores",     "tactic": "Credential Access",  "risk": 5, "color": 5},
}

COMMAND_MAP = {
    "whoami":             "T1033",
    "systeminfo":         "T1082",
    "hostname":           "T1082",
    "ipconfig":           "T1016",
    "netstat":            "T1049",
    "arp":                "T1016",
    "net user":           "T1087",
    "net localgroup":     "T1069",
    "tasklist":           "T1057",
    "sc query":           "T1007",
    "dir":                "T1083",
    "reg query":          "T1012",
    "schtasks":           "T1053",
    "wmic":               "T1082",
    "cmdkey":             "T1555",
    "net share":          "T1135",
    "ping":               "T1018",
    "nslookup":           "T1018",
}

HARDENING = {
    "T1033": "Alert on whoami from non-interactive shells (Sysmon EID 1, parent != explorer/cmd user session).",
    "T1082": "Restrict systeminfo/wmic to admin context; alert on bulk invocations within a short window.",
    "T1016": "Baseline expected network config tools; alert on ipconfig in scripted/non-user context.",
    "T1049": "Correlate netstat runs with active suspicious processes; alert on automated connection enumeration.",
    "T1087": "Enable EID 4798/4799 (local group membership enumeration); restrict net commands in non-admin shells.",
    "T1069": "Alert on group discovery commands run by non-admin accounts or from scripted execution chains.",
    "T1057": "Flag tasklist executions spawned from PowerShell, cmd, or wscript with no user interaction.",
    "T1007": "sc.exe invocations from non-service contexts should be rare — alert and investigate.",
    "T1083": "High-frequency file access events (Sysmon EID 11) across multiple directories in short windows = flag.",
    "T1012": "Enable registry auditing (EID 4656); alert on reg.exe invocations targeting sensitive Run keys.",
    "T1053": "Alert on schtasks /create from non-admin or scripted context; audit Task Scheduler EID 4698.",
    "T1135": "net share queries from non-admin accounts or from lateral-movement-associated processes = alert.",
    "T1018": "ICMP sweep or repeated nslookup from a single host in a short window = classic recon signal.",
    "T1555": "Deploy Windows Credential Guard; audit DPAPI blob access (EID 4693); alert on cmdkey usage.",
}

DB_PATH = os.path.join(os.path.dirname(__file__), "listener_state.db")

# -----------------------------------------------------------------------
# Core mapping functions
# -----------------------------------------------------------------------
def map_command(cmd: str) -> dict:
    """Map a command string to its ATT&CK technique. Returns enriched dict."""
    cl = cmd.lower()
    for kw, tid in COMMAND_MAP.items():
        if kw in cl:
            meta = TECHNIQUES[tid].copy()
            meta["tid"] = tid
            meta["matched_keyword"] = kw
            meta["command"] = cmd
            return meta
    return {
        "tid": None,
        "name": "Uncategorized",
        "tactic": "Unknown",
        "risk": 1,
        "command": cmd,
        "matched_keyword": None,
    }

def get_observed_counts() -> dict:
    """Pull per-technique hit counts from DB. Returns {tid: count}."""
    if not os.path.exists(DB_PATH):
        return {}
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT technique FROM events WHERE type='task_sent' AND technique IS NOT NULL"
    ).fetchall()
    conn.close()
    counts = {}
    for (tech,) in rows:
        if not tech:
            continue
        tid = tech.split(" - ")[0].split(".")[0].strip()
        counts[tid] = counts.get(tid, 0) + 1
    return counts

def get_heatmap_data() -> list:
    """
    Returns list of dicts for dashboard heatmap rendering:
    [{tid, name, tactic, risk, count, heat (0-5)}, ...]
    """
    counts = get_observed_counts()
    max_count = max(counts.values(), default=1)
    out = []
    for tid, meta in TECHNIQUES.items():
        count = counts.get(tid, 0)
        heat = round((count / max_count) * 5) if max_count > 0 else 0
        out.append({
            "tid":    tid,
            "name":   meta["name"],
            "tactic": meta["tactic"],
            "risk":   meta["risk"],
            "count":  count,
            "heat":   heat,
            "hardening": HARDENING.get(tid, ""),
        })
    out.sort(key=lambda x: (-x["count"], x["tid"]))
    return out

# -----------------------------------------------------------------------
# Terminal heatmap renderer
# -----------------------------------------------------------------------
# ANSI colours: grey=37, yellow=33, orange=93, red=31, bright_red=91, white=97
HEAT_COLORS = {0: "\033[90m", 1: "\033[37m", 2: "\033[33m", 3: "\033[93m", 4: "\033[31m", 5: "\033[91m"}
RESET = "\033[0m"
BOLD  = "\033[1m"

def render_terminal_heatmap(data):
    by_tactic = {}
    for item in data:
        by_tactic.setdefault(item["tactic"], []).append(item)

    print(f"\n{BOLD}  BEACONWATCH // MITRE ATT&CK HEATMAP{RESET}")
    print(f"  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Heat: {HEAT_COLORS[0]}■{RESET}=0  {HEAT_COLORS[2]}■{RESET}=2  {HEAT_COLORS[3]}■{RESET}=3  {HEAT_COLORS[4]}■{RESET}=4  {HEAT_COLORS[5]}■{RESET}=5+")
    print()

    for tactic, items in sorted(by_tactic.items()):
        print(f"  {BOLD}{tactic.upper()}{RESET}")
        for item in items:
            color = HEAT_COLORS.get(item["heat"], HEAT_COLORS[0])
            bar = "█" * item["count"] if item["count"] > 0 else "·"
            print(f"    {color}{item['tid']:<10} {item['name']:<45} {item['count']:>3}x  {bar}{RESET}")
        print()

def render_hardening(data):
    observed = [d for d in data if d["count"] > 0]
    if not observed:
        print("  No techniques observed yet.")
        return
    print(f"\n{BOLD}  HARDENING RECOMMENDATIONS (by observation frequency){RESET}\n")
    for item in sorted(observed, key=lambda x: -x["count"]):
        print(f"  [{item['tid']}] {BOLD}{item['name']}{RESET} — observed {item['count']}x")
        print(f"    {item['hardening']}\n")

# -----------------------------------------------------------------------
# Flask endpoint (optional — bolt onto listener if run standalone)
# -----------------------------------------------------------------------
def register_routes(app):
    """Call this from listener.py to add /mitre endpoint."""
    from flask import jsonify as _jsonify
    @app.route("/mitre", methods=["GET"])
    def mitre_endpoint():
        return _jsonify(get_heatmap_data())

# -----------------------------------------------------------------------
# Entry point
# -----------------------------------------------------------------------
def main():
    import argparse
    parser = argparse.ArgumentParser(description="MITRE ATT&CK Mapper")
    parser.add_argument("--harden", action="store_true", help="Print hardening recs")
    parser.add_argument("--watch",  action="store_true", help="Auto-refresh every 10s")
    parser.add_argument("--json",   action="store_true", help="Output raw JSON")
    args = parser.parse_args()

    def run_once():
        data = get_heatmap_data()
        if args.json:
            print(json.dumps(data, indent=2))
        else:
            render_terminal_heatmap(data)
            if args.harden:
                render_hardening(data)

    if args.watch:
        while True:
            os.system("cls" if sys.platform == "win32" else "clear")
            run_once()
            print("  [watch mode] Refreshing in 10s — Ctrl+C to stop")
            time.sleep(10)
    else:
        run_once()

if __name__ == "__main__":
    main()