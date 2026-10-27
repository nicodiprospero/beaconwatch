"""
data_collector.py
-----------------
Reads listener_state.db and produces:
  - Execution pattern analysis
  - Statistical report (console + JSON)
  - STIX 2.1 bundle export for SIEM ingestion

Run: python data_collector.py [--stix] [--report] [--watch]
"""

import sqlite3
import json
import os
import sys
import datetime
import statistics
import argparse
import time
import uuid

DB_PATH = os.path.join(os.path.dirname(__file__), "listener_state.db")

# -----------------------------------------------------------------------
# MITRE ATT&CK technique metadata (for enriched reporting)
# -----------------------------------------------------------------------
TECHNIQUE_META = {
    "T1033": {"name": "System Owner/User Discovery", "tactic": "Discovery",  "risk": 2},
    "T1082": {"name": "System Information Discovery",  "tactic": "Discovery",  "risk": 2},
    "T1016": {"name": "System Network Config Discovery","tactic": "Discovery",  "risk": 2},
    "T1049": {"name": "System Network Connections Discovery","tactic":"Discovery","risk": 3},
    "T1087": {"name": "Account Discovery",             "tactic": "Discovery",  "risk": 3},
    "T1069": {"name": "Permission Groups Discovery",   "tactic": "Discovery",  "risk": 3},
    "T1057": {"name": "Process Discovery",             "tactic": "Discovery",  "risk": 2},
    "T1007": {"name": "System Service Discovery",      "tactic": "Discovery",  "risk": 2},
    "T1083": {"name": "File and Directory Discovery",  "tactic": "Discovery",  "risk": 2},
    "T1012": {"name": "Query Registry",                "tactic": "Discovery",  "risk": 3},
    "T1053": {"name": "Scheduled Task/Job",            "tactic": "Persistence","risk": 4},
    "T1135": {"name": "Network Share Discovery",       "tactic": "Discovery",  "risk": 3},
    "T1018": {"name": "Remote System Discovery",       "tactic": "Discovery",  "risk": 3},
    "T1555": {"name": "Credentials from Password Stores","tactic":"Credential Access","risk":5},
}

def get_tid(technique_str):
    """Extract TID from 'T1082 - System Information Discovery' style strings."""
    if not technique_str:
        return None
    parts = technique_str.split(" - ")
    return parts[0].strip().split(".")[0] if parts else None

# -----------------------------------------------------------------------
# Data loading
# -----------------------------------------------------------------------
def load_events():
    if not os.path.exists(DB_PATH):
        print(f"[!] DB not found at {DB_PATH} — is listener.py running and has it received events?")
        return []
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM events ORDER BY id ASC").fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["yara_hits"] = json.loads(d.get("yara_hits") or "[]")
        d["anomaly"] = bool(d.get("anomaly"))
        result.append(d)
    return result

# -----------------------------------------------------------------------
# Pattern analysis
# -----------------------------------------------------------------------
def analyze(events):
    tasks   = [e for e in events if e["type"] == "task_sent"]
    results = [e for e in events if e["type"] == "result_received"]
    checkins= [e for e in events if e["type"] == "checkin"]

    # Technique frequency
    tech_counts = {}
    for t in tasks:
        tech = t.get("technique") or "Uncategorized"
        tech_counts[tech] = tech_counts.get(tech, 0) + 1

    # Risk scoring per technique
    risk_scores = {}
    for tech, count in tech_counts.items():
        tid = get_tid(tech)
        meta = TECHNIQUE_META.get(tid, {})
        base_risk = meta.get("risk", 1)
        risk_scores[tech] = base_risk * count

    overall_risk = min(100, sum(risk_scores.values()) * 2) if risk_scores else 0

    # Timing analysis
    durations = [e["duration_ms"] for e in results if e["duration_ms"] is not None]
    timing = {}
    if durations:
        timing = {
            "count": len(durations),
            "mean_ms": round(statistics.mean(durations), 1),
            "median_ms": round(statistics.median(durations), 1),
            "stdev_ms": round(statistics.stdev(durations), 1) if len(durations) > 1 else 0,
            "min_ms": min(durations),
            "max_ms": max(durations),
        }

    # Beacon interval analysis
    checkin_times = []
    for e in events:
        if e["type"] in ("checkin", "task_sent"):
            try:
                checkin_times.append(datetime.datetime.fromisoformat(e["time"]))
            except Exception:
                pass
    intervals = []
    if len(checkin_times) > 1:
        checkin_times.sort()
        intervals = [(checkin_times[i] - checkin_times[i-1]).total_seconds()
                     for i in range(1, len(checkin_times))]

    beacon_stats = {}
    if intervals:
        beacon_stats = {
            "sample_count": len(intervals),
            "mean_interval_s": round(statistics.mean(intervals), 1),
            "stdev_s": round(statistics.stdev(intervals), 1) if len(intervals) > 1 else 0,
            "min_s": round(min(intervals), 1),
            "max_s": round(max(intervals), 1),
            "jitter_pct": round(
                (statistics.stdev(intervals) / statistics.mean(intervals) * 100)
                if len(intervals) > 1 and statistics.mean(intervals) > 0 else 0, 1
            ),
        }

    # Anomalies
    anomalies = [e for e in events if e.get("anomaly")]
    yara_events= [e for e in events if e.get("yara_hits")]

    # Tactic distribution
    tactic_dist = {}
    for tech, count in tech_counts.items():
        tid = get_tid(tech)
        meta = TECHNIQUE_META.get(tid, {})
        tactic = meta.get("tactic", "Unknown")
        tactic_dist[tactic] = tactic_dist.get(tactic, 0) + count

    # Execution timeline (task + result pairs)
    timeline = []
    task_queue = []
    for e in events:
        if e["type"] == "task_sent":
            task_queue.append(e)
        elif e["type"] == "result_received" and task_queue:
            t = task_queue.pop(0)
            timeline.append({
                "task": t.get("task"),
                "technique": t.get("technique"),
                "task_time": t.get("time"),
                "result_time": e.get("time"),
                "duration_ms": e.get("duration_ms"),
                "anomaly": e.get("anomaly"),
                "yara_hits": e.get("yara_hits", []),
            })

    return {
        "summary": {
            "total_events": len(events),
            "total_tasks": len(tasks),
            "total_results": len(results),
            "total_checkins": len(checkins),
            "anomalies": len(anomalies),
            "yara_hits_total": len(yara_events),
            "overall_risk_score": overall_risk,
            "overall_risk_label": risk_label(overall_risk),
        },
        "technique_counts": tech_counts,
        "risk_scores": risk_scores,
        "tactic_distribution": tactic_dist,
        "timing": timing,
        "beacon_stats": beacon_stats,
        "timeline": timeline,
        "anomaly_events": anomalies,
    }

def risk_label(score):
    if score == 0:   return "NONE"
    if score < 20:   return "LOW"
    if score < 50:   return "MEDIUM"
    if score < 80:   return "HIGH"
    return "CRITICAL"

# -----------------------------------------------------------------------
# Console report
# -----------------------------------------------------------------------
def print_report(analysis):
    s = analysis["summary"]
    sep = "=" * 60
    print(f"\n{sep}")
    print("  BEACONWATCH // EXECUTION REPORT")
    print(f"  Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(sep)

    print(f"\n  SUMMARY")
    print(f"    Total events      : {s['total_events']}")
    print(f"    Tasks sent        : {s['total_tasks']}")
    print(f"    Results received  : {s['total_results']}")
    print(f"    Check-ins (idle)  : {s['total_checkins']}")
    print(f"    Anomalies flagged : {s['anomalies']}")
    print(f"    YARA hits         : {s['yara_hits_total']}")
    print(f"    Risk Score        : {s['overall_risk_score']}/100 [{s['overall_risk_label']}]")

    if analysis["technique_counts"]:
        print(f"\n  TECHNIQUE FREQUENCY")
        for tech, count in sorted(analysis["technique_counts"].items(), key=lambda x: -x[1]):
            tid = get_tid(tech)
            meta = TECHNIQUE_META.get(tid, {})
            risk = meta.get("risk", 1)
            bar = "█" * count
            print(f"    [{risk}/5] {tech:<45} {count:>3}x  {bar}")

    if analysis["tactic_distribution"]:
        print(f"\n  TACTIC DISTRIBUTION")
        for tactic, count in sorted(analysis["tactic_distribution"].items(), key=lambda x: -x[1]):
            print(f"    {tactic:<30} {count} technique executions")

    if analysis["timing"]:
        t = analysis["timing"]
        print(f"\n  EXECUTION TIMING")
        print(f"    Mean duration    : {t['mean_ms']}ms")
        print(f"    Median           : {t['median_ms']}ms")
        print(f"    Std deviation    : {t['stdev_ms']}ms")
        print(f"    Min / Max        : {t['min_ms']}ms / {t['max_ms']}ms")

    if analysis["beacon_stats"]:
        b = analysis["beacon_stats"]
        print(f"\n  BEACON INTERVAL ANALYSIS")
        print(f"    Mean interval    : {b['mean_interval_s']}s")
        print(f"    Jitter           : {b['jitter_pct']}%  (stdev {b['stdev_s']}s)")
        print(f"    Min / Max        : {b['min_s']}s / {b['max_s']}s")
        if b["jitter_pct"] < 5:
            print(f"    [!] Very low jitter — trivial to detect as beaconing via timing analysis")

    if analysis["anomaly_events"]:
        print(f"\n  ANOMALOUS EVENTS")
        for e in analysis["anomaly_events"]:
            hits = ", ".join(e.get("yara_hits", [])) or "timing anomaly"
            print(f"    [{e['time'][:19]}] type={e['type']} hits={hits}")

    print(f"\n{sep}\n")

# -----------------------------------------------------------------------
# Hardening recommendations (based on what techniques were observed)
# -----------------------------------------------------------------------
HARDENING = {
    "T1033": "Restrict access to whoami/user-enumeration via AppLocker or SRP; alert on unexpected user-discovery commands in Sysmon Event ID 1.",
    "T1082": "Limit systeminfo/wmic output to privileged users; monitor for bulk system info queries in short windows.",
    "T1016": "Alert on ipconfig/netstat executions by non-admin processes; network config shouldn't change frequently.",
    "T1049": "Baseline known outbound connections; alert on new persistent connections from non-browser processes.",
    "T1087": "Restrict net user/net group commands; alert on account enumeration (Sysmon EID 4798/4799).",
    "T1069": "Alert on group-membership queries (EID 4799); restrict to admin context only.",
    "T1057": "Tasklist via shell is a red flag post-compromise; detect child processes spawned from suspicious parents.",
    "T1007": "sc query in a scripting context is unusual; alert on service enumeration from non-admin shells.",
    "T1083": "Mass dir traversal is detectable via Sysmon EID 11 (FileCreate/Access) bursts; set volume thresholds.",
    "T1012": "Registry queries from non-standard processes should alert; audit reg query via EID 4656.",
    "T1053": "Enable Sysmon EID 1 filtering for schtasks; alert on scheduled task creation/modification.",
    "T1135": "net share enumeration should fire alerts in any post-compromise context.",
    "T1018": "Remote system discovery (ping sweeps, nslookup) in bursts should trigger network-based detections.",
    "T1555": "Enable Windows Credential Guard; audit DPAPI access via EID 4693.",
}

def print_hardening(analysis):
    seen_tids = set()
    for tech in analysis["technique_counts"]:
        tid = get_tid(tech)
        if tid and tid in HARDENING and tid not in seen_tids:
            seen_tids.add(tid)
            print(f"  [{tid}] {HARDENING[tid]}\n")

# -----------------------------------------------------------------------
# STIX 2.1 export
# -----------------------------------------------------------------------
def export_stix(analysis, events):
    now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    bundle_id = f"bundle--{uuid.uuid4()}"
    objects = []

    # Identity (this tool)
    identity_id = f"identity--{uuid.uuid4()}"
    objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now,
        "modified": now,
        "name": "BeaconWatch Lab",
        "identity_class": "system",
    })

    # One Attack Pattern per observed technique
    for tech, count in analysis["technique_counts"].items():
        tid = get_tid(tech)
        meta = TECHNIQUE_META.get(tid, {})
        ap = {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": f"attack-pattern--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "name": tech,
            "description": f"Observed {count} time(s) during session.",
            "external_references": [{
                "source_name": "mitre-attack",
                "external_id": tid or "unknown",
            }],
            "x_observation_count": count,
            "x_risk_score": meta.get("risk", 1),
            "x_tactic": meta.get("tactic", "Unknown"),
        }
        objects.append(ap)

    # Observed Data objects for each task+result pair
    for item in analysis["timeline"]:
        od = {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": f"observed-data--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "first_observed": item.get("task_time", now),
            "last_observed":  item.get("result_time", now),
            "number_observed": 1,
            "object_refs": [],
            "x_command": item.get("task"),
            "x_technique": item.get("technique"),
            "x_duration_ms": item.get("duration_ms"),
            "x_anomaly": item.get("anomaly", False),
            "x_yara_hits": item.get("yara_hits", []),
        }
        objects.append(od)

    # Report object wrapping everything
    report = {
        "type": "report",
        "spec_version": "2.1",
        "id": f"report--{uuid.uuid4()}",
        "created": now,
        "modified": now,
        "name": f"BeaconWatch Session Report — {now}",
        "description": (
            f"Automated C2 telemetry report. "
            f"Risk: {analysis['summary']['overall_risk_score']}/100 "
            f"({analysis['summary']['overall_risk_label']}). "
            f"{analysis['summary']['total_tasks']} commands, "
            f"{analysis['summary']['anomalies']} anomalies."
        ),
        "published": now,
        "report_types": ["attack-pattern", "observed-data"],
        "object_refs": [o["id"] for o in objects],
        "x_summary": analysis["summary"],
    }
    objects.append(report)

    bundle = {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
    }
    return bundle

# -----------------------------------------------------------------------
# Entry point
# -----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="BeaconWatch Data Collector")
    parser.add_argument("--stix",   action="store_true", help="Export STIX 2.1 bundle to stix_export.json")
    parser.add_argument("--report", action="store_true", help="Print full report (default if no flags)")
    parser.add_argument("--harden", action="store_true", help="Print hardening recommendations")
    parser.add_argument("--json",   action="store_true", help="Dump raw analysis as JSON")
    parser.add_argument("--watch",  action="store_true", help="Auto-refresh every 15s")
    args = parser.parse_args()

    if not any([args.stix, args.report, args.harden, args.json, args.watch]):
        args.report = True

    def run_once():
        events   = load_events()
        analysis = analyze(events)

        if args.report or args.watch:
            print_report(analysis)

        if args.harden:
            print("\n  HARDENING RECOMMENDATIONS (based on observed techniques)\n")
            print_hardening(analysis)

        if args.json:
            print(json.dumps(analysis, indent=2))

        if args.stix:
            bundle = export_stix(analysis, events)
            out = os.path.join(os.path.dirname(__file__), "stix_export.json")
            with open(out, "w") as f:
                json.dump(bundle, f, indent=2)
            print(f"[+] STIX 2.1 bundle written to {out}  ({len(bundle['objects'])} objects)")

    if args.watch:
        while True:
            os.system("cls" if sys.platform == "win32" else "clear")
            run_once()
            print("  [watch mode] Refreshing in 15s — Ctrl+C to stop")
            time.sleep(15)
    else:
        run_once()

if __name__ == "__main__":
    main()