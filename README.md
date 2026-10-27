<div align="center">

# BeaconWatch

**Purple-team telemetry dashboard: turns the event log of an authorized adversary-emulation exercise into ATT&CK coverage, beacon-timing analysis, risk scoring and concrete detection recommendations.**

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-API%20%2B%20dashboard-000000?logo=flask)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-C8102E)
![STIX](https://img.shields.io/badge/STIX-2.1%20export-2E7D32)
![License](https://img.shields.io/badge/license-MIT-blue)

</div>

---

## Why

A red-team exercise only pays off if the blue team learns what it would have looked like from the defender's chair. BeaconWatch reads the SQLite event log written during a lab exercise and answers the questions a SOC analyst would ask:

- **What did the operator do?** Every logged command is mapped to a MITRE ATT&CK technique and tactic.
- **How noisy was it?** Check-in interval statistics and **jitter %**: a near-constant interval is trivial to catch with timing analysis.
- **How bad was it?** Per-technique and overall risk score, anomaly flags and YARA hits.
- **How do we catch it next time?** Technique-specific hardening and detection advice (Sysmon event IDs, Windows audit events, Credential Guard...), ranked by how often each technique was observed.
- **How do we share it?** One-click **STIX 2.1** bundle for SIEM/TIP ingestion, plus JSON and text reports.

## Features

| Area | What it does |
|---|---|
| ATT&CK mapping | `mitre_mapper.py` maps commands (`whoami`, `systeminfo`, `net user`, `schtasks`, `cmdkey`...) to technique IDs, renders a terminal heatmap and serves `/mitre` |
| Timing analysis | mean / median / stdev of result latency; beacon interval and jitter % |
| Risk scoring | technique base risk × frequency, capped 0–100 overall score |
| Detection advice | per-technique recommendations ranked by observed frequency (`--harden`) |
| Exports | STIX 2.1 bundle (`--stix`, `/api/export/stix`), JSON, text report |
| Dashboard | Flask app with live cache refresh, timeline, tactic breakdown, top techniques |

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python seed_demo.py           # synthetic demo data -> listener_state.db
python app.py                 # http://127.0.0.1:5000
```

CLI reports without the web UI:

```bash
python data_collector.py --report     # full console report
python data_collector.py --harden     # detection / hardening recommendations
python data_collector.py --stix       # writes stix_export.json
python data_collector.py --watch      # refresh every 15 s
python mitre_mapper.py                # live ATT&CK heatmap in the terminal
```

## API

`/api/dashboard` · `/api/events` · `/api/mitre` · `/api/summary` · `/api/timeline` · `/api/tactics` · `/api/risk` · `/api/hardening` · `/api/stats` · `/api/top` · `/api/live` · `/api/export/json` · `/api/export/stix` · `/api/export/report` · `/health`

## Event log schema

BeaconWatch only **reads** a SQLite table named `events` (`listener_state.db`):

| Column | Meaning |
|---|---|
| `type` | `checkin`, `task_sent` or `result_received` |
| `time` | ISO-8601 timestamp |
| `task` | command text that was logged |
| `technique` / `tactic` / `risk` | e.g. `T1082 - System Information Discovery`, `Discovery`, `2` |
| `duration_ms`, `task_time`, `result_time` | latency between task and result |
| `yara_hits` | JSON array of rule names |
| `anomaly` | 0 / 1 |

`seed_demo.py` creates this table with clearly synthetic data, so the project runs without any live exercise.

## Scope

Built for **authorized lab exercises** in my cybersecurity course at FIAP. This repo contains the analysis and detection side only.

---

<sub>Built by **Nicolas Di Prospero** · [github.com/nicodiprospero](https://github.com/nicodiprospero)</sub>
