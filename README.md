# 🛡 SOC SIEM Dashboard

A lightweight Security Information and Event Management (SIEM) system built from scratch. Ingests logs, correlates events using sliding-window detection rules, fires alerts, and displays everything on a live web dashboard.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue) ![Flask](https://img.shields.io/badge/Flask-2.x-lightgrey) ![SOC](https://img.shields.io/badge/Topic-SOC%20%2F%20SIEM-blue)

---

## Features

- **6 correlation rules** (sliding-window detection):
  - SSH Brute Force (≥5 fails in 60s from same IP)
  - Port Scan (≥10 probes in 30s)
  - Privilege Escalation (repeated sudo/su/setuid attempts)
  - Data Exfiltration (multiple large outbound transfers)
  - Impossible Travel (same user, different IP, within 5 min)
  - C2 Beacon Detection (regular-interval outbound connections)
- **Multi-format log ingestion** — Apache/Nginx, SSH auth.log, iptables firewall logs
- **Live web dashboard** — real-time event stream + alert panel, auto-refreshes every 2s
- **CLI mode** — ingest files, demo mode, or live-tail a file
- **JSON export** — machine-readable report of all events and alerts

---

## Project Structure

```
01_siem_dashboard/
├── siem_engine.py    # Core: event model, correlation rules, log parsers
├── dashboard.py      # Flask web dashboard (live UI)
├── requirements.txt
└── README.md
```

---

## Quick Start

```bash
pip install flask

# Run simulated attack scenario (CLI)
python siem_engine.py --demo

# Live web dashboard with simulated feed
python dashboard.py
# Open http://localhost:5000

# Ingest real log files
python siem_engine.py --logs /var/log/auth.log /var/log/apache2/access.log

# Live-tail a log file
python siem_engine.py --watch /var/log/auth.log

# Export JSON report
python siem_engine.py --demo --json report.json
```

---

## How Correlation Rules Work

Rules use a **sliding time window** pattern:

```
Event arrives
    │
    ▼
Push into deque for (rule_key)
Trim events older than window_secs
    │
    ▼
Count ≥ threshold?  ──YES──► Fire Alert (with 60s cooldown)
    │
    NO
    ▼
  (wait)
```

For example, the SSH Brute Force rule:
- Key = `ssh_brute:{src_ip}` (one window per attacker IP)
- Window = 60 seconds
- Threshold = 5 failed logins
- Cooldown = 60 seconds (suppresses alert spam)

---

## Sample Alert Output

```
🚨 [14:23:11] ALERT [HIGH]: SSH Brute Force — 6 failed SSH logins from 45.33.32.156 in 60s
🚨 [14:23:14] ALERT [MEDIUM]: Port Scan Detected — 12 connection probes from 198.51.100.7 in 30s
🚨 [14:23:19] ALERT [CRITICAL]: Potential Data Exfiltration — Multiple large outbound transfers from 10.0.0.5
```

---

## Skills Demonstrated

| Skill | Where |
|---|---|
| SIEM architecture (ingest → correlate → alert) | `siem_engine.py` overall |
| Sliding-window detection rules | `RuleEngine` class |
| Multi-source log parsing (SSH, Apache, firewall) | `parse_log_line()` |
| Threat detection logic | 6 rules in `RuleEngine` |
| Real-time web dashboard | `dashboard.py` |
| IOC extraction | Each alert's `iocs` field |
| SOC alert triage workflow | Alert model + status field |

---

## Disclaimer

For educational use only. Only run against systems and log files you own or have permission to monitor.
