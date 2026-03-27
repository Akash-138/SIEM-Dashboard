"""
SOC SIEM Dashboard — Event Collector, Correlator & Alert Engine
Simulates a lightweight SIEM: ingests logs, correlates events, fires alerts.
Usage: python siem_engine.py --help
"""

import re
import json
import time
import random
import threading
import argparse
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path


# ── Event model ───────────────────────────────────────────────────────────────

SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")

class Event:
    def __init__(self, source, event_type, src_ip, dest_ip, user,
                 message, severity="INFO", raw=""):
        self.id        = f"EVT-{int(time.time()*1000) % 10**9}"
        self.timestamp = datetime.now()
        self.source    = source       # e.g. "firewall", "ssh", "web"
        self.type      = event_type   # e.g. "AUTH_FAIL", "PORT_SCAN"
        self.src_ip    = src_ip
        self.dest_ip   = dest_ip
        self.user      = user
        self.message   = message
        self.severity  = severity
        self.raw       = raw

    def to_dict(self):
        return {
            "id":        self.id,
            "timestamp": self.timestamp.isoformat(),
            "source":    self.source,
            "type":      self.type,
            "src_ip":    self.src_ip,
            "dest_ip":   self.dest_ip,
            "user":      self.user,
            "message":   self.message,
            "severity":  self.severity,
        }

    def __repr__(self):
        ts = self.timestamp.strftime("%H:%M:%S")
        return f"[{ts}] [{self.severity:<8}] {self.source:<12} {self.type:<22} {self.src_ip}"


# ── Alert model ───────────────────────────────────────────────────────────────

class Alert:
    def __init__(self, rule_name, severity, description, events, iocs):
        self.id          = f"ALT-{int(time.time()*1000) % 10**9}"
        self.timestamp   = datetime.now()
        self.rule        = rule_name
        self.severity    = severity
        self.description = description
        self.events      = events      # list of Event objects
        self.iocs        = iocs        # {"ips": [...], "users": [...]}
        self.status      = "OPEN"      # OPEN / IN_PROGRESS / CLOSED
        self.analyst     = None

    def to_dict(self):
        return {
            "id":          self.id,
            "timestamp":   self.timestamp.isoformat(),
            "rule":        self.rule,
            "severity":    self.severity,
            "description": self.description,
            "event_count": len(self.events),
            "iocs":        self.iocs,
            "status":      self.status,
        }


# ── Correlation rules ─────────────────────────────────────────────────────────

class RuleEngine:
    """
    Each rule is a sliding-window detector.
    Rules fire when threshold events match within the time window.
    """

    def __init__(self, alert_callback):
        self.cb       = alert_callback
        self._windows = defaultdict(lambda: deque())  # rule_key → deque of Events
        self._fired   = defaultdict(float)            # rule_key → last fire time (avoid spam)
        self.COOLDOWN = 60   # seconds between repeated alerts for same key

    def _window_push(self, key: str, event: Event, window_secs: int, limit: int):
        """Push event, trim old entries, return list if threshold reached."""
        dq = self._windows[key]
        dq.append(event)
        cutoff = datetime.now() - timedelta(seconds=window_secs)
        while dq and dq[0].timestamp < cutoff:
            dq.popleft()
        if len(dq) >= limit:
            now = time.time()
            if now - self._fired.get(key, 0) > self.COOLDOWN:
                self._fired[key] = now
                return list(dq)
        return []

    def evaluate(self, event: Event):
        """Run all rules against the incoming event."""
        self._rule_ssh_brute(event)
        self._rule_port_scan(event)
        self._rule_privilege_escalation(event)
        self._rule_data_exfiltration(event)
        self._rule_impossible_travel(event)
        self._rule_c2_beacon(event)

    # ── Rule 1: SSH Brute Force ───────────────────────────────────────────────
    def _rule_ssh_brute(self, event: Event):
        if event.type != "AUTH_FAIL" or event.source != "ssh":
            return
        key = f"ssh_brute:{event.src_ip}"
        hits = self._window_push(key, event, window_secs=60, limit=5)
        if hits:
            users = list({e.user for e in hits})
            self.cb(Alert(
                rule_name   = "SSH Brute Force",
                severity    = "HIGH",
                description = f"{len(hits)} failed SSH logins from {event.src_ip} in 60s",
                events      = hits,
                iocs        = {"ips": [event.src_ip], "users": users},
            ))

    # ── Rule 2: Port Scan ────────────────────────────────────────────────────
    def _rule_port_scan(self, event: Event):
        if event.type != "CONNECTION_REFUSED" and event.type != "PORT_PROBE":
            return
        key = f"portscan:{event.src_ip}"
        hits = self._window_push(key, event, window_secs=30, limit=10)
        if hits:
            self.cb(Alert(
                rule_name   = "Port Scan Detected",
                severity    = "MEDIUM",
                description = f"{len(hits)} connection probes from {event.src_ip} in 30s",
                events      = hits,
                iocs        = {"ips": [event.src_ip], "users": []},
            ))

    # ── Rule 3: Privilege Escalation ─────────────────────────────────────────
    def _rule_privilege_escalation(self, event: Event):
        if event.type not in ("SUDO_FAIL", "SU_ATTEMPT", "SETUID_EXEC"):
            return
        key = f"privesc:{event.src_ip}:{event.user}"
        hits = self._window_push(key, event, window_secs=300, limit=3)
        if hits:
            self.cb(Alert(
                rule_name   = "Privilege Escalation Attempt",
                severity    = "HIGH",
                description = f"User {event.user} attempted privilege escalation {len(hits)}x in 5 min",
                events      = hits,
                iocs        = {"ips": [event.src_ip], "users": [event.user]},
            ))

    # ── Rule 4: Data Exfiltration (large outbound) ────────────────────────────
    def _rule_data_exfiltration(self, event: Event):
        if event.type != "LARGE_TRANSFER_OUT":
            return
        key = f"exfil:{event.src_ip}"
        hits = self._window_push(key, event, window_secs=600, limit=3)
        if hits:
            self.cb(Alert(
                rule_name   = "Potential Data Exfiltration",
                severity    = "CRITICAL",
                description = f"Multiple large outbound transfers from {event.src_ip}",
                events      = hits,
                iocs        = {"ips": [event.src_ip], "users": [event.user]},
            ))

    # ── Rule 5: Impossible Travel (same user, two distant IPs fast) ───────────
    _last_seen: dict = {}

    def _rule_impossible_travel(self, event: Event):
        if event.type != "AUTH_SUCCESS" or not event.user:
            return
        key = event.user
        prev = self._last_seen.get(key)
        now = (event.src_ip, event.timestamp)
        self._last_seen[key] = now
        if prev and prev[0] != event.src_ip:
            delta = (event.timestamp - prev[1]).total_seconds()
            if delta < 300:  # same user, different IP, within 5 min
                self.cb(Alert(
                    rule_name   = "Impossible Travel",
                    severity    = "HIGH",
                    description = f"User {event.user} logged in from {prev[0]} then {event.src_ip} within {int(delta)}s",
                    events      = [event],
                    iocs        = {"ips": [prev[0], event.src_ip], "users": [event.user]},
                ))

    # ── Rule 6: C2 Beacon (regular interval connections) ──────────────────────
    def _rule_c2_beacon(self, event: Event):
        if event.type != "OUTBOUND_CONNECTION":
            return
        key = f"beacon:{event.src_ip}:{event.dest_ip}"
        dq = self._windows[key]
        dq.append(event)
        cutoff = datetime.now() - timedelta(seconds=600)
        while dq and dq[0].timestamp < cutoff:
            dq.popleft()
        if len(dq) >= 6:
            # Check if intervals are suspiciously regular (±10%)
            times = [e.timestamp.timestamp() for e in dq]
            intervals = [times[i+1]-times[i] for i in range(len(times)-1)]
            if intervals:
                avg = sum(intervals) / len(intervals)
                deviation = max(abs(iv - avg) / avg for iv in intervals) if avg > 0 else 1
                if deviation < 0.15 and 10 < 60:
                    now = time.time()
                    if now - self._fired.get(key, 0) > self.COOLDOWN:
                        self._fired[key] = now
                        self.cb(Alert(
                            rule_name   = "C2 Beacon Behavior",
                            severity    = "CRITICAL",
                            description = f"Regular interval connections from {event.src_ip} → {event.dest_ip} (possible C2)",
                            events      = list(dq),
                            iocs        = {"ips": [event.src_ip, event.dest_ip], "users": []},
                        ))


# ── Log ingestors ──────────────────────────────────────────────────────────────

# Apache / Nginx combined log
APACHE_RE = re.compile(
    r'(?P<ip>\S+).*\[.*\]\s+"(?P<method>\S+)\s+(?P<path>\S+).*"\s+(?P<status>\d{3})'
)
# SSH auth log lines
SSH_FAIL_RE    = re.compile(r'Failed \w+ for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)')
SSH_SUCCESS_RE = re.compile(r'Accepted \w+ for (?P<user>\S+) from (?P<ip>\S+)')
# Firewall (iptables style)
FW_RE = re.compile(r'SRC=(?P<src>\S+)\s+DST=(?P<dst>\S+).*DPT=(?P<dpt>\d+).*(?P<action>ACCEPT|DROP|REJECT)')


def parse_log_line(line: str, source_hint: str = "auto") -> Event | None:
    line = line.strip()
    if not line:
        return None

    # SSH
    if m := SSH_FAIL_RE.search(line):
        return Event("ssh", "AUTH_FAIL", m.group('ip'), "", m.group('user'),
                     f"Failed login for {m.group('user')}", "MEDIUM", line)
    if m := SSH_SUCCESS_RE.search(line):
        return Event("ssh", "AUTH_SUCCESS", m.group('ip'), "", m.group('user'),
                     f"Successful login for {m.group('user')}", "INFO", line)

    # Apache / web
    if m := APACHE_RE.match(line):
        status = int(m.group('status'))
        sev = "HIGH" if status >= 500 else "MEDIUM" if status >= 400 else "INFO"
        etype = "WEB_ERROR" if status >= 400 else "WEB_REQUEST"
        return Event("web", etype, m.group('ip'), "", "",
                     f"{m.group('method')} {m.group('path')} → {status}", sev, line)

    # Firewall
    if m := FW_RE.search(line):
        sev = "LOW" if m.group('action') == "ACCEPT" else "MEDIUM"
        etype = "FW_ALLOW" if m.group('action') == "ACCEPT" else "FW_BLOCK"
        return Event("firewall", etype, m.group('src'), m.group('dst'), "",
                     f"{m.group('action')} {m.group('src')}:{m.group('dpt')}", sev, line)

    return None


def ingest_file(filepath: str, engine: RuleEngine, store: list):
    with open(filepath, 'r', errors='ignore') as f:
        for line in f:
            ev = parse_log_line(line)
            if ev:
                store.append(ev)
                engine.evaluate(ev)


# ── Live event simulator ──────────────────────────────────────────────────────

ATTACKER_IPS = ["45.33.32.156", "198.51.100.7", "203.0.113.99"]
INTERNAL_IPS = ["192.168.1.10", "192.168.1.20", "10.0.0.5"]
USERS        = ["alice", "bob", "admin", "root", "svcaccount"]

def simulate_events(engine: RuleEngine, store: list, count: int = 200):
    """Generate realistic SOC event stream with embedded attack patterns."""
    event_types = [
        # Normal traffic (weight 60%)
        *[("ssh",      "AUTH_SUCCESS",      "INFO"  )] * 20,
        *[("web",      "WEB_REQUEST",       "INFO"  )] * 20,
        *[("firewall", "FW_ALLOW",          "LOW"   )] * 20,
        # Attacks (weight 40%)
        *[("ssh",      "AUTH_FAIL",         "MEDIUM")] * 15,
        *[("firewall", "PORT_PROBE",        "MEDIUM")] * 10,
        *[("system",   "SUDO_FAIL",         "HIGH"  )] * 5,
        *[("network",  "LARGE_TRANSFER_OUT","HIGH"  )] * 5,
        *[("network",  "OUTBOUND_CONNECTION","LOW"  )] * 5,
    ]

    for i in range(count):
        src, etype, sev = random.choice(event_types)
        src_ip  = random.choice(ATTACKER_IPS if "FAIL" in etype or "PROBE" in etype else INTERNAL_IPS)
        user    = random.choice(USERS)
        dest_ip = random.choice(INTERNAL_IPS)

        ev = Event(src, etype, src_ip, dest_ip, user,
                   f"Simulated {etype} event #{i}", sev)
        store.append(ev)
        engine.evaluate(ev)
        time.sleep(0.01)  # 10ms between events


# ── Reports ───────────────────────────────────────────────────────────────────

SEV_COLOR = {
    "INFO":     "\033[37m",
    "LOW":      "\033[36m",
    "MEDIUM":   "\033[33m",
    "HIGH":     "\033[31m",
    "CRITICAL": "\033[1;31m",
}
RESET = "\033[0m"


def print_summary(events: list, alerts: list):
    print("\n" + "═" * 68)
    print("  SOC SIEM SUMMARY REPORT")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("═" * 68)
    print(f"\n  Total Events : {len(events):,}")

    from collections import Counter
    by_sev = Counter(e.severity for e in events)
    for sev in SEVERITIES:
        if by_sev[sev]:
            col = SEV_COLOR.get(sev, "")
            print(f"  {col}{sev:<10}{RESET} {by_sev[sev]:>6,}")

    print(f"\n  Total Alerts : {len(alerts)}")
    by_rule = Counter(a.rule for a in alerts)
    for rule, cnt in by_rule.most_common():
        print(f"    {cnt:>3}x  {rule}")

    if alerts:
        print(f"\n  {'─' * 66}")
        print(f"  ALERT DETAILS")
        print(f"  {'─' * 66}")
        for a in sorted(alerts, key=lambda x: SEVERITIES.index(x.severity), reverse=True):
            col = SEV_COLOR.get(a.severity, "")
            ts  = a.timestamp.strftime("%H:%M:%S")
            print(f"\n  [{ts}] {col}[{a.severity}]{RESET}  {a.rule}")
            print(f"  Description : {a.description}")
            if a.iocs.get("ips"):
                print(f"  IOC IPs     : {', '.join(a.iocs['ips'])}")
            if a.iocs.get("users"):
                print(f"  IOC Users   : {', '.join(a.iocs['users'])}")
            print(f"  Events      : {len(a.events)} correlated")
    print("\n" + "═" * 68 + "\n")


def export_json_report(events, alerts, path):
    data = {
        "generated": datetime.now().isoformat(),
        "event_count": len(events),
        "alert_count": len(alerts),
        "events": [e.to_dict() for e in events[-100:]],
        "alerts": [a.to_dict() for a in alerts],
    }
    with open(path, 'w') as f:
        json.dump(data, f, indent=2, default=str)
    print(f"  JSON report → {path}")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SOC SIEM Engine")
    parser.add_argument("--logs",   nargs="+", help="Log files to ingest")
    parser.add_argument("--demo",   action="store_true", help="Run simulated attack scenario")
    parser.add_argument("--json",   metavar="OUT",       help="Export JSON report")
    parser.add_argument("--watch",  metavar="FILE",      help="Live-tail a log file")
    args = parser.parse_args()

    events: list[Event] = []
    alerts: list[Alert] = []

    def on_alert(alert: Alert):
        alerts.append(alert)
        col = SEV_COLOR.get(alert.severity, "")
        ts  = alert.timestamp.strftime("%H:%M:%S")
        print(f"  🚨 [{ts}] {col}ALERT [{alert.severity}]{RESET}: {alert.rule} — {alert.description}")

    engine = RuleEngine(alert_callback=on_alert)

    if args.demo:
        print("\n📡 SOC SIEM Engine — Demo Mode")
        print("   Simulating 200 events with embedded attack patterns...\n")
        simulate_events(engine, events, count=200)
        print_summary(events, alerts)

    elif args.logs:
        print(f"\n📋 Ingesting {len(args.logs)} log file(s)...")
        for lf in args.logs:
            print(f"  → {lf}")
            ingest_file(lf, engine, events)
        print_summary(events, alerts)

    elif args.watch:
        print(f"\n👁 Live-tailing: {args.watch}  (Ctrl+C to stop)\n")
        with open(args.watch, 'r') as f:
            f.seek(0, 2)   # seek to end
            try:
                while True:
                    line = f.readline()
                    if line:
                        ev = parse_log_line(line)
                        if ev:
                            events.append(ev)
                            engine.evaluate(ev)
                            col = SEV_COLOR.get(ev.severity, "")
                            print(f"  {col}{ev}{RESET}")
                    else:
                        time.sleep(0.1)
            except KeyboardInterrupt:
                print("\n\nStopped.")
                print_summary(events, alerts)

    else:
        parser.print_help()

    if args.json and events:
        export_json_report(events, alerts, args.json)


if __name__ == "__main__":
    main()
