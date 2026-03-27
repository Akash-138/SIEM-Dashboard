"""
SOC SIEM Web Dashboard — Flask UI
Run: python dashboard.py --demo   then open http://localhost:5000
"""

from flask import Flask, jsonify, render_template_string
from siem_engine import simulate_events, RuleEngine, Event, Alert, SEVERITIES
import threading, time, json
from collections import Counter

app = Flask(__name__)

# ── Shared state ──────────────────────────────────────────────────────────────
events: list[Event] = []
alerts: list[Alert] = []
_lock = threading.Lock()

def on_alert(a: Alert):
    with _lock:
        alerts.append(a)

engine = RuleEngine(alert_callback=on_alert)

def feed_events():
    """Background thread: continuously generate simulated events."""
    import random
    from siem_engine import ATTACKER_IPS, INTERNAL_IPS, USERS
    ET = [
        ("ssh","AUTH_SUCCESS","INFO"),("web","WEB_REQUEST","INFO"),
        ("firewall","FW_ALLOW","LOW"),("ssh","AUTH_FAIL","MEDIUM"),
        ("firewall","PORT_PROBE","MEDIUM"),("system","SUDO_FAIL","HIGH"),
        ("network","LARGE_TRANSFER_OUT","HIGH"),
    ]
    while True:
        src, etype, sev = random.choice(ET)
        src_ip = random.choice(ATTACKER_IPS if "FAIL" in etype or "PROBE" in etype else INTERNAL_IPS)
        ev = Event(src, etype, src_ip, random.choice(INTERNAL_IPS),
                   random.choice(USERS), f"{etype}", sev)
        with _lock:
            events.append(ev)
            if len(events) > 500:
                events.pop(0)
        engine.evaluate(ev)
        time.sleep(0.5)

# ── HTML template ─────────────────────────────────────────────────────────────
HTML = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><title>SOC SIEM Dashboard</title>
<style>
* { box-sizing:border-box; margin:0; padding:0; }
body { font-family:'Segoe UI',monospace; background:#0a0d14; color:#c8d0e0; font-size:13px; }
header { background:#111827; padding:12px 20px; display:flex; align-items:center; gap:16px;
  border-bottom:1px solid #1e2a3a; }
header h1 { font-size:1rem; color:#60a5fa; font-weight:600; }
.live-dot { width:8px; height:8px; border-radius:50%; background:#34d399; animation:pulse 1.5s infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.3} }
.grid { display:grid; grid-template-columns:1fr 1fr 1fr 1fr; gap:1px; background:#1e2a3a;
  border-bottom:1px solid #1e2a3a; }
.stat { background:#111827; padding:14px 18px; }
.stat-num { font-size:1.6rem; font-weight:700; }
.stat-lbl { font-size:0.72rem; color:#64748b; margin-top:2px; }
.c-info { color:#60a5fa; } .c-med { color:#f59e0b; }
.c-high { color:#ef4444; } .c-ok  { color:#34d399; }
.panels { display:grid; grid-template-columns:2fr 1fr; gap:1px; background:#1e2a3a; height:calc(100vh - 120px); }
.panel { background:#0f1623; overflow:hidden; display:flex; flex-direction:column; }
.panel-header { background:#111827; padding:8px 16px; font-size:0.75rem; color:#64748b;
  text-transform:uppercase; letter-spacing:.08em; border-bottom:1px solid #1e2a3a; flex-shrink:0; }
.panel-body { overflow-y:auto; flex:1; }
.event-row { display:flex; gap:10px; padding:5px 16px; border-bottom:1px solid #0d1420;
  font-size:0.75rem; align-items:center; }
.event-row:hover { background:#131c2e; }
.ts { color:#475569; min-width:64px; }
.badge { padding:1px 7px; border-radius:3px; font-size:0.68rem; font-weight:600; min-width:62px; text-align:center; }
.badge-INFO     { background:#1e3a5f; color:#60a5fa; }
.badge-LOW      { background:#1e3a30; color:#34d399; }
.badge-MEDIUM   { background:#3d2e0a; color:#f59e0b; }
.badge-HIGH     { background:#3d1010; color:#ef4444; }
.badge-CRITICAL { background:#5a0a0a; color:#fca5a5; font-weight:700; }
.src  { color:#7dd3fc; min-width:72px; }
.msg  { color:#94a3b8; flex:1; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.alert-row { padding:10px 16px; border-bottom:1px solid #0d1420; }
.alert-row:hover { background:#131c2e; }
.alert-title { font-size:0.8rem; font-weight:600; margin-bottom:3px; }
.alert-desc  { font-size:0.72rem; color:#64748b; }
.alert-iocs  { font-size:0.7rem; color:#475569; margin-top:3px; }
.a-HIGH     { border-left:2px solid #ef4444; }
.a-CRITICAL { border-left:2px solid #fca5a5; }
.a-MEDIUM   { border-left:2px solid #f59e0b; }
.a-LOW      { border-left:2px solid #34d399; }
</style></head><body>
<header>
  <div class="live-dot"></div>
  <h1>🛡 SOC SIEM Dashboard</h1>
  <span style="color:#475569;font-size:0.75rem">Live event stream · Auto-refreshes every 2s</span>
</header>

<div class="grid" id="stats">
  <div class="stat"><div class="stat-num c-info" id="s-total">0</div><div class="stat-lbl">Total Events</div></div>
  <div class="stat"><div class="stat-num c-high" id="s-alerts">0</div><div class="stat-lbl">Active Alerts</div></div>
  <div class="stat"><div class="stat-num c-med"  id="s-high">0</div><div class="stat-lbl">High/Critical Events</div></div>
  <div class="stat"><div class="stat-num c-ok"   id="s-eps">0</div><div class="stat-lbl">Events / sec</div></div>
</div>

<div class="panels">
  <div class="panel">
    <div class="panel-header">Event Stream (latest 80)</div>
    <div class="panel-body" id="event-list"></div>
  </div>
  <div class="panel">
    <div class="panel-header">Alerts <span id="alert-count" style="color:#ef4444"></span></div>
    <div class="panel-body" id="alert-list"></div>
  </div>
</div>

<script>
let lastTotal = 0, lastTime = Date.now();
async function refresh() {
  const [evRes, alRes] = await Promise.all([fetch('/api/events'), fetch('/api/alerts')]);
  const evData = await evRes.json();
  const alData = await alRes.json();

  document.getElementById('s-total').textContent  = evData.total.toLocaleString();
  document.getElementById('s-alerts').textContent = alData.alerts.length;
  document.getElementById('s-high').textContent   = evData.high_count;
  const now = Date.now(); const eps = Math.round((evData.total - lastTotal) / ((now-lastTime)/1000));
  document.getElementById('s-eps').textContent = isNaN(eps)||eps<0 ? '–' : eps;
  lastTotal=evData.total; lastTime=now;

  const el = document.getElementById('event-list');
  el.innerHTML = evData.events.map(e => `
    <div class="event-row">
      <span class="ts">${e.timestamp.slice(11,19)}</span>
      <span class="badge badge-${e.severity}">${e.severity}</span>
      <span class="src">${e.source}</span>
      <span class="msg">${e.src_ip}  ${e.message}</span>
    </div>`).join('');

  const al = document.getElementById('alert-list');
  document.getElementById('alert-count').textContent = alData.alerts.length ? `(${alData.alerts.length})` : '';
  al.innerHTML = alData.alerts.slice().reverse().map(a => `
    <div class="alert-row a-${a.severity}">
      <div class="alert-title"><span class="badge badge-${a.severity}">${a.severity}</span>  ${a.rule}</div>
      <div class="alert-desc">${a.description}</div>
      <div class="alert-iocs">${a.timestamp.slice(11,19)}  ·  ${a.event_count} events</div>
    </div>`).join('');
}

setInterval(refresh, 2000);
refresh();
</script></body></html>"""

@app.route('/')
def index(): return render_template_string(HTML)

@app.route('/api/events')
def api_events():
    with _lock:
        ev_list = list(events)
    high = sum(1 for e in ev_list if e.severity in ("HIGH","CRITICAL"))
    return jsonify({
        "total": len(ev_list),
        "high_count": high,
        "events": [e.to_dict() for e in reversed(ev_list[-80:])],
    })

@app.route('/api/alerts')
def api_alerts():
    with _lock:
        al_list = list(alerts)
    return jsonify({"alerts": [a.to_dict() for a in al_list]})

if __name__ == '__main__':
    t = threading.Thread(target=feed_events, daemon=True)
    t.start()
    print("\n🛡 SOC SIEM Dashboard running at http://localhost:5000\n")
    app.run(debug=False, use_reloader=False)
