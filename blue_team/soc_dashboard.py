#!/usr/bin/env python3
"""
soc_dashboard.py - Real-time SOC Monitoring Dashboard

Flask web UI that aggregates events from trap.log and soc_events.jsonl
and streams them to the browser via SSE. Dark-theme console with
severity-coded event timeline and stats cards.

Usage:
  python3 soc_dashboard.py                                # defaults
  python3 soc_dashboard.py --port 8080 --trap-log trap.log
  python3 soc_dashboard.py --soc-log soc_events.jsonl
"""
import os
import sys
import json
import time
import re
import threading
import argparse
from flask import Flask, Response, render_template_string

app = Flask(__name__)

# ═══════════════════════════════════════════════════════════════
#  Global Event Store
# ═══════════════════════════════════════════════════════════════

events = []
event_lock = threading.Lock()
stats = {'total': 0, 'blocked_ips': set(), 'kills': 0, 'criticals': 0}
MAX_EVENTS = 5000
API_TOKEN = None

TRAP_IP_RE = re.compile(
    r'\[([^\]]+)\]\s+Attacker IP:\s*(\d+\.\d+\.\d+\.\d+)\s+Port:\s*(\d+)')


# ═══════════════════════════════════════════════════════════════
#  Log File Watchers
# ═══════════════════════════════════════════════════════════════

class FileWatcher:
    def __init__(self, path, parser):
        self.path = path
        self.parser = parser
        self.offset = 0
        if os.path.exists(path):
            self.offset = os.path.getsize(path)

    def check(self):
        if not os.path.exists(self.path):
            return []
        size = os.path.getsize(self.path)
        if size < self.offset:
            self.offset = 0
        if size <= self.offset:
            return []
        new_events = []
        with open(self.path, 'r', errors='replace') as f:
            f.seek(self.offset)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                evt = self.parser(line)
                if evt:
                    new_events.append(evt)
            self.offset = f.tell()
        return new_events


def parse_trap_log(line):
    m = TRAP_IP_RE.search(line)
    if not m:
        return None
    return {
        'ts': m.group(1),
        'source': 'HONEYPOT',
        'event': 'HONEYPOT_TRAP',
        'severity': 'HIGH',
        'detail': f'Connection from {m.group(2)}:{m.group(3)}',
        'ip': m.group(2),
        'action': 'LOGGED',
    }


def parse_soc_jsonl(line):
    try:
        data = json.loads(line)
        data.setdefault('ts', time.strftime('%Y-%m-%d %H:%M:%S'))
        data.setdefault('source', 'UNKNOWN')
        data.setdefault('severity', 'INFO')
        return data
    except json.JSONDecodeError:
        return None


def _add_event(evt):
    events.append(evt)
    stats['total'] += 1
    if evt.get('ip'):
        stats['blocked_ips'].add(evt['ip'])
    if evt.get('action') == 'KILLED':
        stats['kills'] += 1
    if evt.get('severity') == 'CRITICAL':
        stats['criticals'] += 1
    if len(events) > MAX_EVENTS:
        del events[:len(events) - MAX_EVENTS // 2]


def watcher_loop(watchers, poll_interval):
    while True:
        for w in watchers:
            new = w.check()
            if new:
                with event_lock:
                    for evt in new:
                        _add_event(evt)
        time.sleep(poll_interval)


# ═══════════════════════════════════════════════════════════════
#  SSE Endpoint
# ═══════════════════════════════════════════════════════════════

@app.route('/stream')
def stream():
    def generate():
        last_idx = 0
        # Send initial stats
        with event_lock:
            s = {
                'total': stats['total'],
                'blocked_ips': len(stats['blocked_ips']),
                'kills': stats['kills'],
                'criticals': stats['criticals'],
            }
            def generate():
                with event_lock:
                    for evt in events:
                        yield f"event: alert\ndata: {json.dumps(evt)}\n\n"
                    last_total = stats['total']

                while True:
                    time.sleep(0.5)
                    with event_lock:
                        current_total = stats['total']
                        if current_total > last_total:
                            new_count = current_total - last_total
                            if new_count > len(events):
                                new_count = len(events)
                            for evt in events[len(events) - new_count:]:
                                yield f"event: alert\ndata: {json.dumps(evt)}\n\n"
                            last_total = current_total
                            s = {
                                'total': stats['total'],
                                'blocked_ips': len(stats['blocked_ips']),
                                'kills': stats['kills'],
                                'criticals': stats['criticals'],
                            }
                            yield f"event: stats\ndata: {json.dumps(s)}\n\n"
    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache',
                             'X-Accel-Buffering': 'no'})


@app.route('/api/event', methods=['POST'])
def api_event():
    """HTTP API for tools to POST events directly."""
    from flask import request
    if API_TOKEN:
        auth = request.headers.get('Authorization', '')
        if auth != f'Bearer {API_TOKEN}':
            return 'Unauthorized', 401
    data = request.get_json(silent=True)
    if not data:
        return 'Bad request', 400
    data.setdefault('ts', time.strftime('%Y-%m-%d %H:%M:%S'))
    with event_lock:
        _add_event(data)
    return 'OK', 200


# ═══════════════════════════════════════════════════════════════
#  Dashboard HTML
# ═══════════════════════════════════════════════════════════════

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC Dashboard</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    background: #0a0e17; color: #c8d6e5; font-family: 'Consolas', 'Monaco', monospace;
    font-size: 14px; overflow: hidden; height: 100vh;
}
.header {
    background: linear-gradient(135deg, #0f1923 0%, #1a2332 100%);
    border-bottom: 2px solid #1e90ff;
    padding: 16px 24px; display: flex; align-items: center; gap: 16px;
}
.header h1 { font-size: 20px; color: #1e90ff; font-weight: 600; }
.header .status {
    margin-left: auto; display: flex; align-items: center; gap: 8px;
}
.header .dot {
    width: 10px; height: 10px; border-radius: 50%; background: #00ff88;
    animation: pulse 1.5s infinite;
}
@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
}
.stats {
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px;
    padding: 16px 24px;
}
.stat-card {
    background: #111827; border: 1px solid #1f2937; border-radius: 8px;
    padding: 16px; text-align: center;
}
.stat-card .value {
    font-size: 36px; font-weight: 700; margin: 4px 0;
}
.stat-card .label {
    font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: #6b7280;
}
.stat-card.events .value { color: #1e90ff; }
.stat-card.blocked .value { color: #f59e0b; }
.stat-card.kills .value { color: #ef4444; }
.stat-card.critical .value { color: #ff4757; }
.timeline-header {
    padding: 8px 24px; color: #6b7280; font-size: 12px;
    text-transform: uppercase; letter-spacing: 1px;
    border-bottom: 1px solid #1f2937;
    display: grid; grid-template-columns: 90px 100px 90px 140px 120px 80px 1fr;
    gap: 8px; background: #0f1923;
}
.timeline {
    flex: 1; overflow-y: auto; padding: 0 24px;
    height: calc(100vh - 240px);
}
.event-row {
    display: grid; grid-template-columns: 90px 100px 90px 140px 120px 80px 1fr;
    gap: 8px; padding: 8px 0; border-bottom: 1px solid #111827;
    animation: fadeIn 0.3s ease;
}
@keyframes fadeIn {
    from { opacity: 0; transform: translateY(-8px); }
    to { opacity: 1; transform: translateY(0); }
}
.event-row .ts { color: #6b7280; }
.event-row .source { color: #8b5cf6; font-weight: 600; }
.sev-CRITICAL { color: #ef4444; font-weight: 700; }
.sev-HIGH { color: #f59e0b; font-weight: 600; }
.sev-MEDIUM { color: #3b82f6; }
.sev-INFO { color: #6b7280; }
.act-KILLED { color: #ef4444; font-weight: 700; }
.act-BLOCKED, .act-BLOCK { color: #f59e0b; font-weight: 600; }
.act-ALERT, .act-LOGGED { color: #3b82f6; }
.empty-state {
    text-align: center; padding: 60px; color: #374151;
    font-size: 16px;
}
.timeline::-webkit-scrollbar { width: 6px; }
.timeline::-webkit-scrollbar-track { background: #0a0e17; }
.timeline::-webkit-scrollbar-thumb { background: #1f2937; border-radius: 3px; }
</style>
</head>
<body>
<div class="header">
    <h1>&#x1f6e1; SOC Dashboard — Real-time Security Monitoring</h1>
    <div class="status"><div class="dot"></div><span style="color:#00ff88;font-size:12px">LIVE</span></div>
</div>

<div class="stats">
    <div class="stat-card events">
        <div class="label">Total Events</div>
        <div class="value" id="stat-total">0</div>
    </div>
    <div class="stat-card blocked">
        <div class="label">Blocked IPs</div>
        <div class="value" id="stat-blocked">0</div>
    </div>
    <div class="stat-card kills">
        <div class="label">Process Kills</div>
        <div class="value" id="stat-kills">0</div>
    </div>
    <div class="stat-card critical">
        <div class="label">Critical Alerts</div>
        <div class="value" id="stat-criticals">0</div>
    </div>
</div>

<div class="timeline-header">
    <span>TIME</span><span>SOURCE</span><span>SEVERITY</span>
    <span>EVENT</span><span>TARGET</span><span>ACTION</span><span>DETAIL</span>
</div>

<div class="timeline" id="timeline">
    <div class="empty-state" id="empty">Waiting for events...</div>
</div>

<script>
const timeline = document.getElementById('timeline');
const empty = document.getElementById('empty');
let hasEvents = false;

function addEvent(evt) {
    if (!hasEvents) { empty.style.display = 'none'; hasEvents = true; }
    const row = document.createElement('div');
    row.className = 'event-row';
    const ts = evt.ts || '';
    const timeStr = ts.includes(' ') ? ts.split(' ')[1] : ts;
    const sev = evt.severity || 'INFO';
    const act = evt.action || '';
    const src = evt.source || '';
    const evtName = evt.event || '';
    const ip = evt.ip || evt.comm || '';
    const detail = evt.detail || '';
    row.innerHTML = `
        <span class="ts">${esc(timeStr)}</span>
        <span class="source">${esc(src)}</span>
        <span class="sev-${sev}">${esc(sev)}</span>
        <span>${esc(evtName)}</span>
        <span>${esc(ip)}</span>
        <span class="act-${act}">${esc(act)}</span>
        <span>${esc(detail)}</span>
    `;
    timeline.insertBefore(row, timeline.firstChild.nextSibling || null);
    if (timeline.children.length > 200) timeline.removeChild(timeline.lastChild);
}

function esc(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}

function updateStats(s) {
    document.getElementById('stat-total').textContent = s.total || 0;
    document.getElementById('stat-blocked').textContent = s.blocked_ips || 0;
    document.getElementById('stat-kills').textContent = s.kills || 0;
    document.getElementById('stat-criticals').textContent = s.criticals || 0;
}

const es = new EventSource('/stream');
es.addEventListener('alert', e => addEvent(JSON.parse(e.data)));
es.addEventListener('stats', e => updateStats(JSON.parse(e.data)));
es.onerror = () => setTimeout(() => location.reload(), 3000);
</script>
</body>
</html>
"""


# ═══════════════════════════════════════════════════════════════
#  Dashboard Page
# ═══════════════════════════════════════════════════════════════

@app.route('/')
def dashboard():
    return render_template_string(DASHBOARD_HTML)


# ═══════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(description='SOC Real-time Dashboard')
    ap.add_argument('--port', type=int, default=8080,
                    help='Dashboard web port (default 8080)')
    ap.add_argument('--host', default='0.0.0.0',
                    help='Bind address (default 0.0.0.0)')
    ap.add_argument('--trap-log', default='trap.log',
                    help='Honeypot trap.log path')
    ap.add_argument('--soc-log', default='soc_events.jsonl',
                    help='SOC events JSONL path')
    ap.add_argument('--poll', type=float, default=0.5,
                    help='Log poll interval in seconds (default 0.5)')
    ap.add_argument('--api-token', type=str, default='',
                    help='Bearer token for /api/event (empty = no auth)')
    args = ap.parse_args()

    global API_TOKEN
    API_TOKEN = args.api_token or None

    print('\033[94m')
    print('+' + '=' * 52 + '+')
    print('|   SOC Dashboard  v1.0                             |')
    print('|   Real-time Security Monitoring                    |')
    print('+' + '=' * 52 + '+')
    print('\033[0m')
    print(f'  Web UI   : http://{args.host}:{args.port}')
    print(f'  Trap log : {os.path.abspath(args.trap_log)}')
    print(f'  SOC log  : {os.path.abspath(args.soc_log)}')
    token_str = f'Bearer {API_TOKEN}' if API_TOKEN else 'NONE (open)'
    print(f'  API      : POST http://{args.host}:{args.port}/api/event')
    print(f'  API auth : {token_str}')
    print()
    print('[*] Open the URL above in a browser.')
    print('[*] Events will appear in real-time.\n')

    watchers = [
        FileWatcher(args.trap_log, parse_trap_log),
        FileWatcher(args.soc_log, parse_soc_jsonl),
    ]

    t = threading.Thread(target=watcher_loop, args=(watchers, args.poll),
                         daemon=True)
    t.start()

    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.WARNING)

    app.run(host=args.host, port=args.port, debug=False, threaded=True)


if __name__ == '__main__':
    main()
