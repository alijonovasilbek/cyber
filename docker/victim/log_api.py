"""
Victim container log API — backend bu API orqali qo'shimcha ma'lumot oladi.
Port 5000 da ishlaydi.
"""
import os
import re
from datetime import datetime, timedelta
from flask import Flask, jsonify, request

app = Flask(__name__)
LOG_FILE = '/victim-logs/auth.log'

FAILED_RE  = re.compile(r'Failed password')
SUCCESS_RE = re.compile(r'Accepted password')
TS_RE      = re.compile(r'^(\w{3}\s+\d+\s+\d+:\d+:\d+)')


def _parse_ts(line: str) -> datetime | None:
    m = TS_RE.match(line)
    if not m:
        return None
    try:
        year = datetime.now().year
        return datetime.strptime(f"{m.group(1)} {year}", "%b %d %H:%M:%S %Y")
    except ValueError:
        return None


@app.route('/health')
def health():
    exists = os.path.exists(LOG_FILE)
    return jsonify({'status': 'ok', 'log_exists': exists})


@app.route('/stats')
def stats():
    minutes = int(request.args.get('minutes', 5))
    cutoff  = datetime.now() - timedelta(minutes=minutes)
    failed  = 0
    success = 0

    try:
        with open(LOG_FILE, 'r', errors='replace') as f:
            for line in f:
                ts = _parse_ts(line)
                if ts and ts >= cutoff:
                    if FAILED_RE.search(line):
                        failed += 1
                    elif SUCCESS_RE.search(line):
                        success += 1
    except FileNotFoundError:
        pass

    return jsonify({
        'failed_logins':  failed,
        'success_logins': success,
        'window_minutes': minutes,
    })


@app.route('/logs')
def logs():
    n    = min(int(request.args.get('n', 50)), 200)
    lines = []
    try:
        with open(LOG_FILE, 'r', errors='replace') as f:
            lines = f.readlines()
    except FileNotFoundError:
        pass
    return jsonify({'lines': [l.rstrip() for l in lines[-n:]]})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
