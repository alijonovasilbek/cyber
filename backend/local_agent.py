import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

BASE_DIR = Path(__file__).resolve().parent
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cyberguard.settings')
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import django  # noqa: E402

django.setup()

from threats.demo_engine import scan_ip_safe  # noqa: E402
from threats.network_services import connect_to_wifi, get_wifi_status, list_network_interfaces  # noqa: E402
from threats.services import discover_local_devices  # noqa: E402


def _json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False).encode('utf-8')


class LocalAgentHandler(BaseHTTPRequestHandler):
    server_version = 'CyberGuardLocalAgent/1.0'

    def log_message(self, format, *args):
        return

    def _send_json(self, status_code: int, payload: dict):
        body = _json_bytes(payload)
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'content-type, x-api-key')
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get('Content-Length', '0') or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        if not raw:
            return {}
        try:
            return json.loads(raw.decode('utf-8'))
        except json.JSONDecodeError:
            return {}

    def do_OPTIONS(self):
        self._send_json(200, {'ok': True})

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/') or '/'

        try:
            if path == '/health':
                self._send_json(200, {
                    'status': 'ok',
                    'agent': 'cyberguard-local-agent',
                    'mode': 'safe-local-scan',
                })
                return

            if path == '/network/interfaces':
                interfaces = list_network_interfaces()
                self._send_json(200, {'interfaces': interfaces, 'total': len(interfaces), 'source': 'local-agent'})
                return

            if path == '/network/wifi/status':
                payload = get_wifi_status()
                payload['source'] = 'local-agent'
                self._send_json(200, payload)
                return

            if path == '/network/scan':
                devices = discover_local_devices()
                self._send_json(200, {'devices': devices, 'total': len(devices), 'source': 'local-agent'})
                return

            if path == '/scan-ip':
                query = parse_qs(parsed.query)
                ip = (query.get('ip') or [''])[0].strip()
                ports_raw = (query.get('ports') or [''])[0].strip()
                timeout_raw = (query.get('timeout') or ['0.35'])[0].strip()
                ports = []
                if ports_raw:
                    ports = [int(item) for item in ports_raw.split(',') if item.strip().isdigit()]
                timeout = float(timeout_raw or 0.35)
                result = scan_ip_safe(ip=ip, ports=ports or None, timeout=timeout)
                result['source'] = 'local-agent'
                self._send_json(200, result)
                return

            self._send_json(404, {'error': 'Not found'})
        except Exception as exc:
            self._send_json(500, {'error': str(exc)})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/') or '/'
        payload = self._read_json()

        try:
            if path == '/network/wifi/connect':
                result = connect_to_wifi(
                    ssid=payload.get('ssid', ''),
                    password=payload.get('password', ''),
                    interface_name=payload.get('interface_name', ''),
                    authentication=payload.get('authentication', ''),
                    encryption=payload.get('encryption', ''),
                )
                result['source'] = 'local-agent'
                self._send_json(200, result)
                return

            if path == '/scan-ip':
                result = scan_ip_safe(
                    ip=payload.get('ip_address', ''),
                    ports=payload.get('ports'),
                    timeout=payload.get('timeout', 0.35),
                )
                result['source'] = 'local-agent'
                self._send_json(200, result)
                return

            self._send_json(404, {'error': 'Not found'})
        except Exception as exc:
            self._send_json(400, {'error': str(exc)})


if __name__ == '__main__':
    host = '127.0.0.1'
    port = 8765
    print(f'CyberGuard local agent listening on http://{host}:{port}')
    ThreadingHTTPServer((host, port), LocalAgentHandler).serve_forever()
