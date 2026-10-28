"""High Tech VPN v1.7 — 逆向 Demo Server (仅标准库 + argon2-cffi + cryptography)

依赖 out/ 目录下的产物(由 tools/refresh.py + tools/probe.py + tools/bench.py 生成):
  nodes.json / ports.json / probe.json / bench.json

接口:
  GET /                 演示页
  GET /api/meta         协议与加密算法说明
  GET /api/config       实时拉取并解密厂商配置 (证明可长期刷新)
  GET /api/nodes        节点清单 + 上次实测数据
  GET /api/probe?node=  单节点实时测活 (需 mihomo 提供 socks 端口)
  GET /api/bench        上次压测结果

环境变量:
  DEMO_STATE     状态目录, 默认 ../out
  DEMO_PORT      监听端口, 默认 8933
  DEMO_UPSTREAM  拉取配置用的上游代理, 如 socks5h://127.0.0.1:10808
"""
import json
import os
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'tools'))
from ht_decrypt import API_UA, API_URL, decrypt_blob, decrypt_tree, fetch_remote  # noqa: E402

STATE = os.environ.get('DEMO_STATE', os.path.join(ROOT, 'out'))
PORT = int(os.environ.get('DEMO_PORT', '8933'))
UPSTREAM = os.environ.get('DEMO_UPSTREAM', '')


def load_json(name, default):
    p = os.path.join(STATE, name)
    if not os.path.exists(p):
        return default
    try:
        return json.load(open(p, encoding='utf-8'))
    except Exception:
        return default


def public_nodes():
    nodes = [n for n in load_json('nodes.json', []) if n.get('kind') != 'openvpn']
    probe = {r['id']: r for r in load_json('probe.json', [])}
    bench = {r['id']: r for r in load_json('bench.json', [])}
    ports = load_json('ports.json', {})
    out = []
    for n in nodes:
        pr = probe.get(n['id'], {})
        b = bench.get(n['id'], {})
        out.append({
            'id': n['id'], 'kind': n['kind'], 'name': n['name'], 'variant': n.get('variant'),
            'addr': n.get('addr'), 'port': n.get('port'), 'sni': n.get('sni'),
            'host': n.get('ws_host'), 'path': n.get('path'), 'uri': n.get('uri'),
            'socks_port': ports.get(n['id']),
            'alive': bool(pr.get('alive')), 'exit_ip': pr.get('ip'), 'exit_cc': pr.get('cc'),
            'exit_isp': pr.get('isp'),
            'lat_p50': b.get('lat_p50'), 'lat_p95': b.get('lat_p95'),
            'conc_ok': b.get('conc_ok'), 'conc_total': b.get('conc_total'),
            'dl_kbps': b.get('dl_kbps'),
        })
    return out


def probe_node(nid):
    n = next((x for x in public_nodes() if x['id'] == nid), None)
    if not n:
        return {'error': 'unknown node id'}
    if not n['socks_port']:
        return {'error': 'no socks listener (run mihomo + tools/probe.py first)'}
    t0 = time.time()
    r = subprocess.run(['curl', '-sS', '-m', '20', '--socks5-hostname',
                        '127.0.0.1:%d' % n['socks_port'], 'http://ip-api.com/json'],
                       capture_output=True, text=True, encoding='utf-8', errors='replace')
    ms = round((time.time() - t0) * 1000)
    try:
        j = json.loads(r.stdout)
    except Exception:
        return {'id': nid, 'ok': False, 'ms': ms, 'raw': (r.stdout or r.stderr)[:200]}
    return {'id': nid, 'ok': j.get('status') == 'success', 'ms': ms, 'ip': j.get('query'),
            'cc': j.get('countryCode'), 'isp': j.get('isp')}


class H(BaseHTTPRequestHandler):
    server_version = 'HightechVPN-Reverse-Demo/1.0'

    def log_message(self, fmt, *a):
        sys.stderr.write('%s %s\n' % (self.address_string(), fmt % a))

    def _send(self, code, body, ctype='application/json; charset=utf-8'):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False, indent=1)
        b = body.encode('utf-8') if isinstance(body, str) else body
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(b)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        try:
            if u.path in ('/', '/index.html'):
                p = os.path.join(HERE, 'demo.html')
                return self._send(200, open(p, 'rb').read(), 'text/html; charset=utf-8')
            if u.path == '/api/meta':
                return self._send(200, {
                    'app': 'High Tech VPN v1.7 (com.hightech.vpn)',
                    'vendor_api': API_URL, 'app_id_header': 'User-Agent: ' + API_UA,
                    'envelope': {'format': 'base64( [16B salt][12B nonce][ciphertext||tag] )',
                                 'kdf': 'argon2id(t=3, m=8192KiB, p=1, 32B)',
                                 'password': 'NewDecryptLibPassword (blob) / ...PasswordII (field)',
                                 'cipher': 'AES-256-GCM', 'aad': 'salt = raw[0:16]',
                                 'source': 'libgojni.so :: AndroidLibXrayLite.DO'},
                    'state_dir': STATE})
            if u.path == '/api/config':
                cfg = decrypt_tree(json.loads(decrypt_blob(fetch_remote(UPSTREAM))))
                summ = {k: (len(v) if isinstance(v, list) else v)
                        for k, v in cfg.items() if k != 'DefaultOVPNCert'}
                return self._send(200, {'ok': True, 'summary': summ,
                                        'servers': cfg.get('Servers'), 'networks': cfg.get('Networks')})
            if u.path == '/api/nodes':
                return self._send(200, {'ok': True, 'nodes': public_nodes()})
            if u.path == '/api/bench':
                return self._send(200, {'ok': True, 'bench': load_json('bench.json', [])})
            if u.path == '/api/probe':
                return self._send(200, probe_node((q.get('node') or [''])[0]))
            return self._send(404, {'error': 'not found'})
        except Exception as e:
            return self._send(500, {'error': '%s: %s' % (type(e).__name__, e)})


if __name__ == '__main__':
    print('demo: http://127.0.0.1:%d   state=%s   upstream=%s' % (PORT, STATE, UPSTREAM or 'direct'))
    ThreadingHTTPServer(('127.0.0.1', PORT), H).serve_forever()
