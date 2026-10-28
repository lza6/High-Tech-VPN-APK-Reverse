"""节点测活: 起 mihomo → 逐 socks 端口问 ip-api → out/probe.json
用法: python tools/probe.py [--out-dir out] [--no-start] [--bin <mihomo>]
"""
import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def find_bin(explicit=None):
    if explicit:
        return explicit
    if os.environ.get('MIHOMO_BIN'):
        return os.environ['MIHOMO_BIN']
    for name in ('mihomo', 'mihomo.exe', 'clash-meta', 'clash-meta.exe'):
        p = shutil.which(name)
        if p:
            return p
    return 'mihomo'


def wait_port(port, timeout=12):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            socket.create_connection(('127.0.0.1', port), 1).close()
            return True
        except Exception:
            time.sleep(0.3)
    return False


def assert_own_listeners(logpath, min_ok=1):
    """铁律: 端口被别的程序占着时, 测出来的"存活"其实是别人的节点。
    mihomo 绑定失败会在日志里留下 listen err —— 有就立刻失败退出。"""
    if not os.path.exists(logpath):
        return
    bad = [l for l in open(logpath, encoding='utf-8', errors='replace') if 'listen err' in l]
    if bad:
        sys.stderr.write('FATAL: mihomo 无法绑定端口, 端口已被其它进程占用, 测活结果会串线!\n')
        for l in bad[:4]:
            sys.stderr.write('  ' + l.strip() + '\n')
        sys.stderr.write('换一个 --base-port (如 33000/34000) 重新 refresh, 并确认该段无人占用。\n')
        sys.exit(3)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out-dir', default=os.path.join(ROOT, 'out'))
    ap.add_argument('--no-start', action='store_true')
    ap.add_argument('--bin', default=None)
    a = ap.parse_args()

    cfg = os.path.join(a.out_dir, 'mihomo.yaml')
    ports = json.load(open(os.path.join(a.out_dir, 'ports.json')))
    nodes = {n['id']: n for n in json.load(open(os.path.join(a.out_dir, 'nodes.json'), encoding='utf-8'))}
    proc = None
    if not a.no_start:
        logp = os.path.join(a.out_dir, 'mihomo.log')
        proc = subprocess.Popen([find_bin(a.bin), '-f', cfg, '-d', a.out_dir],
                                stdout=open(logp, 'w'),
                                stderr=subprocess.STDOUT)
        time.sleep(3)
        assert_own_listeners(logp)
    results = []
    try:
        for nid, port in ports.items():
            if not wait_port(port, 8):
                results.append({'id': nid, 'port': port, 'alive': False, 'err': 'listener down'})
                print('%-16s DOWN (listener)' % nid)
                continue
            r = subprocess.run(['curl', '-sS', '-m', '20', '--socks5-hostname', '127.0.0.1:%d' % port,
                                '-w', '|%{time_total}', 'http://ip-api.com/json'],
                               capture_output=True, text=True, encoding='utf-8', errors='replace')
            body, _, t = (r.stdout or '').rpartition('|')
            try:
                j = json.loads(body)
            except Exception:
                j = {}
            alive = j.get('status') == 'success'
            results.append({'id': nid, 'port': port, 'alive': alive, 'sec': float(t or 0),
                            'ip': j.get('query'), 'cc': j.get('countryCode'),
                            'isp': (j.get('isp') or '')[:48], 'addr': nodes[nid].get('addr'),
                            'sni': nodes[nid].get('sni'), 'kind': nodes[nid].get('kind')})
            print('%-16s %-5s %-15s %-4s %-28s %.2fs' % (
                nid, 'ALIVE' if alive else 'DEAD', j.get('query') or '-',
                j.get('countryCode') or '-', (j.get('isp') or '-')[:28], float(t or 0)))
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(3)
            except Exception:
                proc.kill()
    out = os.path.join(a.out_dir, 'probe.json')
    json.dump(results, open(out, 'w', encoding='utf-8'), indent=1, ensure_ascii=False)
    alive = sum(1 for r in results if r.get('alive'))
    print('--- alive %d/%d -> %s' % (alive, len(results), out))
    return 0


if __name__ == '__main__':
    sys.exit(main())
