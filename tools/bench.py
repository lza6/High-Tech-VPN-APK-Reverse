"""节点压测: 顺序延迟 10 次 + 8 并发 x 10 次成功率 + 3MB 吞吐
用法: python tools/bench.py [--out-dir out] [--brief MB] [--conc 8] [--rounds 10]
输出: out/bench.json
"""
import argparse
import concurrent.futures as cf
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from probe import find_bin, wait_port  # noqa: E402

LAT_URL = 'https://www.gstatic.com/generate_204'


def req(port, url, timeout=30):
    t0 = time.time()
    r = subprocess.run(['curl', '-sS', '-m', str(timeout), '--socks5-hostname',
                        '127.0.0.1:%d' % port, '-o', os.devnull, '-w', '%{http_code} %{speed_download}', url],
                       capture_output=True, text=True, encoding='utf-8', errors='replace')
    dt = (time.time() - t0) * 1000
    parts = (r.stdout or '').split()
    code = parts[0] if parts else '000'
    try:
        spd = float(parts[1])
    except Exception:
        spd = 0.0
    return code, dt, spd


def pct(v, p):
    if not v:
        return None
    v = sorted(v)
    return round(v[min(len(v) - 1, int(round(p / 100.0 * (len(v) - 1))))], 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out-dir', default=os.path.join(ROOT, 'out'))
    ap.add_argument('--conc', type=int, default=8)
    ap.add_argument('--rounds', type=int, default=10)
    ap.add_argument('--dl-mb', type=float, default=3.0)
    ap.add_argument('--no-start', action='store_true')
    a = ap.parse_args()

    ports = json.load(open(os.path.join(a.out_dir, 'ports.json')))
    proc = None
    if not a.no_start:
        proc = subprocess.Popen([find_bin(), '-f', os.path.join(a.out_dir, 'mihomo.yaml'), '-d', a.out_dir],
                                stdout=open(os.path.join(a.out_dir, 'mihomo.log'), 'w'),
                                stderr=subprocess.STDOUT)
        time.sleep(3)
    dl_url = 'https://speed.cloudflare.com/__down?bytes=%d' % int(a.dl_mb * 1000000)
    out = []
    try:
        for nid, port in ports.items():
            if not wait_port(port, 8):
                continue
            lat, ok = [], 0
            for _ in range(a.rounds):
                code, dt, _ = req(port, LAT_URL, 20)
                if code.startswith('2') or code == '204':
                    ok += 1
                    lat.append(dt)
            total = a.conc * a.rounds
            lat_c, ok_c = [], 0
            with cf.ThreadPoolExecutor(max_workers=a.conc) as ex:
                for code, dt, _ in ex.map(lambda _: req(port, LAT_URL, 25), range(total)):
                    if code.startswith('2') or code == '204':
                        ok_c += 1
                        lat_c.append(dt)
            code, _, spd = req(port, dl_url, 120)
            rec = {'id': nid, 'port': port, 'seq_ok': ok, 'seq_total': a.rounds,
                   'lat_p50': pct(lat, 50), 'lat_p95': pct(lat, 95),
                   'conc_ok': ok_c, 'conc_total': total,
                   'conc_p50': pct(lat_c, 50), 'conc_p95': pct(lat_c, 95),
                   'dl_code': code, 'dl_kbps': round(spd / 1024.0, 1)}
            out.append(rec)
            print('%-16s seq %2d/%-2d p50=%-8s p95=%-8s | conc %3d/%-3d | %s %8.1f KB/s' % (
                nid, ok, a.rounds, rec['lat_p50'], rec['lat_p95'], ok_c, total, code, rec['dl_kbps']))
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(3)
            except Exception:
                proc.kill()
    json.dump(out, open(os.path.join(a.out_dir, 'bench.json'), 'w', encoding='utf-8'),
              indent=1, ensure_ascii=False)
    return 0


if __name__ == '__main__':
    sys.exit(main())
