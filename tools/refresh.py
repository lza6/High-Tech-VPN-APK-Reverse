"""拉取 → 解密 → 生成节点池 (长期轮换用, 可 cron)
输出 (默认 out/, 已 gitignore):
  out/nodes.json      节点清单
  out/mihomo.yaml     mihomo 配置, 每节点一个 127.0.0.1:socks 端口
  out/ports.json      id → socks 端口
  out/ovpn/*.ovpn     OpenVPN 配置(若上游仍下发)
  out/prev_nodes.json 上一轮快照(用于 diff)

用法:
  python tools/refresh.py                       # 直连拉取
  python tools/refresh.py --upstream socks5h://127.0.0.1:10808
  python tools/refresh.py --config out/remote.json   # 用已解密配置, 不联网
"""
import argparse
import json
import os
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from ht_decrypt import decrypt_blob, decrypt_tree, fetch_remote  # noqa: E402

HOST_TOKEN = '[host]'


def pick(v, fallback):
    v = (v or '').strip()
    return fallback if (not v or v == HOST_TOKEN) else v


def build_nodes(conf, include_ovpn=True):
    servers = conf.get('Servers') or []
    nets = conf.get('Networks') or []
    nodes = []

    def srv_by_type(t):
        for s in servers:
            if (s.get('ServerType') or '').lower() == (t or '').lower():
                return s
        return None

    for n in nets:
        if n.get('TunnelType') != 'V2ray':
            continue
        need = (n.get('V2rayServerNeed') or '').strip()
        s = srv_by_type(need)          # 没有对应类型的服务器(如 CF Worker)直接跳过
        if not s or not s.get('V2rayUUID'):
            continue
        host = s['ServerIPHost']
        addr = pick(n.get('V2rayAddress'), host)
        sni = pick(n.get('V2raySNI'), host)
        ws_host = pick(n.get('V2rayHost'), host)
        port = int(n.get('V2rayPort') or 443)
        path = s.get('V2rayPath') or '/'
        uri = 'vless://%s@%s:%d?type=ws&path=%s&host=%s&security=tls&encryption=none&sni=%s#%s' % (
            s['V2rayUUID'], addr, port, urllib.parse.quote(path, safe=''), ws_host, sni,
            urllib.parse.quote(n['Name'].strip()))
        nodes.append({'id': 'vless-%d-app' % len(nodes), 'kind': 'vless-ws-tls', 'variant': 'app',
                      'name': n['Name'].strip(), 'addr': addr, 'port': port, 'uuid': s['V2rayUUID'],
                      'path': path, 'ws_host': ws_host, 'sni': sni,
                      'fronting': addr != host, 'uri': uri})
        if sni != host or addr != host:
            uri2 = 'vless://%s@%s:%d?type=ws&path=%s&host=%s&security=tls&encryption=none&sni=%s#%s' % (
                s['V2rayUUID'], host, port, urllib.parse.quote(path, safe=''), host, host,
                urllib.parse.quote(n['Name'].strip() + '-real'))
            nodes.append({'id': 'vless-%d-real' % len(nodes), 'kind': 'vless-ws-tls', 'variant': 'real',
                          'name': n['Name'].strip() + ' (real-host)', 'addr': host, 'port': port,
                          'uuid': s['V2rayUUID'], 'path': path, 'ws_host': host, 'sni': host,
                          'fronting': False, 'uri': uri2})

    for s in servers:
        if 'hysteria' not in (s.get('ServerProtocol') or '').lower():
            continue
        auth = s.get('UDP_user') or conf.get('HysteriaUser') or ''
        if not auth:
            continue
        obfs = s.get('UDP_obfs') or ''
        nodes.append({'id': 'hy2-%d' % len(nodes), 'kind': 'hysteria2', 'variant': 'app',
                      'name': s['Name'].strip(), 'addr': s['ServerIPHost'], 'port': 443,
                      'auth': auth, 'sni': '', 'obfs': obfs, 'insecure': True,
                      'uri': 'hysteria2://%s@%s:443?insecure=1&obfs=salamander&obfs-password=%s#%s' % (
                          auth, s['ServerIPHost'], obfs, urllib.parse.quote(s['Name'].strip()))})

    if include_ovpn:
        for s in servers:
            if (s.get('ServerProtocol') or '').upper() != 'OVPN':
                continue
            for h in [x.strip() for x in (s.get('ServerIPHost') or '').split(';') if x.strip()]:
                nodes.append({'id': 'ovpn-%d' % len(nodes), 'kind': 'openvpn', 'variant': 'app',
                              'name': s['Name'].strip(), 'addr': h,
                              'port': int(s.get('OpenVPNTCPPort') or 1194),
                              'user': s.get('OVPNUser') or conf.get('DefOVPNUser') or '',
                              'passwd': s.get('OVPNPass') or conf.get('DefOVPNPass') or '',
                              'template': conf.get('DefaultOVPNCert') or ''})

    seen, uniq = set(), []
    for n in nodes:
        k = (n['kind'], n.get('addr'), n.get('port'), n.get('uuid'), n.get('path'),
             n.get('ws_host'), n.get('sni'), n.get('auth'), n.get('user'), n.get('passwd'))
        if k in seen:
            continue
        seen.add(k)
        uniq.append(n)
    return uniq


def emit_mihomo(nodes, base_port=31000, upstream=None):
    proxies, listeners, ports = [], [], {}
    for n in nodes:
        if n['kind'] == 'vless-ws-tls':
            p = {'name': n['id'], 'type': 'vless', 'server': n['addr'], 'port': n['port'],
                 'uuid': n['uuid'], 'network': 'ws', 'tls': True, 'udp': True,
                 'servername': n['sni'], 'skip-cert-verify': True, 'client-fingerprint': 'chrome',
                 'ws-opts': {'path': n['path'], 'headers': {'Host': n['ws_host']}}}
        elif n['kind'] == 'hysteria2':
            p = {'name': n['id'], 'type': 'hysteria2', 'server': n['addr'], 'port': n['port'],
                 'password': n['auth'], 'skip-cert-verify': True, 'udp': True}
            if n['obfs']:
                p['obfs'] = 'salamander'
                p['obfs-password'] = n['obfs']
        else:
            continue
        if upstream:
            p['dialer-proxy'] = 'up'
        proxies.append(p)
        port = base_port + len(ports) + 1
        ports[n['id']] = port
        listeners.append((n['id'], port))

    out = ['mixed-port: 7899', 'allow-lan: false', 'mode: rule', 'log-level: warning',
           'external-controller: 127.0.0.1:9099', '', 'proxies:']
    if upstream:
        sp = urllib.parse.urlsplit(upstream)
        out += ['  - name: "up"', '    type: "%s"' % (sp.scheme.replace('h', '') or 'socks5'),
                '    server: "%s"' % sp.hostname, '    port: %d' % (sp.port or 1080)]
    for p in proxies:
        out.append('  - name: "%s"' % p['name'])
        for k, v in p.items():
            if k == 'name':
                continue
            if isinstance(v, dict):
                out.append('    %s:' % k)
                for k2, v2 in v.items():
                    if isinstance(v2, dict):
                        out.append('      %s:' % k2)
                        for k3, v3 in v2.items():
                            out.append('        %s: "%s"' % (k3, v3))
                    else:
                        out.append('      %s: "%s"' % (k2, v2))
            elif isinstance(v, bool):
                out.append('    %s: %s' % (k, 'true' if v else 'false'))
            elif isinstance(v, (int, float)):
                out.append('    %s: %s' % (k, v))
            else:
                out.append('    %s: "%s"' % (k, v))
    out += ['', 'listeners:']
    for nid, port in listeners:
        out += ['  - name: in-%s' % nid, '    type: socks', '    port: %d' % port,
                '    listen: 127.0.0.1', '    proxy: %s' % nid, '    udp: true']
    out += ['', 'rules:', '  - MATCH,DIRECT', '']
    return '\n'.join(out), ports


def ovpn_text(n):
    lines = []
    for line in (n['template'] or '').split('\n'):
        lines.append('remote %s %d' % (n['addr'], n['port']) if line.startswith('remote ') else line)
    body = '\n'.join(lines)
    return body if body.endswith('\n') else body + '\n'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--upstream', default=os.environ.get('HT_UPSTREAM', ''))
    ap.add_argument('--config', help='已解密的配置 JSON; 缺省则联网拉取')
    ap.add_argument('--out-dir', default=os.path.join(ROOT, 'out'))
    ap.add_argument('--base-port', type=int, default=31000)
    ap.add_argument('--no-ovpn', action='store_true')
    a = ap.parse_args()

    os.makedirs(a.out_dir, exist_ok=True)
    if a.config:
        conf = json.load(open(a.config, encoding='utf-8'))
    else:
        conf = decrypt_tree(json.loads(decrypt_blob(fetch_remote(a.upstream))))
        json.dump(conf, open(os.path.join(a.out_dir, 'remote.json'), 'w', encoding='utf-8'),
                  indent=1, ensure_ascii=False)

    nodes = build_nodes(conf, include_ovpn=not a.no_ovpn)
    prev_path = os.path.join(a.out_dir, 'prev_nodes.json')
    prev = json.load(open(prev_path, encoding='utf-8')) if os.path.exists(prev_path) else []

    yml, ports = emit_mihomo(nodes, a.base_port, a.upstream)
    json.dump(nodes, open(os.path.join(a.out_dir, 'nodes.json'), 'w', encoding='utf-8'),
              indent=1, ensure_ascii=False)
    json.dump(prev, open(prev_path, 'w', encoding='utf-8'), indent=1, ensure_ascii=False)
    open(os.path.join(a.out_dir, 'mihomo.yaml'), 'w', encoding='utf-8').write(yml)
    json.dump(ports, open(os.path.join(a.out_dir, 'ports.json'), 'w'), indent=1)
    if not a.no_ovpn:
        d = os.path.join(a.out_dir, 'ovpn')
        os.makedirs(d, exist_ok=True)
        for n in nodes:
            if n['kind'] == 'openvpn':
                open(os.path.join(d, n['id'] + '.ovpn'), 'w', encoding='utf-8').write(ovpn_text(n))

    keys = lambda ns: {(x['kind'], x.get('addr'), x.get('port'), x.get('sni')) for x in ns}
    added, removed = keys(nodes) - keys(prev), keys(prev) - keys(nodes)
    kinds = {}
    for n in nodes:
        kinds[n['kind']] = kinds.get(n['kind'], 0) + 1
    print('config Version=%s | nodes=%d %s | socks 端口 %s..%s' % (
        conf.get('Version'), len(nodes), kinds,
        a.base_port + 1 if ports else '-', a.base_port + len(ports)))
    if prev:
        print('diff vs 上一轮: +%d / -%d' % (len(added), len(removed)))
        for x in sorted(added):
            print('  + %s' % (x,))
        for x in sorted(removed):
            print('  - %s' % (x,))
    return 0


if __name__ == '__main__':
    sys.exit(main())
