"""High Tech VPN v1.7 信封解密器 (独立实现, 无外部依赖除 argon2-cffi / cryptography)

逆向来源: libgojni.so :: AndroidLibXrayLite.DO / AndroidLibXrayLite.decrypt
  base64 → [16B salt][12B nonce][ciphertext || GCM tag]
  key    = argon2id(password, salt, t=3, m=8192KiB, p=1, keyLen=32)
  plain  = AES-256-GCM(key, nonce, aad=salt).open(ciphertext)

两个口令:
  NewDecryptLibPassword    (21B) → 整包配置 (AndroidLibXrayLite.DO, Java 侧 do_)
  NewDecryptLibPasswordII  (23B) → 字段级密文 (AndroidLibXrayLite.decrypt)

用法:
  python tools/ht_decrypt.py --file blob.b64            # 解密整包, 输出 JSON
  python tools/ht_decrypt.py --file blob.b64 --fields   # 解密整包并解字段
  python tools/ht_decrypt.py --fetch                    # 从厂商 API 拉取并解密
  python tools/ht_decrypt.py --selftest                 # 自检(合成信封)
"""
import argparse
import base64
import json
import os
import sys

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PWD_BLOB = b'NewDecryptLibPassword'      # 21 bytes — AndroidLibXrayLite.DO
PWD_FIELD = b'NewDecryptLibPasswordII'   # 23 bytes — AndroidLibXrayLite.decrypt
API_URL = 'https://strongteam.co/api/hightech/v1/'
API_UA = 'High Tech VPN'                 # R.string.app — 服务端按此校验 App ID
KDF = dict(time_cost=3, memory_cost=8192, parallelism=1, hash_len=32,
           type=Type.ID, version=19)


def derive_key(password: bytes, salt: bytes) -> bytes:
    return hash_secret_raw(secret=password, salt=salt, **KDF)


def open_envelope(b64: str, password: bytes) -> bytes:
    raw = base64.b64decode(b64, validate=False)
    if len(raw) < 28:
        raise ValueError('envelope too short: %d bytes' % len(raw))
    salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
    return AESGCM(derive_key(password, salt)).decrypt(nonce, ct, salt)  # AAD = salt


def decrypt_blob(b64: str) -> str:
    return open_envelope(b64, PWD_BLOB).decode('utf-8')


def decrypt_field(value: str) -> str:
    """字段级密文解密; 不是密文/解不开则原样返回 (配置里混有明文, 如 Name/Info)"""
    if not isinstance(value, str) or len(value) < 40:
        return value
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception:
        return value
    if len(raw) < 28:
        return value
    for pw in (PWD_FIELD, PWD_BLOB):
        try:
            return open_envelope(value, pw).decode('utf-8')
        except Exception:
            continue
    return value


def decrypt_tree(obj):
    if isinstance(obj, dict):
        return {k: decrypt_tree(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [decrypt_tree(v) for v in obj]
    return decrypt_field(obj)


def fetch_remote(upstream: str = '', timeout: int = 40) -> str:
    """从厂商 API 拉取密文信封。upstream 形如 socks5h://127.0.0.1:10808"""
    import urllib.request
    handlers = [urllib.request.ProxyHandler({'http': upstream, 'https': upstream} if upstream else {})]
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(API_URL, headers={'User-Agent': API_UA})
    with opener.open(req, timeout=timeout) as r:
        return r.read().decode('utf-8').strip()


def seal_envelope(plain: bytes, password: bytes = PWD_BLOB) -> str:
    """自检用: 按同一算法造一个信封"""
    salt = os.urandom(16)
    nonce = os.urandom(12)
    ct = AESGCM(derive_key(password, salt)).encrypt(nonce, plain, salt)
    return base64.b64encode(salt + nonce + ct).decode()


def selftest() -> int:
    payload = json.dumps({'Version': '0.0', 'Servers': [{'Name': 'test'}]}).encode()
    blob = seal_envelope(payload)
    assert decrypt_blob(blob) == payload.decode(), 'blob roundtrip failed'
    fblob = seal_envelope(b'194.1.2.3', PWD_FIELD)
    assert decrypt_field(fblob) == '194.1.2.3', 'field roundtrip failed'
    assert decrypt_field('PlainTextValue') == 'PlainTextValue', 'passthrough failed'
    print('selftest OK  (blob + field + passthrough)')
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--file', help='密文信封文件 (单行 base64)')
    ap.add_argument('--fetch', action='store_true', help='从厂商 API 实时拉取')
    ap.add_argument('--fields', action='store_true', help='同时解密字段级密文')
    ap.add_argument('--upstream', default=os.environ.get('HT_UPSTREAM', ''),
                    help='拉取用代理, 如 socks5h://127.0.0.1:10808')
    ap.add_argument('--out', help='输出文件 (默认 stdout)')
    ap.add_argument('--selftest', action='store_true')
    a = ap.parse_args()

    if a.selftest:
        return selftest()
    if a.fetch:
        blob = fetch_remote(a.upstream)
    elif a.file:
        blob = open(a.file, encoding='utf-8').read().strip()
    else:
        ap.print_help()
        return 2

    cfg = json.loads(decrypt_blob(blob))
    if a.fields:
        cfg = decrypt_tree(cfg)
    text = json.dumps(cfg, indent=1, ensure_ascii=False)
    if a.out:
        open(a.out, 'w', encoding='utf-8').write(text)
        print('wrote %s (%d bytes)' % (a.out, len(text)), file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == '__main__':
    sys.exit(main())
