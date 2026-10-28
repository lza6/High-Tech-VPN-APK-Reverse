# PROTOCOL — High Tech VPN v1.7 配置下发协议实现手册

> 面向二次开发 / 对接方。按本文可独立实现「拉取 → 解密 → 出节点」全流程，无需反编译 APK。
> 逆向依据：`libgojni.so`（Go 1.24.3，`github.com/2dust/AndroidLibXrayLite` 的定制分支）。

---

## 1. 常量表

| 名称 | 值 | 位置 |
|---|---|---|
| 配置接口 | `https://strongteam.co/api/hightech/v1/` | `libgojni.so` rodata `0x37016a`（`AndroidLibXrayLite.Updateurl`） |
| 请求头 | `User-Agent: High Tech VPN` | `res/values/strings.xml` → `R.string.app`，由 `defpackage.jb0#getHeaders()` 注入 |
| 整包口令 | `NewDecryptLibPassword`（**21 字节**） | `AndroidLibXrayLite.DO` rodata `0x352946` |
| 字段口令 | `NewDecryptLibPasswordII`（**23 字节**） | `AndroidLibXrayLite.decrypt` rodata `0x355934` + 内联 `"sswordII"` |
| KDF | `argon2id`，time=3，memory=8192 KiB，parallelism=1，keyLen=32，version=0x13 | `golang.org/x/crypto/argon2.deriveKey` |
| 对称 | `AES-256-GCM` | `crypto/aes.NewCipher` + `crypto/cipher.NewGCM` |

> 两个口令只有 2 字节之差（`…Password` / `…PasswordII`）。**整包用 21 字节那个**；用 23 字节的会稳定拿到 `InvalidTag`，这是最容易卡住的地方。

## 2. 信封格式

```
body = base64( [16B salt][12B nonce][ciphertext || 16B GCM tag] )
key   = argon2id(password, salt, t=3, m=8192KiB, p=1, keyLen=32)
plain = AES-256-GCM(key, nonce, AAD = salt).open(ciphertext)
```

- `base64` 为标准字母表（含 `+` `/`），带 `=` 填充。
- **AAD 必须传 salt**（即 `raw[0:16]`）。不传 / 传空串 / 传 nonce 都解不开。
- 明文长度 = `len(raw) - 28 - 16`。

## 3. 请求 / 响应

```http
GET /api/hightech/v1/ HTTP/1.1
Host: strongteam.co
User-Agent: High Tech VPN
```

| 现象 | 含义 |
|---|---|
| `404 Invalid App Code`（16 字节 body） | 缺少/错误的 `User-Agent`（服务端用 UA 当 App ID 校验，**不是** header 里的 `X-App-Code`） |
| `200` + 一大段 base64 | 正常，按第 2 节解密 |
| `301` 到带斜杠路径 | 少了结尾 `/` |

响应解密后是一个 JSON 配置对象，结构见第 4 节。同结构的密文也内置在 APK 的 `assets/configfile.json`（出厂版本 `1.01`，远端已是 `1.11`）。

## 4. 配置 Schema

顶层字段（明文）：`Version`(字符串版本号)、`ReleaseNotes`、`Telegram`、`WhatsApp`、`Facebook`、`DefOVPNUser`、`DefOVPNPass`、`HysteriaUser`、`HysteriaOBFS`、`DefaultOVPNCert`(OpenVPN 模板)、`isTimerOn`、`timetoadd`、`Servers[]`、`Networks[]`。

### 4.1 `Servers[]`（服务器 = 落地侧）

| 字段 | 说明 | 是否字段级加密 |
|---|---|---|
| `Name` / `Flag` / `ServerType` / `ServerProtocol` | 名称、国旗、类型（`WS Server`/`GCP`/…）、协议（`OVPN`/`V2ray`/`UDP Hysteria`） | 否 |
| `ServerIPHost` | 主机名；多机时用 `;` 分隔 | **是** |
| `OpenVPNTCPPort` / `OpenVPNUdpPort` / `SSH_Port` / `SSLPort` | 端口 | 否 |
| `OVPNUser` / `OVPNPass` | OpenVPN 账号 | **是** |
| `UDP_user` / `UDP_obfs` | Hysteria2 认证串（`user:pass` 形态）与 obfs 口令 | **是** |
| `V2rayProtocol` / `V2rayProto` / `V2rayUUID` / `V2rayPath` | VLESS 参数 | UUID/Path **是** |
| `SlowDNSHost` / `SlowDNSKey` / `H2pass` / `CustomCertificate` | 其它通道 | **是** |

### 4.2 `Networks[]`（通道 = 前置/伪装侧）

| 字段 | 说明 |
|---|---|
| `Name` / `Info` / `TunnelType` | 通道名；类型：`V2ray` / `UDP Hysteria` / `Direct TCP`（`SSH`/`Slow DNS` 等） |
| `V2rayAddress` | 实际 TCP 目标；`[host]` = 用 `Servers.ServerIPHost` 替换 |
| `V2rayHost` | WS `Host` 头；`[host]` 同上 |
| `V2raySNI` | TLS SNI；`[host]` 同上 |
| `V2rayPort` | 端口（一般 443） |
| `V2rayServerNeed` | 需要哪种 `ServerType` 的服务器（`GCP` / `CF Worker` / `WS Server`） |
| `V2rayNetwork` | `Websocket` / `Xhttp` / `Custom-1` |
| `Insecure` / `V2ray_is_SNI` / `URI` | 证书校验开关等 |

**配对规则**：`Networks[].V2rayServerNeed == Servers[].ServerType`。配置里出现 `CF Worker` 但没下发 `CF Worker` 服务器时，该通道不可用（本版本无 CF 服务器）。

### 4.3 字段级加密

`Servers` / `Networks` 里绝大多数**值**是独立加密的 base64 串，算法与整包相同、口令换成 `…PasswordII`。配置中同时混有明文（`Name`、`Info`、`TunnelType`、`Flag`、端口号），实现时按「尝试解密，失败原样返回」处理即可。

## 5. 节点构造

### 5.1 VLESS over WS over TLS（`TunnelType == "V2ray"`）

```
addr = (Network.V2rayAddress == "[host]") ? Server.ServerIPHost : Network.V2rayAddress
host = (Network.V2rayHost    == "[host]") ? Server.ServerIPHost : Network.V2rayHost
sni  = (Network.V2raySNI     == "[host]") ? Server.ServerIPHost : Network.V2raySNI
uri  = vless://{Server.V2rayUUID}@{addr}:{V2rayPort}
         ?type=ws&path={urlquote(Server.V2rayPath)}&host={host}
         &security=tls&encryption=none&sni={sni}#{urlquote(Network.Name)}
```

App 生成的 Outbound 等价于 `assets/custom1.json` 模版（`allowInsecure=true`）。用 mihomo 表达：

```yaml
- name: vless-x
  type: vless
  server: <addr>
  port: 443
  uuid: <V2rayUUID>
  network: ws
  tls: true
  servername: <sni>
  skip-cert-verify: true
  client-fingerprint: chrome
  ws-opts: {path: "/", headers: {Host: <host>}}
```

要点：**TCP 连的是 `addr`（一个前置域名），TLS 的 SNI 与 WS 的 `Host` 分别由网络配置决定**，三者可能互不相同 —— 这就是它绕过运营商 DPI 的手段（不同前置域名解析到不同 ISP 可直达的 Google/Cloudflare 边缘 IP）。

实测：**不同 SNI 变体在服务端映射到不同出口节点**，因此 6 条 URI 得到 6 个不同国家/ASIP 的出口（见 README 实测表）。

### 5.2 Hysteria2（`ServerProtocol == "UDP Hysteria"`）

```
server   = Server.ServerIPHost
port     = 443/udp
password = Server.UDP_user        # 形如 "<user>:<pass>"，整串就是口令
obfs     = salamander, obfs-password = Server.UDP_obfs
sni      = 空 → skip-cert-verify
```

mihomo：

```yaml
- name: hy2-x
  type: hysteria2
  server: <host>
  port: 443
  password: "<UDP_user>"
  obfs: salamander
  obfs-password: "<UDP_obfs>"
  skip-cert-verify: true
```

注意该服务器 **只开 UDP**（同 IP 的 TCP 443/22 全超时），TCP 探活会误判为死。

### 5.3 OpenVPN（`ServerProtocol == "OVPN"`）

把 `DefaultOVPNCert` 里的 `remote 0.0.0.0 1194` 换成 `remote {ServerIPHost} {OpenVPNTCPPort}`，账号用 `OVPNUser/OVPNPass`（缺失时回退顶层 `DefOVPNUser/DefOVPNPass`，再缺失用配置顶层的默认账号）。`ServerIPHost` 含 `;` 时按主机逐条展开。

⚠️ **本版本实测该部分全部失效**：`boujeeteam.xyz` 与全部 `v2rayN.zamsytam.xyz` 已 NXDOMAIN（DoH 双源确认），配置仍在下发但已无解析。

## 6. 最小实现骨架（30 行）

```python
import base64, json, urllib.request
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

API, UA = 'https://strongteam.co/api/hightech/v1/', 'High Tech VPN'
PW_BLOB, PW_FIELD = b'NewDecryptLibPassword', b'NewDecryptLibPasswordII'

def key(pw, salt):
    return hash_secret_raw(secret=pw, salt=salt, time_cost=3, memory_cost=8192,
                           parallelism=1, hash_len=32, type=Type.ID, version=19)

def open_env(b64, pw):
    raw = base64.b64decode(b64)
    salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
    return AESGCM(key(pw, salt)).decrypt(nonce, ct, salt)

def field(v):
    try:    return open_env(v, PW_FIELD).decode()
    except Exception: return v

req = urllib.request.Request(API, headers={'User-Agent': UA})
blob = urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=30).read().decode()
cfg  = json.loads(open_env(blob.strip(), PW_BLOB))
cfg['Servers']  = [{k: field(v) for k, v in s.items()} for s in cfg['Servers']]
cfg['Networks'] = [{k: field(v) for k, v in n.items()} for n in cfg['Networks']]
print(cfg['Version'], len(cfg['Servers']), len(cfg['Networks']))
```

## 7. 坑清单（按踩坑概率排序）

1. **AAD 必须等于 salt**。漏传/传空 → `InvalidTag`，且没有更多错误信息。
2. **两个口令别搞混**：整包 21 字节、字段 23 字节；长度算错一位就全解不开（`NewDecryptLibPa`+`ssword` 与 `…PasswordII` 的拼接是编译器把 8 字节常量 `stur` 到 key 缓冲第 15 字节造成的，看着像被截断）。
3. **缺 UA 就是 404 `Invalid App Code`**，而不是 401 —— 别去猜 API Key。
4. **端口探活会骗人**：Hysteria 只开 UDP；前置域名可能是 Google/Cloudflare 边缘，TCP 通 ≠ 服务在。
5. **同一批 URI 的 SNI 换一个就是另一个出口**，不要以为重复节点去重掉了。
6. **厂商会重启/改版**：观测到 `Version 1.01 → 1.11` 的滚动更新，且 Cloud Run 中继出现过 503（见 REVERSE_REPORT「存活观测」）。任何对接都必须自带健康检查与轮换。
7. `ServerIPHost` 是多主机 `;` 拼接的列表，只取第一条会少一大半节点。
