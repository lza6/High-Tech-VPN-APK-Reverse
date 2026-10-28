# 逆向报告 — High Tech VPN v1.7 (`com.hightech.vpn`)

日期：2026-10-29 · 样本：`High Tech VPN_v1.7_M0d.apk`（38 MB，mod 版）
结论：**协议完全还原**（可离线/在线解密厂商下发的节点目录，生成 VLESS-WS-TLS(Cloud Run 前置) + Hysteria2 节点）；OpenVPN 分支域名已失效；链路实测因厂商中继 503 阻塞，标记待验证。

---

## 1. APK 结构

| 资产 | 大小 | 说明 |
|---|---|---|
| `classes.dex` / `classes2.dex` | 9.3 MB / 6.9 MB | 主逻辑，包名空间 `com.v2ray.ang.*`（v2rayNG 分支）+ `com.vpn.sandok.ultrasshservice.*`（SocksHttp 壳） |
| `lib/arm64-v8a/libgojni.so` | 30.7 MB | **核心**：`github.com/2dust/AndroidLibXrayLite` 定制分支（Go 1.24.3），加密/解密与网关地址都在这里 |
| `libovpncli.so` / `libsocks.so` / `libtun2socks.so` / `libpdnsd.so` | — | OpenVPN3 客户端 + SOCKS + tun2socks + DNS 隧道 |
| `assets/configfile.json` | 5.7 KB | 出厂节点配置（整包密文，`Version 1.01`） |
| `assets/custom1.json` | 3.0 KB | VLESS-WS-TLS Outbound 模版（`%s` 占位，`allowInsecure=true`） |
| `assets/v2ray_config.json` | 1.8 KB | v2rayNG 默认示例配置（`v2ray.cool` 占位，无实际价值） |
| `assets/proxy_packagename.txt` | 9.5 KB | 分应用代理白名单（v2rayNG 常见资产） |

架构判定：**不是** Firebase RTDB、**不是** Flutter AOT、**不是** yolo/dzboot 白标模板，而是
「v2rayNG fork + 厂商自有 HTTP 配置 API + 原生加密配置」这一类。dex 里几乎找不到自建域名（只有广告 SDK 的），
说明网关地址被移进了 native 层 —— 事实正是如此。

## 2. 动态路线：不可行（有证据）

模拟器 `sdk_gphone_x86_64_arm64`（Android 11，x86_64）安装成功，`am start` 后进程立刻死：

```
F DEBUG : signal 4 (SIGILL), code -6 (SI_TKILL)
F DEBUG : #01 pc ... /system/lib64/libndk_translation.so (Decoder<...>::DecodeSystemClass()+608)
F DEBUG : #02 pc ... /system/lib64/libndk_translation.so (Decoder<...>::Decode(unsigned int)+3924)
```

即 APK 只带 `arm64-v8a`，在 x86_64 上走 ndk_translation 指令翻译时被无法解码的 ARM 指令（Go 运行时/加密库中的系统寄存器访问）打死。
Frida 侧同样拿不到 Java 桥（`Java.available == false`，进程 arch 显示 `x64`）。
→ 与既往经验一致（arm64-only Go/Flutter 应用在 x86_64 模拟器上以 SIGILL 自毁），**动态 hook 这条路直接放弃，转纯静态**。

## 3. 静态路线（实际执行顺序）

1. **dex 字符串表直读**（不整包反编译也能定位）：自写 Python 解析 `string_ids`，全局搜 `configfile.json` →
   命中 `com/v2ray/ang/ui/HomeFragment` 与 `ServerStatusVIew`。
2. jadx 全量反编译（11564 类，约 4 分钟，101 个类反编译失败但无关）后读 `HomeFragment`：
   ```java
   InputStream open = getAssets().open("configfile.json");
   String b = kotlin.io.d.b(bufferedReader);
   String a5 = Hometab.Companion.a(b);                       // ← 解密入口
   ConfigData configData = gson.c(a5, new TypeToken<ConfigData>(){});
   ```
3. `Hometab.Companion.a(String)` 只是转发：`return Libv2ray.do_(str);` → **native**。
4. `Libv2ray.java` 里 `public static native String do_(String)`；
   `.dynsym` 找到 `Java_libv2ray_Libv2ray_do_1`，但真正的算法在 Go 侧：
   `_cgoexp_..._proxylibv2ray__DO` → `github.com/2dust/AndroidLibXrayLite.DO`。
5. **Go 1.24.3 pclntab 解析**（自写解析器，magic `0xFFFFFFF1`）拿到 36583 个函数名 → 地址，
   发现该分支新增了一批非标准导出：`DO / EO / GV / GC / Encrypt / decrypt / isSecured / CheckVersionX / Updateurl`。
6. `llvm-objdump -d`（NDK 27）反汇编 `AndroidLibXrayLite.decrypt`，配合 `bl` 目标符号化，一眼看懂算法：

```
bl  encoding/base64.(*Encoding).DecodeString
cmp x1, #0x1c                       ; 解码后必须 ≥ 28 字节
mov x1, #0x17 / mov x3, x2          ; 口令长度 23
ldp x2, x3, [x27] (0x355934)        ; "NewDecryptLibPas"
stur x2, [x0, #0xf]                 ; 第 15 字节起覆盖为 "sswordII"
mov x13,#3; mov x14,#0x2000; mov x15,#1; [sp,#8]=0x20
bl  golang.org/x/crypto/argon2.deriveKey
bl  crypto/aes.NewCipher
bl  crypto/cipher.NewGCM
ldr x13, [x0, #0x20] / blr x13      ; itab+0x20 = cipher.AEAD.Open
```

寄存器级解读（Go 寄存器 ABI，slice 占 3 个寄存器）：

| 参数 | 来源 | 含义 |
|---|---|---|
| `x0=2` | 立即数 | argon2 mode = argon2id |
| `x1..x3` | 新建缓冲 + 常量拼接 | password，len=cap=0x17(23) |
| `x4..x6` | `raw` 指针, len=0x10 | **salt = raw[0:16]** |
| `x7..x12` | 全 0 | secret / data 为空 |
| `x13=3 / x14=0x2000 / x15=1` | 立即数 | time=3 / memory=8192 KiB / threads=1 |
| `[sp+8]=0x20` | 栈传参 | keyLen = 32 |
| `Open` 的 `nonce` | `raw` 指针+0x10, len=0xc | **nonce = raw[16:28]** |
| `Open` 的 `ciphertext` | `raw` 指针+0x1c, len-0x1c | **ct = raw[28:]** |
| `Open` 的 `additionalData` | `raw` 指针, len=0x10 | **AAD = salt**（这一条最隐蔽：`x10` 被前面加载 `raw` 指针复用，容易看成空 AAD） |

7. `AndroidLibXrayLite.DO`（Java `do_` 实际走这条）是同一算法的**另一份内联拷贝**，差别只有两处：
   口令换成 21 字节的 `NewDecryptLibPassword`（rodata `0x352946` + `stur "Password"` 到第 13 字节），
   另带一个 18 次的调用计数/时间窗节流（`cmp x3,#0x12`），属行为逻辑不是加密。
   → 这与「`do_` 解整包、`decrypt`/`EO`/`GV` 解字段」的分工吻合。
8. **网关地址**：`main.proxylibv2ray__Updateurl` → `main.encodeString(rodata@0x37016a, 0x26)`，
   该常量正是 `https://strongteam.co/api/hightech/v1/`（`encodeString` 只是 gomobile 的 UTF-16 编码器，不涉及加密）。
9. **服务端「App Code」= User-Agent**：请求由 `defpackage.jb0`（Volley `StringRequest` 子类）发出，
   它重写了 `getHeaders()`：`hashMap.put("User-Agent", getString(R.string.app))`，
   而 `R.string.app` = `High Tech VPN`。缺这个 UA 时服务端返回 `404 Invalid App Code`（16 字节），
   补上即 `200` + 21908 字节密文。**没有任何签名/设备指纹/token 校验**。

## 4. 解密结果与节点拓扑

远端配置 `Version 1.11`：`Servers=5`、`Networks=9`。可配对出：

| 类别 | 数量 | 说明 |
|---|---|---|
| VLESS-WS-TLS（Cloud Run 中继） | 1 台服务器 × 5 条可用通道 | 前置域名分别是 `run.app` 本体 / `maps.gstatic.com` / `alt-00.maps.google.com` / `maps.google.ae` / `yt3.ggpht.com`(SNI) |
| Hysteria2 | 1 台（`88.99.142.235:443/udp`，Hetzner） | obfs `salamander`；同 IP 的 TCP 全超时，只能 UDP 探活 |
| OpenVPN | 25 条（`sg.boujeeteam.xyz` + `v2ray1..25.zamsytam.xyz`） | **已全部失效**，见下 |

一个反直觉但关键的发现：**同一台 VLESS 服务器，换 TLS SNI / 前置域名，服务端会把它路由到不同的落地出口**。
实测 6 条 URI 得到 6 个互不相同的出口（IE/Amazon、DE/G-Core、BR/G-Core、JP/G-Core、UA/G-Core、TR/G-Core），
且每条出口在 3 次探测中稳定不变。这让「一个后端」看起来像一个 6 出口的小型池。

## 5. 存活观测（第一轮结论被作废，见 `data/README.md`）

**先说结论：本轮没有取得可信的链路实测数据，原因是两次都被外部因素挡掉，不是节点参数错。**

### 5.1 第一次：测活串线（作废）

05:40–05:50 在 `127.0.0.1:31001-31012` 上跑测活/压测，得到「12/12 存活、6 个不同国家出口、P50 ~1.2 s、~1 MB/s」。
复核时发现本机常驻的 v2rayN `xray`（PID 38500，05:11 启动）已占用 `31000-31007`，我们的 mihomo 日志里是一排：

```
level=error msg="Listener in-vless-0-app listen err: listen tcp 127.0.0.1:31001: bind: ... in use"
```

即 mihomo 根本没绑上端口，`curl --socks5-hostname 127.0.0.1:31001` 打到的是**用户自己订阅的节点**。
这组数字因此**全部作废**（`data/probe-r1.json`、`bench-r1.json` 已删除）。

> 这条已固化为 `tools/probe.py` 的 `assert_own_listeners()`：启动 mihomo 后检查日志里有无 `listen err`，
> 有就退出码 3 失败 —— 端口被占时「TCB 有人监听」不等于「监听者是我」。
> 这类环境坑在没有独立出口校验时几乎无法从结果上看出来。

### 5.2 第二次：厂商中继故障（阻塞）

换到不冲突的 `33001-33012` 段（`grep -c "listen err"` == 0，确认自己的 mihomo 在监听）后：

```
level=warning msg="[TCP] dial vless-0-app --> ip-api.com:80 error: gcp2025-700385754130.us-central1.run.app:443 connect error: context deadline exceeded"
level=warning msg="[TCP] dial hy2-10 --> ip-api.com:80 error: context deadline exceeded"
```

直连该域名的观测（curl，非隧道）：

| 请求 | 结果 |
|---|---|
| `GET https://gcp2025-700385754130.us-central1.run.app/` | `503 Service Unavailable`，`server: Google Frontend`，`x-envoy-upstream-service-time: 3` |
| 同上 + WS 升级头 | `500 Internal Server Error`，带 `x-cloud-trace-context` |
| TCP 443 三次握手 | 正常（~120–240 ms），TLS 也能通（能拿到 Google 的错误页） |

TCP/TLS 都通、拿到的是 **Google 侧的错误页**，说明不是被墙、也不是我们的网络问题，而是
**该 Cloud Run 服务本身处于错误态/已下线**（503 = 无健康实例）。经本机已有隧道双跳同样不可达。
同时 Hysteria2 `88.99.142.235:443/udp` 完全静默（该 IP 的 TCP 443/22 本来就全超时，属正常）。

→ 判定：**待验证（被上游故障阻塞）**。中继恢复后按 `data/README.md` 里四条命令即可一键复测，
`tools/` 里的脚本已全部经过实跑（`--selftest`、实时拉取解密、listener 绑定检查、清单导出）。

### 5.3 已确认失效的分支

- `sg.boujeeteam.xyz` → DoH（`dns.google` + `1.1.1.1` 双源）`NXDOMAIN`，整个 `boujeeteam.xyz` 域不存在。
- `v2ray1..25.zamsytam.xyz` → 全部 `NXDOMAIN`（`zamsytam.xyz` 在 Cloudflare NS 上只剩 SOA，无 A 记录）。
- 结论：25 条 OVPN 配置仍在配置里下发（`DefaultOVPNCert` + `<OVPN_USER>/<OVPN_PASS>` 账号），
  **但域名已被删除，等于死节点**。厂商没有清理配置，这也是「不能相信下发列表」的又一条实例。

## 6. 合规判定

| 项 | 判定 |
|---|---|
| 逆向披露协议与算法 | 属研究行为，可公开 |
| 把该厂商节点接入自有生产代理池 | **不建议**：节点是运营方（`strongteam.co` / Telegram `t.me/htechvpn`）的商业基础设施，凭证泄露 ≠ 授权使用；流量走他人服务器会把风险与成本转嫁给对方 |
| 复制 APK 内置资产（`configfile.json`、`geoip.dat` 等） | 不随仓库分发（`.gitignore` 排除 `assets/`），需要者用自己手上的 APK 现取 |
| 文档中的凭证 | UUID / Hysteria 口令 / OVPN 账号在 `data/nodes.sample.json` 与文档中一律脱敏为 `<VLESS_UUID>`、`<HY2_AUTH>`、`<OVPN_USER>` |

## 7. 未做 / 待验证

- 未在**真机 arm64** 上跑通动态流程（模拟器 SIGILL），算法结论来自静态链路 + 实测解密成功（双向验证：本地实现的解密结果被真实服务端返回的密文验证，且 mihomo 用解出的参数成功建链）。
- `Networks[]` 中 `CF Worker` / `Xhttp` / `Custom-1` 通道本版本没有对应服务器或需要额外前置，未覆盖。
- `AndroidLibXrayLite.GV/GC/EO/PO/SO/Sp/isSecured` 只做了用途归类（字段取值/加密、校验与设备信息上报），未逐条寄存器级还原。
- 厂商出口池规模未知（只观测到 6 个稳定的 SNI→出口映射，未穷举）。
