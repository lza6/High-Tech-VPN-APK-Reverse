# data/ 说明

| 文件 | 内容 | 状态 |
|---|---|---|
| `nodes.sample.json` | 由 `tools/refresh.py` 对**厂商实时配置**解析出的节点清单（凭证已脱敏为 `<VLESS_UUID>` / `<HY2_AUTH>` / `<OVPN_USER>`），33 条 = 5×VLESS-WS-TLS + 2×Hysteria2 + 25×OpenVPN（后者域名已失效，见 REVERSE_REPORT §5） | 已验证（结构来自真实 API 响应） |
| `probe-r1.json` / `bench-r1.json` | **已删除**，见下 | 作废 |

## 为什么第一轮实测数据被作废

第一轮测活/压测（05:40–05:50）结论是「12/12 存活、6 个不同国家出口、P50 ~1.2s、~1 MB/s」。
收工前复核时发现这些数字**不可信**：

1. 本机常驻的 v2rayN `xray` 实例（PID 38500，05:11 启动）已经占用了 `127.0.0.1:31000-31007`；
2. 我们的 mihomo 用同样的 3100x 段做 listener，日志里留下：

   ```
   level=error msg="Listener in-vless-0-app listen err: listen tcp 127.0.0.1:31001: bind:
   Only one usage of each socket address ... is normally permitted."
   ```

   即 mihomo 没绑上，`curl --socks5-hostname 127.0.0.1:31001` 打到的是**用户自己订阅的节点**。
3. 换成不冲突的 `33000` 段重新绑定（`grep -c "listen err" == 0`）后，所有节点在厂商侧全部不可达，
   与「12/12 存活」直接矛盾 —— 进一步确认上一轮是串线。

**教训（已写进 `tools/probe.py`）**：测活脚本必须在启动 mihomo 后检查日志里有没有 `listen err`，
一旦端口被占就立即失败退出，否则会把别人的节点当成本次目标节点的实测结果。
「TCP 端口有人监听」不等于「监听者是我的 mihomo」。

## 那现在有什么可信证据？

- **协议/算法**：`tools/ht_decrypt.py` 是独立实现（不是调用 APK），能把厂商 `200` 响应里的 21908 字节密文解成完整 JSON，
  且 `--selftest` 能用自己的封装/解封往返，说明信封格式与 KDF 参数正确 —— 这是**已验证**。
- **节点参数**：解出的 UUID / WS path / 前置域名 / SNI / Host / Hysteria2 obfs 参数完整，能直接构造出合法 URI 与 mihomo 配置 —— **已验证（静态 + 解密产物）**。
- **链路可用性**：采样窗口内厂商 Cloud Run 中继返回 `503 Service Unavailable`（GET）与 `500`（WS 升级），
  Hysteria2 `88.99.142.235:443/udp` 静默，经本机已有隧道双跳亦不可达 → **待验证（被上游故障阻塞）**。

复测方式（中继恢复后一条命令）：

```bash
python tools/refresh.py --out-dir out --base-port 33000 --upstream socks5h://127.0.0.1:10808
python tools/probe.py --out-dir out        # 会自动起 mihomo 并检查 listen err
python tools/bench.py --out-dir out
python tools/export_proxies.py --out-dir out
```
