# 自适应网络优化工具（Adaptive Network Optimizer）

**v0.2.2 · Windows 11 · 简体中文 · 只读测试原型**

不依赖第三方 Python 库，不需要管理员权限，不修改注册表、DNS、MTU、防火墙、代理或 TCP 参数。

## 启动

需要 Python 3.10+（含 Tkinter）。如果尚未安装，可在 PowerShell 运行 `winget install --id Python.Python.3.13 -e`，完成后重新打开终端。解压本项目，双击 `start.cmd`，或在项目目录执行 `python app.py`。

## 测量过程

1. 读取 Windows 已连接网卡、DNS、默认路由、接口 MTU。将已连接 IPv4 网卡的 DNS 纳入比较，不假设它们就是浏览器实际使用的解析器。
2. 以同一批公开域名对各候选 DNS 执行 A 记录查询；轮换查询顺序，重复 3 或 5 次。直接向 UDP 53 查询，遇截断时尝试 TCP；验证交易 ID、问题、响应及 A/CNAME 记录。DNS 服务商可以记录查询，请勿输入私人/内网域名。
3. 统计每组成功次数、延迟中位数、P95（最近秩法）。只对全部成功的组推荐；当现有 DNS 的中位数不超过最快者的 110% + 2ms，且 P95 不超过最快者的 120% + 5ms，优先保留现有 DNS。阈值为第一版保守策略，不是网络标准。
4. 分别向 Cloudflare 的 IPv4、IPv6 地址 TCP 443 建立连接，记录 5 次连接结果。仅代表这两个目标的可达性和 TCP 握手耗时，不表示网站速度，也不是严格的网络层丢包率。
5. 可选探测指定公开 IPv4 目标的 MTU：Windows `ping.exe -4 -f -l`，每种载荷尝试 3 次；根据三次均成功的最大探测包估计路径可通过大小（载荷 + 28 字节）。仅覆盖至 1500 字节；小包无法稳定通过时不提供结果。ICMP 过滤、随机丢包及路由变化均可能干扰估计。
6. 在 `Downloads/AdaptiveNetworkOptimizer/` 创建独立报告目录，导出 `report.html`（图表和摘要）、`report.json`（含原始样本、网络配置与警告）、`dns_samples.csv`、`dns_summary.csv`。报告仅保存在本机，但含本地网卡、DNS 和路由等信息，分享前请检查。

## 边界与验收

- DNS 候选仅测试直接 IPv4 DNS UDP/TCP 53，不测试 DoH、DoT、IPv6 DNS、系统缓存或代理内的解析。不同解析器可能返回不同 CDN 地址。没有 DNSSEC 验证，不承诺查询未经透明转发或干扰；解析延迟低不等于下载吞吐量高。
- 不自动选择双 DNS 配对，不修改系统设置，不覆盖企业/VPN 的分流或私有解析规则。
- MTU 探测仅为特定路径估计，不自动推荐网卡 MTU。若高载荷失败，不能直接认定是 MTU 太大。
- 尚未实现 TCP 拥塞控制寻优、代理节点寻优、配置事务及回滚；这些应单独验收。
- `python -m unittest -v`：本地模拟 DNS UDP/TCP 服务器和确定性数据测试，无需外网。Linux 环境下通过；Windows GUI、真实网络、PowerShell 系统信息采集、Windows ping 输出解析仍需实机验收。

## v0.1.1：实验有效性验证

- 识别活动代理/VPN/TUN 网卡名称、198.18.0.0/15 DNS/路由及半默认路由。该地址段用于基准测试，也常用于 Fake-IP；命中只表示疑似接管，不证明代理品牌或真实上游。
- 检查每个成功样本的 A 地址；Fake-IP、非公网地址或缺少应答证据均阻止公网 DNS 推荐。相同公网地址不单独判定劫持（CDN 可能正常重合）。
- DNS 实验前后重新读取配置，比较网卡、DNS 和默认/半默认路由；快照缺失、配置变化或缺少当前 DNS 基线时拒绝推荐。
- JSON 增加 version、snapshot_after_dns、validity（环境分类、原因代码、证据计数和涉及的候选）；CSV 增加 sample_complete 与 eligible 的区分。保留被干扰的原始测量，但 GUI/HTML 不再给出错误排名或候选推荐。
- no_known_proxy_indicators 仅表示未发现已知迹象，不证明直连；不探测所有系统代理、WFP/透明转发或上游身份，不自动关闭代理。TCP/MTU 仍为当前实际路径的诊断，不代表物理网卡或公网端到端性能。
- 保持只读；建议在可接受的情况下由用户自行选择另一网络状态，重新运行并比较独立报告。不要因本工具的结果直接改 DNS/MTU 或禁用 IPv6。

## v0.2.0：实际网络性能基准

- 默认开启 HTTPS 与 ICMP；TCP 443 对 Cloudflare、Google、Quad9 各一组 IPv4/IPv6 公共地址分别测 5 次，统计中位、P95 和相邻成功样本的绝对差均值（不跨失败样本，不是 RFC 定义的单向抖动）。
- Windows PowerShell/.NET Ping 返回结构化状态，统计每个目标的 ICMP 无应答率、RTT 和波动。ICMP 可能被防火墙、代理或目的端限速/过滤，不能等同于物理链路丢包率。全为本地异常时标为不可测。
- HTTPS 使用系统可用 curl，默认保留环境代理规则，不强制直连、不关闭证书校验、不跟随重定向、不重试。测量 Cloudflare 零字节端点、Google 204 和 GitHub API zen；吞吐量仅用 Cloudflare 官方测速接口固定 1/2/4 MiB，每组 3/5 轮、轮换顺序。缺少 curl 时跳过 HTTPS，保留其他数据。
- 解析 curl 累计计时，计算 DNS、TCP、TLS 阶段差值、TTFB、总耗时；代理 CONNECT 可能计入 TLS、TCP 可能连接代理、DNS 可能为本地代理。只有 2xx、退出码正常、字节数与预期及本地文件一致、计时有效才计入统计。有效 Mbps = 字节×8/总秒数/10^6；正文 Mbps 使用总时间减 TTFB，过短时不估计。403/429 停止该目标（Cloudflare 两个端点一起停止）。固定小样本并非最大带宽或长期速度测试。
- 默认测速正文计划 3 MiB，加上小请求；设置上限、请求超时和文件体积监控，临时文件自动清理。旧版 curl 对未知长度的限制可能有滞后，不承诺硬流量上限；取消最多等待当前有超时的探测返回。
- 即使 DNS 推荐被拦截，也保留当前实际路径的 HTTPS/TCP/ICMP 观测。记录性能前后配置快照及环境标记、测试计划和目标；快照一致不证明代理节点或路径未变化，不自动跨报告判断改善。`report.json` 增加 performance、performance_baseline、snapshot_after_performance；HTML 增加性能表，四个 performance_*.csv 导出原始或汇总数据。
- 仍为只读，不改网络配置；代理节点、用户身份、浏览器使用的实际协议未必可见。IPv6 多目标失败也不能证明系统完全不支持 IPv6。没有实现独立基线自动比较、代理节点优化、上传测速或安全回滚。
- 参考：curl https://curl.se/docs/manpage.html；Cloudflare 测速接口 https://github.com/cloudflare/speedtest；Google DNS https://developers.google.com/speed/public-dns/docs/using；Quad9 https://docs.quad9.net/services/。

## 下一阶段

先验收 v0.2.0 的真实网络数据，再开发独立基线对照、显式批准且可回滚的配置变更。不同实验分开进行，避免混淆因果。

## 参考

- RFC 1035: https://www.rfc-editor.org/rfc/rfc1035
- Windows DNS 配置读取: https://learn.microsoft.com/powershell/module/dnsclient/get-dnsclientserveraddress
- Windows 路由读取: https://learn.microsoft.com/powershell/module/nettcpip/get-netroute

## v0.2.1：自适应采样与失败证据

- 下载先进行 128 KiB 预探测，按实测速率选择 64 KiB 至用户上限的固定样本，预探测不参与正式统计。正式样本最多补测两次；阶段预算 210 秒，计划正文预算为 128 KiB + (轮数 + 2) × 上限，非硬流量上限。
- curl 失败记录退出码、阶段原始计时、已接收字节和分类；仅完整成功样本计入速度。TCP 记录异常类型、errno、winerror；ICMP 保留异常类型、HResult、可用的 socket 错误码，异常样本不纳入无应答率；IPv6 ICMP 不可用仍不等于丢包。
- 正式下载质量要求成功数不少于设定轮数、完成率至少 80%、成功速度最大值不超过最小值两倍、样本大小及 HTTP 版本一致。阈值为保守工程策略，非统计置信保证；即使通过也仅是候选基线，不自动调参。
- 未改变系统设置，不保证识别代理实际节点或故障根因。真实网络和 Windows GUI 仍需实机验收。

## v0.2.2：动态网络环境感知

- DNS 与性能实验期间每隔约 15 秒采集一次配置，最多 120 次周期采样，另保留三个阶段快照；采样串行、有超时，实际间隔包含采集耗时。记录 UTC 偏移时间、单调时钟秒数及采集耗时。监测失败、采样间隙和代理内部变化仍可能影响判断。
- 采集 AutomaticMetric、Get-NetAdapter 链路速率（含可用收发速率）、netsh WLAN 信号及收发协商速率；无线仅解析中英日常见字段，权限不足、未连接或未知语言时标记不可用。不保存 SSID、BSSID、MAC、无线配置文件或原始 netsh 输出。Windows 可能要求位置权限；工具不修改或绕过权限。链路速率并非互联网带宽。
- 按接口索引/地址族及路由身份逐字段差分，记录观测时间区间；启用自动跃点数时的 metric 变化仅标记可能自动调整，不证明链路速率造成变化或修改者身份。链路遥测不作为配置签名字段。阶段内观察到配置变化或快照缺失时拒绝 DNS 推荐或性能基线（即使首尾恢复）。
- IPv6 诊断统计 WSAEACCES 10013，保留 ICMP NativeErrorCode，并读取防火墙配置、IPv6 网卡绑定和地址状态计数；不读取安全事件日志、不修改规则、不确定具体拦截组件。报告包含本地网络信息，分享前检查。
- JSON 增加 environment_monitor；HTML 增加差分和时间线，另导出 environment_changes.csv、adapter_link_timeline.csv、wlan_timeline.csv。周期采集会增加少量系统负载，不能证明采样间隙不变；仍不进行自动调参。
- 参考 Microsoft Learn：Get-NetIPInterface、Get-NetAdapter、Get-NetFirewallProfile、Windows Sockets Error Codes。
