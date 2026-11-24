# 自适应网络优化工具（Adaptive Network Optimizer）

**v0.1.0 · Windows 11 · 简体中文 · 只读测试原型**

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
- 尚未实现吞吐量基准测试、真实 ICMP 丢包统计、TCP 拥塞控制寻优、代理节点寻优、配置事务及回滚；这些应单独验收。
- `python -m unittest -v`：本地模拟 DNS UDP/TCP 服务器和确定性数据测试，无需外网。Linux 环境下通过；Windows GUI、真实网络、PowerShell 系统信息采集、Windows ping 输出解析仍需实机验收。

## 下一阶段

增加固定测试目标的 HTTPS 实际传输性能与抖动检测；建立配置前后基线；再开发显式批准、可回滚的 DNS 变更。不同实验分开进行，避免混淆因果。

## 参考

- RFC 1035: https://www.rfc-editor.org/rfc/rfc1035
- Windows DNS 配置读取: https://learn.microsoft.com/powershell/module/dnsclient/get-dnsclientserveraddress
- Windows 路由读取: https://learn.microsoft.com/powershell/module/nettcpip/get-netroute
