# 导航与 sender deadline 独立发布审查

结论：可作为未采用的隔离源码候选及有限主机证据公开纳入；没有发现需阻断本导航包发布的问题。冻结 R6 和整项资格不变。

- ARTIFACTS-v2 的23个文件均与清单长度/hash一致；补丁精确等于保留原源码到候选源码的差异。
- deadline 从 shell 入口、route 之前开始，剩余预算用于 listener检查、connect、send、handshake、头/负载读取和最终成功返回检查。线协议、数值预算和重试数量保持，旧 standalone helper 的可选 deadline 参数保留兼容性。
- 原 socketpair 证据在0.2秒预算下约0.405秒仍成功，支持“单次recv超时并不保证整体观察deadline”的独立缺陷。候选 drip/silence 约0.201秒超时；成功与exit137保留；route耗尽后零shell请求。这里只审了原代码和原证据，没有额外重跑测试。
- README及机器证据明确137的实际根因UNKNOWN、远端PID/PGID/kill/join未核实、关闭本地socket不构成远端收尾证明，固定19信用0，候选未采用。实现及证据不应描述成严格实时调度保证、整个actor deadline或远端进程清理。
- dependencies/control_send_once.read.original.json 与6301字节固定helper源码完整逐字一致。它包含固定的历史控制测试prompt及设备serial、源码路径与文件指纹；没有动态runtime config、实际XML、用户草稿正文、私有幂等key、凭证或配置SSH target。无需为了本次公开范围对该原读回包进行脱敏。

此导航包的通过不解除此前 CONTROLLER-RECONCILIATION.PUBLIC.json 的嵌套SSH target脱敏问题。父README历史正文仍需提供基准字节后单独比对。
