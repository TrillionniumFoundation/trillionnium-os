# 2026-11-07 原任务收尾与源码后继证据

统一状态入口在项目根 `CURRENT.md` / `CURRENT.json`。此目录是一组有界观察和 source-only 交付，不是原 bound02 的 accepted closure，也没有新增 fixed19 credit。

| 文件 | 内容 |
| --- | --- |
| [ORIGINAL-RECONCILIATION.json](ORIGINAL-RECONCILIATION.json) | 原 job / PLAN / REQUEST / 原件 / 远端所有权、UNKNOWN 和草稿义务 |
| [RECOVERY-RESULTS.json](RECOVERY-RESULTS.json) | 两次不同 recovery 的原始结果与独立读者，严格分账 |
| [NATIVE-OBSERVATION.json](NATIVE-OBSERVATION.json) | 一次按原 REQUEST 哈希的只读手机查询及原件，不能证明原任务未执行 |
| [EXIT137-ANALYSIS.json](EXIT137-ANALYSIS.json) | 137/Killed 的已知证据与未知原因 |
| [SOURCE-SELECTION.json](SOURCE-SELECTION.json) | 唯一选中源码后继、完整 hash 和尚未重绑的运行边 |
| [TRANSPORT-CONFIG-DESCRIPTOR.json](TRANSPORT-CONFIG-DESCRIPTOR.json) | 私有配置完整原件的字节数、hash、version 与元数据；不含 body |
| [BUDGETS.json](BUDGETS.json) | 原冻结预算对象及明确规范化 hash |
| [FIXED19-LEDGER.json](FIXED19-LEDGER.json) | 当前 19 项规定层、原件槽与真实 blocker |
| [BUILD-RUNBOOK.md](BUILD-RUNBOOK.md) | actual BUILD、安装、READY、健康与 P2 的既有读者顺序 |
| [PROTOCOL-MAP.json](PROTOCOL-MAP.json) | 精确协议与 source 位置映射 |
| [ci/CANDIDATE-ADOPTION.md](ci/CANDIDATE-ADOPTION.md) | 候选采用决定、失败检查解释与 provenance |

`originals/` 中每件标注 original 的文件保留完整读取字节并核对原 SHA256；`observations/` 中 MCP 响应按 JSON 重新序列化，只作为观察回执，不能冒充远端原文件。私有 REQUEST 和用户草稿只保留原位置及 descriptor，不公开内容。完整公共清单在 `DELIVERY-MANIFEST.json`，清单自身由提交的 tree/blob 身份绑定。
