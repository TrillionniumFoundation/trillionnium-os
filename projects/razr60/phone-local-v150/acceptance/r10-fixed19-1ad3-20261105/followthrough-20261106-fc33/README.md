# Fixed19 followthrough — 2026-11-06

## 当前结论

本目录保存两组独立源码候选与一次已对账的真实恢复失败。**新增整项通过数为 0；没有把主机回归计为手机实机资格。** 原 NEG-01 的组件通过保留，新候选尚未形成正式四角色 READY 组合。

- 当前冻结 runtime 的 37/37 文件全量读回并匹配长度与 SHA256；原 manifest 复读未变，详见 native-streams/evidence/runtime37-hash-summary.json。
- native 输出解析候选通过 **42/42** 个留存 Mac 检查，修复事件次序、未知事件和 Python 数值类型别名；只改 native_streams 与 daily 依赖哈希。
- install／READY 读回候选通过 **67/67** 个留存 Mac 检查，拒绝游标、计数、截断标志和进程身份的 bool/float 冒充；执行协议原字节不变。
- 两个候选均未部署，未填造正式输入或 execution plan。
- NEG-02 的唯一清理任务曾在 MCP 返回超时，随后找回原任务 **1a1b10ebd5e-fc05-756b**。真实 actor exit 0、phone rc 1；首个删除前被目录／别名／传输父目录一致性 gate 拒绝，已记录删除数 **0**。清理仍未闭合。

## 实机状态与下一条件

| 用例 | 本 checkpoint 的证据判断 | 仍需完成 |
| --- | --- | --- |
| E2E-01 | 未取得当前完整业务资格 | 新截图进入本地模型；一次选择；公开回执和挑战码一致；实际回 HEPTA |
| E2E-02 | 保留历史成功；当前整项待验 | 中文、emoji、LF 精确输入/确认/读回/回执/返回 |
| E2E-03 | 保留历史基础；当前组合待验 | 新随机表达式、可见结果、独立计算和要求的返回 |
| E2E-04 | 保留历史基础；当前组合待验 | 当前唯一版本字段、包/焦点独立核实；不修改设置 |
| COMP-01 | 冻结导航源码不等于实机闭环 | launch、Activity、焦点、top-resumed 一致 |
| NEG-01 | 原组件通过保留；不转授给新候选 | 在合法正式组合中纳入原证据或补对应证据 |
| NEG-02 | 原发送 0 次；恢复新尝试首删前拒绝、删除 0 | 查明五组比较具体差异，合法恢复后验证同 viewport/focus 内容变更在 input 前 exit 71 |
| NEG-03 | 当前完整资格待补 | 拒绝未资格外屏/旋转配置，不能向其他屏注入 |
| NEG-04 | 历史主机证据保留 | 当前物理任务 dispatch 前断连、零派发、无重放 |
| NEG-05 | 历史主机证据保留 | 效果开始后断连、至多一次、未知不重执行 |
| NEG-06 | 当前完整汇总未取得 | 有界超时、零派发、原进程组清理、无隐藏 fallback |
| NEG-07 | 历史主机证据保留 | 物理执行器超时；迟到结果不改终态、不造成第二次效果 |
| NEG-08 | 历史主机证据保留 | 物理 dispatch 前取消、零效果及清理 |
| NEG-09 | 历史主机证据保留 | 首次效果后取消、保留已有效果、不继续输入或强制返回 |
| NEG-10 | 新候选含四个实际 map 图像拒绝分支回归 | 正式组合下非法图像 dispatch 前拒绝的完整证据 |
| NEG-11 | 新候选解析回归通过 | 正式组合下身份/序列/长度/终态/截断/哈希全部拒绝证据 |
| NEG-12 | 历史独立源码候选结果保留 | 最终组合缺确认/回执/返回时失败并列缺失条件 |
| NEG-13 | 历史独立源码候选结果保留 | 最终组合一次绑定、错误 scope 不消费、旧身份不派发 |
| NEG-14 | 新候选部分真实文件系统和资源基线回归通过 | 完整容量/竞态/未知 I/O 拒绝及任务资源实测收尾 |

## 文件与复现

[native-streams/README.md](native-streams/README.md) 说明 42 项的具体范围、源码 derivation、运行方法及未覆盖条件。[install-reader/RESULTS-AND-LIMITS.md](install-reader/RESULTS-AND-LIMITS.md) 说明 67 项留存结果与四项 Linux 观察不能冒充 Mac 留存证据的界限。

[STATE.json](STATE.json) 是本次明确状态；[cleanup/ORIGINAL-ATTEMPT-RECONCILIATION.json](cleanup/ORIGINAL-ATTEMPT-RECONCILIATION.json) 是真实唯一清理任务的派生摘要，原始进程与手机结果另有保全。摘要不取代原件。

旧归档 OBS 与 TARGET 的五组结构全部相等。源码精查确认这些比较结构使用 dict/list，没有 tuple/list 修复依据。实际不同字段尚未取得：不得因此放宽 full9、names、别名或父目录等值条件，不得覆盖原失败身份或重放未知请求。

候选会改变源码身份；后续必须完成新组合 derivation/adoption、实际 BUILD/install/READY 及相应用例证据。当前保留旧 source seal、失败记录及其他 final02 的 UNKNOWN 状态。
