# Fixed19 followthrough — 2026-11-06

## 后续 checkpoint（2026-11-06 14:23:52 UTC）

新的只读现场采集已结束并完整对账。全部 192 份原件、77 个 owned 文件、9 个目录、stage aliases 及两个 transport parents 都相同；唯一差异是 XML 父目录 /proc/1/root/data/local/tmp 的 mtime/ctime。其身份、权限、大小和全部 881 个成员名未变，采集 before/after 相等。原失败清理仍为零删除，后继恢复尚未执行。完整分析及原件 SHA 见 [cleanup/postfailure-capture/RESULT.original.json](cleanup/postfailure-capture/RESULT.original.json)。

新增 [NEG-12/13 共享实现主机包](neg12-13-host/README.md)：完整 15 文件真实导入、14 个选择性场景通过，包括真实 O_EXCL 双线程竞争和 pipe admission；owner/public 数据全部明确为 synthetic，不闭合整项实机用例。

新增 [安装 reader environment-v2 候选](install-reader-env-v2/README.md)：72 项通过，包含前 67 项与 5 项环境控制；独立复跑仍是同一 72 项。实际 BUILD/安装/READY slots 未绑定，[入口与缺口清单](install-reader-env-v2/ENTRYPOINTS-AND-INPUT-GAPS.md) 说明正式链路仍需哪些真实原件。

另外，[native metadata 覆盖复现](native-metadata-coverage/LIMITS.json) 在未修改的 22580b 候选中确认 7 类未校验元数据可在 synthetic receipt 下形成真实共享业务完成结论：错 target、object target、bool/float PID、float event/terminal elapsed、exited/0 配合 signal。它证明消费端校验缺口，不是已部署攻击入口证明；当前 NEG-11 保持未关闭，独立 v2 修复仍在准备。

## 首次 checkpoint 的结论

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
| NEG-02 | 原发送 0 次；恢复首删前拒绝、删除 0；已定位唯一 XML 父目录时间戳变化 | 绑定新完整 profile 合法恢复后，验证同 viewport/focus 内容变更在 input 前 exit 71 |
| NEG-03 | 当前完整资格待补 | 拒绝未资格外屏/旋转配置，不能向其他屏注入 |
| NEG-04 | 历史主机证据保留 | 当前物理任务 dispatch 前断连、零派发、无重放 |
| NEG-05 | 历史主机证据保留 | 效果开始后断连、至多一次、未知不重执行 |
| NEG-06 | 当前完整汇总未取得 | 有界超时、零派发、原进程组清理、无隐藏 fallback |
| NEG-07 | 历史主机证据保留 | 物理执行器超时；迟到结果不改终态、不造成第二次效果 |
| NEG-08 | 历史主机证据保留 | 物理 dispatch 前取消、零效果及清理 |
| NEG-09 | 历史主机证据保留 | 首次效果后取消、保留已有效果、不继续输入或强制返回 |
| NEG-10 | 新候选含四个实际 map 图像拒绝分支回归 | 正式组合下非法图像 dispatch 前拒绝的完整证据 |
| NEG-11 | 原 42 检查保留；另复现 7 类 native metadata 消费缺口 | 完成独立 v2 修复及正式组合下完整损坏拒绝证据 |
| NEG-12 | 当前 15 源共享实现的缺确认/回执/返回拒绝与 partial coverage 主机场景通过 | 最终组合完整业务/物理证据 |
| NEG-13 | 当前 15 源真实 O_EXCL 竞争、错误 scope 与旧身份 pipe admission 主机场景通过 | 最终组合一次绑定、错误 scope 不消费、旧身份不派发的完整证据 |
| NEG-14 | 新候选部分真实文件系统和资源基线回归通过 | 完整容量/竞态/未知 I/O 拒绝及任务资源实测收尾 |

## 文件与复现

[native-streams/README.md](native-streams/README.md) 说明 42 项的具体范围、源码 derivation、运行方法及未覆盖条件。[install-reader/RESULTS-AND-LIMITS.md](install-reader/RESULTS-AND-LIMITS.md) 说明 67 项留存结果与四项 Linux 观察不能冒充 Mac 留存证据的界限。

[STATE.json](STATE.json) 是本次明确状态；[cleanup/ORIGINAL-ATTEMPT-RECONCILIATION.json](cleanup/ORIGINAL-ATTEMPT-RECONCILIATION.json) 是真实唯一清理任务的派生摘要，原始进程与手机结果另有保全。摘要不取代原件。

旧归档 OBS 与 TARGET 的五组结构全部相等。源码精查确认这些比较结构使用 dict/list，没有 tuple/list 修复依据。后续已取得的精确差异仅为 XML 父目录 mtime/ctime：不得因此放宽 full9、names、别名或父目录等值条件，不得覆盖原失败身份或重放旧请求。

候选会改变源码身份；后续必须完成新组合 derivation/adoption、实际 BUILD/install/READY 及相应用例证据。当前保留旧 source seal、失败记录及其他 final02 的 UNKNOWN 状态。
