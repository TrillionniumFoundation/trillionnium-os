# Fixed19 全量推进：检查点 06

当前正式组合尚未新增整项通过。工作目标仍是把全部 19 项在同一最终组合下闭合；源码回归、准备包和旧组合成功分别保留各自范围。

## 当前实际状态

最终 15 个生产源码、17 个共享材料和 38 个组件运行时已在主机实际冻结；完整冻结目录为 18,364,398 字节。独立 preparer 随后全量重读冻结目录、双完成记录和原输入，实际通过。当前 runtime manifest 为 `990c726a1fff139761494cc19cf091deb269201f27ea947dda4a5833e3a72f2a`，组合为 `7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411`。

本次 `root-r10-neg01-fc33-bound01` 在实际手机 stage 的共享父目录检查失败，协调器 exit 1。精确执行源、全部七个已发生阶段、Mac 115 个文件及 Pocket4 发送标记交叉确认：尚未创建本次组件 home，未进入 sender-preview 或 sender-execute。手机 material/source push 与 stage 尝试已经发生，不能表述为手机零效果。唯一 nonce 已永久消费，原任务不会重放。

Root 的单次只读手机观察发现，两个父目录别名和两次采样均为 17 个成员、nlink 19；当前基线要求 16/18。唯一额外成员是既有 `root-r10-neg02-a1055-final05`。该任务属于旧组合，原 sender 报告零 Send 并恢复草稿；lifecycle 原件报告失败，尚缺完整独立远端角色收尾和安全恢复证明。它被保留，不被添加为成功 source-parent，也不放宽目录门槛。

旧 NEG-02 final04 的清理由原执行者 cleanup02 完成，已有独立公开验证器重放与完整 44 根 inventory 对照。我们的后发清理仍是预检失败、零移除。旧 final02 的未知终态仍为 UNKNOWN。新增 final05 是独立的当前阻塞项。

## 本检查点新增的可复核材料

| 路径 | 内容 | 实际边界 |
| --- | --- | --- |
| physical-neg03-09-source/ | 328 份物理故障验证源码、原件、控制与执行计划 | 未实际运行手机物理任务 |
| e2e-source-plan/ | 90 份 E2E/COMP 源码、完整逆向、绑定器与关闭条件 | 未运行新业务用例 |
| install-ready-input-templates/ | 40 份安装、保全和 READY 输入模板；295 个未绑定槽 | BUILD、install、READY 均未发生 |
| release-source-binding-r5-990-hold/ | 10 份精确绑定到 990c runtime 的源码候选 | 源码发布尝试在写入前失败；实际派生未调用 |
| neg01-stage-host-evidence/ | 15 份安全公开失败证据；30 份原件共 77,606 字节 | 本次未到 sender；不声称全局无任务或清理闭合 |

新增 483 个文件的本地长度、SHA256 和 Git blob SHA1 已逐一核对；五份映射一同保全。私有 stdin、原草稿和内层 payload 的正文未导出，只保留实际主机外层 descriptor。完整审计日志采用只读全文件与压缩转运保全，未把首尾分页冒充连续完整 process_read。

## 后续依赖

先核实 final05 的完整原材料、私有树、已知进程与内核缺席、原 44 根基线；任何缺失均保持未闭合。恢复成立后，采用独立审阅的新身份继续 NEG-01、NEG-02。两项当前组件原件闭合后，再完成实际 BUILD、安装、四角色 READY、E2E/COMP 和物理故障任务，并汇总最终源码上的 NEG-10 至 NEG-14。

旧 NEG-01 成功只属于原组合。所有 source-only 或 synthetic 控制均明确标注，不提供当前整项资格。

## 源码发布与归档的实际边界

E2E 原映射只计算本地 Git SHA1；首次创建 Git tree 因 blob 缺失而拒绝，分支未移动。随后 90 份文件逐项实际 create_blob 并核返回 SHA，回执见 e2e-source-plan/ACTUAL-GITHUB-PUBLICATION.json。原映射未改写。

R5 下游主机发布入口第一次运行在完整字节逆向检查处 exit 1：JSON 排序改变 descriptor 的 Python repr 字节。拒绝发生在发布前；后续独立只读主机观察确认两个输出目录均 ENOENT。完整 controller 保全于 runtime-r5/source-publication-attempt01/；修复将统一生成顺序并保留原逐字校验，不修改生产源码。

后继 NEG-01 preparer 仅准备了独立源：新标签 bound02、显式排除两枚已消费 nonce。尚未发布、生成身份或派发，仍要求先通过完整恢复与新鲜基线准入。
