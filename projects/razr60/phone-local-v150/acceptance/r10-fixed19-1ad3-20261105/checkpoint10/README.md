# Checkpoint10 — 两项真实主机历史审计与固定载体证据

本检查点只在 a87b2fc4b99880e3820d2fffd285943777ac4057 / tree 1d17fcaae320ce053f54e90de3cee1322f7a4613 之后追加。E2E01–04、COMP01、NEG01–14 共 19 个整项验收仍为 **0/19**。已有 host 层 NEG04/05/07/08/09 的 5/5，以及 policy post-comparison 的 16/16 分别保留；本次历史审计和数据暂存不增加物理或业务案例通过数。

## 本次纳入的实际完成证据

Policy 历史 owned audit02 已实际完成一次。控制器、实际子进程 JOIN、双 EOF、全部 12 份输出正文及实际 source/action 来源均已独立核对。原验证函数消费了 554 个完整原件，555 项书签保持；原路径正文合计 31,518,321 字节，332 个不同正文合计 23,893,406 字节。原审计器的物理读取计量为 64,570,651 字节；它的 64 MiB 域与外层 caller 的 16 MiB 域分别核验，未混为一个预算。该审计器耗时约 8.664 秒。此前写出 INTENT 后因 Mac 目录检查拒绝的 attempt01、实际目录行为诊断、对应窄修和全部失败回执都保留，旧失败未改写成成功。

Policy 的 10 个新 Mac 数据载体已实际 create-only 暂存并完成独立 native 全量回读。正文总计 192,950 字节，暂存器两次完整读取计 385,900 字节；每份 bytes/SHA 与实际 full9 对照，native version 的五个字段没有冒充全部九项元数据。真实父目录名称 1613→1614，只有指定目录增加；输出加完整展开名称计 252,385 字节，仍在 262,144 原限内。两份解码名称正文始终标为派生数据，不伪装为额外现场观察。已核实的固定 evidence 允许后继源码显式绑定；本检查点不声称 final runtime 已可执行。

Retained6077 历史分支的独立 P4 owned host audit01 也已实际完成一次。控制器0、子进程3395490真实代际/JOIN、双 EOF 和自有输出收尾完整。原160条 Guard读集、137个历史 host 输入 full9、原 ec20 完整归档278成员及原277条 CAPTURE记录都由固定受审主机实现复算；49字段闭件的完整55,184字节精确等于历史35af原件。保留 native_status=provider_failed、actual_native_calls=1、原 sender unknown，以及组件/业务资格为false；这不是重跑旧native动作或创建新边界。新审计耗时约12.459秒，caller计量3,384,642字节和320,136字节元数据。

该审计的40个实际输出已通过9次小文件batch与23个固定版本binary块完整读回，共1,660,670字节。31条完整full9与native五字段version独立相符，其他原件不补造未观察字段。源、controller、owned child、25份audit输出和8份caller输出全链已核。所有请求、原始DTO、块、原正文和独立报告都保留。

## 已封存的源码与载体计划

6077纯验证器已冻结carrier-v2后继：原P4语义路径及full9留在真实source/action/readset中，52组固定origin→Mac carrier逐体bytes/SHA相等；54个实际callback路径包括两份数据包，返回used只代表这些物理载体。外部source binding仍为None，packet不能自行授权。消费域只包含完整source/action/output/readset及固定依赖，不把137个深层原件或2.4 MiB归档重新列为手机mandatory callback。已准备58个regular文件的只落盘数据包及固定stage计划，但**本检查点不包含随后发生的6077实际Mac carrier stage或其读回**，两者须在后续记录另行保存。

publication producer final0、明确的host双层action门、runtime-protocol-preview04与所选历史profile草稿保持source-only。Root主入口/CLAIM、最终32模块及生产材料整体仍待闭合，不以局部源码、synthetic测试、预算下界、主机历史复算或载体暂存代替新的案例资格。活跃工作和后继stage已按ROOT-SELECTION明确排除。

## 保存与恢复

ROOT-SELECTION列出的27个完整目录、10个明确文件，以及选择文件和本构建器，共同按原字节归档；仅排除Python缓存。SOURCE-INDEX记录每个本地源的完整SHA和当时full9，但恢复不会宣称复制原文件系统身份。分块XZ和恢复工具先核完整闭集与每件字节，再可选create-only恢复；不导入、编译或执行归档内任何程序。压缩仅用于检查点保存，不降低运行时原件或源码预算。Git发布仍由Root单独负责。
