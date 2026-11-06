# 实际 BUILD、安装与四角色 READY 的输入模板

本包只准备精确输入形状。25 份 JSON 模板/契约中有 295 个 `null` 槽，完整 JSON Pointer 索引在 `UNBOUND-SLOTS.json`。`PREPARATION.json` 记录本次准备为零 phone 调用、零新 case、零新增控制场景、零实际 source-chain 派生、零 BUILD/安装/READY。

这些 `null` 是未绑定状态，不能直接送入实际 reader。`derived-shapes/` 两份 scope 仅说明公共 API 的返回形状；实际 scope 必须从完整实际 phase 原件派生，不能手工填一个相似对象。

Root 后续已报告实际 R5 freezer 与独立 preparer 成功，并授权单 literal consumer 准备。该实际绑定候选另存于 `../R5-release-source-binding01/`，没有回写本包最初的空槽。最新新 NEG-01 在 stage 的目录 names 校验拒绝，root 正调查；990c 绑定候选当前 HOLD，无 source-chain 发布或派生。模板中的所有新 case、BUILD 和 READY 身份继续为空。

## 真实入口与依赖顺序

| 顺序 | 真实入口 | 必须已有的实际输入 | 产物与下一步 |
| --- | --- | --- | --- |
| 1 | 消费器 `PACKAGE_SHA` 单 literal 绑定 | 实际经 root 独立核验的 runtime manifest；精确消费器父源 | 完整 bound consumer 字节及逆向证明。其他历史/count 常量不猜测 |
| 2 | `derive_reviewed_source_chain(inputs_raw, read_pinned=...)` | 模板 01 的 material 八项、完整 bound consumer、实际 runtime manifest、fresh 输出目录；构造器 `FROZEN_INPUTS` 只绑定这份输入 | 14 份 source candidates；九键 `source_binding`；所有实际安装槽仍 `None` |
| 3 | 当前组件 consumer 的 `prepare_bundle` / `validate_component` | 新同组合 NEG-01 与 NEG-02 均实际闭合；完整 boundary/closure/inventory；两份原始 LEASE；原历史/退役/发布原件 | 模板 03 的完整组件输入。只允许新前缀满足新组合资格 |
| 4 | 实际 `build_release_r10.py` CLI | 已派生正式输入、完整组件输入、实际退役输入、固定实际 policy adoption、实际 shared 原件 | 真正 sealed BUILD 目录、archive、release/module manifests、原始控制器进程回执 |
| 5 | `verify_final_release_inputs(inputs_raw, read_pinned=...)` | 模板 06；实际 BUILD 原件和 start/status/read；所有 shared17 全字节及完整组件原件 | 主机 BUILD 验证结果；其 `phone_ready` / `whole_case_pass` 仍为 false |
| 6 | `protocol.validate_plan` 与 `protocol.expected_phase` | 模板 07；实际 release verifier 返回值；真实发布到 phone 私有目录的 archive/installer descriptor；三条唯一 phase 身份 | stage/start/ready 各自精确 request bytes、guard、argv、dispatch；root 执行 |
| 7 | 实际 stage 完成后的 `derive_scope_from_actual_phase` | 模板 09；完整 stage 原始结果、源 guard 回执及 controller 终态 | 仅 INSTALL-INTENT、STAGED、STAGED-PRESERVATION 三文件的严格 stage scope |
| 8 | retention producer 与 `retain_installation_originals` | stage scope；按实际首 manifest 导出的全部 chunk；最后 manifest；每次操作原始控制器/actor 字节 | 完整 stage 三原件和精确 `original_map`，仍不授予安装/READY 资格 |
| 9 | 实际 start 完成后的 scope / retention | 模板 10 与 13；完整 stage+start 原件；实际新 supervisor generation | START-INTENT、STARTED 两原件；再与 stage 三原件合并 |
| 10 | 实际 readiness collector 与 exact8 reader | 同实际 start 的 READY 原始 stdout、collector 原件、四角色 identity、三个 child bind 及其原始进程/初始流证据 | `verify_resident_output_bindings` 的精确角色与流来源验证 |
| 11 | `verify_install_start_ready_originals` | 模板 15；真实 release、exact8、plan、三 phase、retention 五原件与所有原件映射；最终两个 FROZEN 字面量 | 同次实际 BUILD→stage→start→READY 运输/执行证据结论。业务 E2E 和后续健康/冷启动等仍分别验证 |

第 7–9 步不存在依赖最终 READY 的循环。retention 调用 install reader 的纯 `verify_phase` 辅助函数，不调用最终安装 reader。stage stdout 已有 preservation 的精确长度/SHA，足以先派生 scope 再获取完整大原件。实践上在各 phase 完成后及时完成对应 manifest/chunk/manifest，可避开后续目录元数据变化；这不是另加的流程资格门。

## 只有新两案闭合后才能计算的值

模板 03 的最终 latest boundary、chain、closure、inventory、发布原件与组件输入 SHA256 必须来自新的实际闭合。此前历史成功只属于原 tuple。

每案 LEASE 都从同次捕获中的 `home/LEASE.json` 取完整原字节；以已经核过的完整 AFTER inventory 中精确路径的 `bytes/sha256/full9` 构造 phone descriptor，再核 `closure.lease_sha256`。模板 17 是现有 `originals` 的普通 phone/copy 行，不增加顶层 schema。

消费器据已核的 label、nonce、journal、home、boot、case、owner request、package、combination、prior boundary、retirement 和 session/profile 推导各案的三根。最终根列表必须等于真实 source-parent 的有序根列表，再追加新 NEG-01 三根与新 NEG-02 三根。不能只从根数加 3、闭合记录里的路径字符串或测试 LEASE 推导。

旧 source-parent 与原 9 条失败祖先保持原接口，不新增其 LEASE 要求。新两份 LEASE 缺一、确认原件不完整、公开回执缺失或来源不匹配，均不能用旧历史补齐。

因此 BUILD 所引用的 `component_boundary_inputs_sha256`、release/module/bundle pins、实际 archive SHA、执行 plan 的 release-input pin、retention scope 与所有最终 READY/source-guard 身份都不能提前计算成“实际”值。源码身份可提前派生，运行身份必须等真实原件。

## 文件阅读顺序

- `KNOWN-SOURCE-REFERENCES.json`：已读原源、材料和正式 source-chain 的完整 pins，旧合同只作 reference。
- `SOURCE-CHAIN-RETURN-CONTRACT.json`：真实公共 API 的五键返回对象、九键 source binding、14 文件名及准确 readiness 接口。
- `DESCRIPTOR-SHAPES.json`：三字段 host descriptor、四字段 phone/full9 descriptor 与 retained host copy。
- `templates/01`–`06`：消费器/正式源、两案组件/退役、实际 BUILD 与 BUILD reader。
- `templates/07`–`13`：三 phase、原始操作回执、stage/start authority 和 retention。
- `templates/14`–`17`：exact8、最终安装 reader、original map、两份新 LEASE。
- `EXECUTION-RECIPES.md`：精确调用形状、序列化与实际读取要求。

原件 JSON 的原始 bytes 必须保留。`st_mtime_ns/st_ctime_ns` 等 full9 大整数应由 Python 保持原值，不能经过 JavaScript 数值 parse/roundtrip。源码和请求的 UTF-8、LF、原始换行、完整 stdout/stderr 都按实际 reader 指定格式核对。

本包不需要执行新的控制场景。原 43 项 source-chain、72 项 env reader、82+10 项 retention 与 55 项 consumer 控制仍各归各源；这份文档没有把它们合成安装成功计数。
