# NEG-03—NEG-09：当前源传播候选与执行前准备

本包保全了面向 `COMBINATION 7969a11b…`、`R5 runtime 990c726a…` 的主机源码候选、完整历史源、实际执行过的主机控制及七项后续执行方案。**没有新的物理任务、模型请求、取消、信号或部署；没有给任何整项 NEG 用例增加通过资格。**

当前完整源码构造器是 `derive_negative_sources_UNBOUND.py`。它只返回待审源码字节、逐项反演证明与未绑定计划，不包含发布器。`FROZEN_INPUTS = None` 时，公共 API 在解析输入或调用读取回调之前拒绝。

## 当前停止绑定的位置

实际源传播需要 Root 的最终 runtime/freezer 双副本与真实 controller 成功回执、正式 source-chain 发布、sealed BUILD 和四角色 READY。这个包没有替代这些条件。

Root 最新报告的新 NEG01 在 `stage → verify_retired` 的共享父目录 identity/label/names 检查处拒绝，尚未进入 sender/fixture 或创建 stage home。该问题仍在独立读取对账；本包没有改这道检查。若最终 R5 runtime 或 root 源改变，本构造器的 `990c726a… / f9145ce2… / 2af78597…` 精确 pin 会拒绝；必须形成新的明确源候选，不能把现有输入重新标成已采用。

`SOURCE-INPUTS.template.json` 保留所有实际槽为 `null`。`CURRENT-SOURCE-BOUNDARY.json` 单独记录已知原件的位置和 hash，不能作为执行输入或成功回执。

## 已完成的最小修复

| 源码 | 改动与目的 | 证据 |
| --- | --- | --- |
| `candidate/shared/observe_cancel_phase_r10.py` | 在已经核对过的 semantic wire 与实际 scope 上，把 `expected_call=wire, expected_scope=actual` 传给现有 v3 `native_streams`；不改变生产五源。 | 原调用真实复现缺参数 `TypeError`；新消费者链 7 项主机控制通过。 |
| `candidate/component/verify_unqualified_geometry_fixture.py` | 为现有六轴几何 fixture 加入显式 synthetic 五字段 scope 和完整 v3 native schema；独立 hash preimage helper 保持原字节。 | 实际生产 map/prepare/native/parser 六轴 70 个断言通过；没有真实 native scope 或手机操作。 |
| `candidate/templates/physical-fault/physical_fault_common.py` | R8/32 的严格源关系改为这个 R5/38 候选，配置与 service 改为当前源指纹。 | 所有信号、传输、作用域与请求函数原体保持；`FINAL_DEPENDENCIES` 仍未绑定。 |
| `candidate/templates/physical-component/physical_component_common.py` | 仅允许 `SOURCE_PINS` 中精确四个源名及严格整数字节数/hash tuple；增加现有 active 的 config/service 两个 literal 传播与实际核对。 | 旧字典拒绝真实复现；多余名字、布尔长度、错误 hash 和其它执行体变化仍拒绝。 |
| `candidate/templates/closure/negative_originals.py` | 把整个 root capture 模板绑定到已审 R5 七槽反演结果，并更新 config/service 来源。 | 旧 root 模板确实拒绝 R5；新完整反演与原 Q2 传输体通过，七槽以外变化拒绝。 |

每个候选旁边保留完整原件映射、精确 diff 和 `DERIVATION.json`。`REVIEWED-INPUTS.json` 固定 171 个完整输入，原历史 Git commit 为 `744fc422a28bd6f505701503bf0d113ab49d4634`。

## 实际主机控制与限制

| 结果 | 已实际执行的范围 | 不能据此声称的范围 |
| --- | --- | --- |
| `observer-controls02/RESULT.json`：7/7 | 原 observer.dispatches → 当前 native v3 → r6 terminal → app-open receipt → viewport；错误 trusted request/scope/target 拒绝。 | Android root 文件所有权、真实 active runtime、实际阶段观察、完整 adapter/BUILD/READY。 |
| `geometry-controls01/RESULT.json`：六轴 / 70 个断言 | 当前完整 15 源与 daily 14 依赖核对；真实 production mapper/parser 消费显式 synthetic receipt；后续 tap map 拒绝。 | 真实外屏、旋转、输入、实际 BUILD/READY、正式 COMP01。 |
| `template-controls02/RESULT.json`：15 项 | 最新构造器零 I/O 未绑定门、三模板完整反演、严格字典、真实 R5 root/source 反演、171 原件与进程资源基线。 | 公共构造器的完整正向采用、任何真实角色/lease/nonce、正式 source-chain 或物理用例。 |

`template-controls01` 是同一组控制的前一结果，不能与 `template-controls02` 累加。最初 observer host 尝试因真实 Android root 所有权门拒绝，保留在 `observer-controls01`。第二脚本明确使用 synthetic host-owned full9 文件读取适配器，生产所有权门没有放宽，也没有把该门计作通过。

所有脚本和完整 synthetic 输出都在包中。fixture scope、native frame 和公开业务 receipt 均标明 synthetic；没有绕过 `PhoneLocalAdapter.validate_executor` 构造一个可用于执行的 adapter。

## 完整源码构造器的接口

公共函数：

```python
derive_negative_sources(inputs_raw, *, read_pinned)
```

未来绑定只改一个 `FROZEN_INPUTS` descriptor；它必须是经过审查的完整输入原文。读取回调要按 exact3 descriptor 返回完整字节，并独立保留文件全九字段/完整原件读取证据。构造器重复核对全部来源，最后再次完整读回。

实际 source-chain 必须是既有 `derive_reviewed_release_sources_UNBOUND.py` 的单 literal 绑定版本：去掉 `FROZEN_INPUTS` 后完整字节恢复到 `33827 B / 4c8f32d5…`。构造器调用其公共 API，随后独立完整读回已经发布的 consumer/readiness，并与 API 返回字节比较。它没有通过私有函数绕过采用门。

输入还包括同一 7969 的完整 shared17/production15、990 runtime38、f9145 root manifest3、实际 policy/adoption 原件以及原 materializer。它继续调用已审 physical fault 的 `generation_inputs`，保留全部 44 个权限原子检查。这里的源一致性不能代替 sealed BUILD 或独立 READY。

候选构造器计划返回 11 个源码家族：UI、fault、component、CPU、P4、phone、closure、physical-fault、physical-component、host-five、host-neg06，以及七个未绑定计划。它尚未实际生成这一整套输出。

关键传播包括：

* UI/fault 共用同一 active 源，六个 dependency literal；全部 15 源清单及 actor manifest 的 `reviewed_production_source_pins` 同步更新。
* component 的当前四源 `SOURCE_PINS`、接口说明与 full v3 synthetic fixture 同步；旧 direct COMP helper 完整保留作历史参考。
* CPU/P4/phone/closure 的 source pins、daily pin、root capture 模板和完整 15 项 closure callback 来源同步。
* physical-fault 的四个 `FINAL_DEPENDENCIES`、现有 preparer 所需 `FREEZE-INPUT.original.json` 与 source-only finalization 同步。**保留的 legacy `freeze_physical_fault.py` 是原件；新构造器代替该旧源码冻结入口，后续不能再调用旧 freezer 来接受新体。**
* host-five 保留原 counter/once-only/late-fence 行为，只更新真实 15 源与 config/service；NEG06 保留原隔离 namespace 和模型超时机制，只选择原协议的 NEG06。

## 之后如何执行

详见 `PHYSICAL-EXECUTION-PLAN.md` 与 `SOURCE-ENTRY-INDEX.json`。Root 按每项实际准入生成新 plan，只消费其确切 `execute_argv` 一次；这个包不提供可以直接派发的实际 argv、task scope、nonce、owner 或目标 PID。

NEG04/05/07/08/09 的原协议要求 `host_isolated` 与 `physical_native_task` 两层。历史 host 成功保留，当前组合需重新取得对应层的原件。NEG06 的原协议是隔离主机 HTTP timeout fixture；它没有要求浪费一次真实模型请求，但 bound real server 的清理资格仍不能由 fixture 推断。

正式 COMP01 由 E2E 的 production mapped/native `phone.return_hepta` 闭环取得 launch、Activity、实际 focus 和 top-resumed 原件。旧 direct helper 或 synthetic geometry return 都不提供当前 COMP01 资格。

## 复现布局

Git 归档保留这一相对布局：

```text
review/neg03-09-plan/        # 本目录、全部参考源、控制脚本和实际结果
review/source-audit-v3/     # 原 CANDIDATE-PINS、30 个原/新源、精确 fixture helper
review/R5-root/runtime/MANIFEST.json
review/R5-root/root-chain/source/run_component_root_once.py
```

依赖逐文件 pin 在 `REPRODUCTION-DEPENDENCIES.json`。在支持 `/proc` 的 Linux 主机，从归档根目录选择三个全新的绝对输出目录，分别执行：

```bash
python3 -I -B review/neg03-09-plan/test_observer_native_v3_v2.py /absolute/new-observer-result
python3 -I -B review/neg03-09-plan/test_geometry_native_v3.py /absolute/new-geometry-result
python3 -I -B review/neg03-09-plan/test_negative_source_templates.py /absolute/new-template-result
```

这些命令只运行主机控制；输出路径已存在则拒绝。脚本拒绝网络、进程启动和信号，精确核对当前 15 源，记录实际 FD/thread 基线。不要运行 `reference/` 中任何 `main` 来复现：那些是尚未取得当前准入的真实 operator 历史源码。

完整 public constructor 的正向执行仍须真实来源发布后另行完成，不在本次 7/70/15 结果内。
