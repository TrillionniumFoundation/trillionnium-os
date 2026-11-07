# R6 实际 BUILD、安装与验收运行说明

日期：2026-11-07。本文只映射已存在的构造器、读者和证据门；不是执行请求、资格回执或新的 admission 实现。精确路径、字节数、SHA256、schema 和字段见 [PROTOCOL-MAP.json](PROTOCOL-MAP.json)，19 项逐项要求见 [FIXED19-LEDGER.json](FIXED19-LEDGER.json)。

## 1. 当前停留点

| 对象 | 当前可确认状态 | 下一步所缺原件 |
|---|---|---|
| R6 原 NEG-01 bound02 | `launch_unknown`；没有可核验原终态 | 同一原 job 的完整终态，或独立且被现有流程接受的正式处置 |
| 当前 NEG-01 / NEG-02 | 没有被接受的当前整项通过 | 当前原请求、guard、独立作用计数、终态、closure、inventory、late boundary |
| 实际 BUILD / 安装 / READY | 实际槽位 `UNBOUND` | 当前两个组件原件及后续真实 BUILD、三阶段 actor、安装读回和八条角色输出 |
| 固定 19 项 | 当前组合整项 PASS **0 / 19** | 各规定层与业务回执，不能移植历史/source-only 结果 |

当前组合：

```text
combination 7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411
runtime     270357b7649af61414d31580b3c1eaddc47174bd1bac3c8adfc02934a92c8cf5
boot        f8019f83-20a7-4f18-bea1-51c980621e4d
```

原 bound02 身份：`mac / 1a1b3420986-fc05-8183`，label `root-r10-neg01-fc33-r6-bound02`，nonce `731dc46ccaad6e5717306d0c5f029a82`。原 PLAN SHA256 `0fbfd5aa0ed86e0bad846f2e541c3117ee1c7a46c98af7000c96f2e7d25a4bfa`；原 REQUEST 317B、SHA256 `b25d5c139aebdec8a222ca4298e91cd57500b0836c0c9f1629cb4ce769ad6d3f`。

原 worker 或输出目录缺失不能证明未执行、零作用或释放身份。先核对原 job、原请求、所有输出、远端所有权及终态，随后依据被接受的结论确定下一合法动作。不得为得到结果而重发原 argv、换 key 或生成新 nonce。[原身份对账](https://github.com/TrillionniumFoundation/trillionnium-os/blob/22e6105c2effe102c0f120a906752003aedfb37d/projects/razr60/phone-local-v150/acceptance/r10-fixed19-1ad3-20261105/followthrough-20261106-fc33/verification-20261107/CONTROLLER-RECONCILIATION.PUBLIC.json)

`recovery02-fresh` 与 `recovery02` 都属于另一条 `root-r10-neg01-fc33-r6-bound01`：前者 phone rc0、owned cleanup 闭合；后者 host exit0 但 phone rc1，`PRE_MUTATION_REJECTED`。两者各保留自己的原 job、reader 和结果，均不结算 bound02。[分别保留的 recovery 原件摘要](https://github.com/TrillionniumFoundation/trillionnium-os/blob/22e6105c2effe102c0f120a906752003aedfb37d/projects/razr60/phone-local-v150/acceptance/r10-fixed19-1ad3-20261105/followthrough-20261106-fc33/verification-20261107/recovery/SUMMARY.json)

## 2. 原任务处置与当前组件门

当前实际 `run_component_root_once.py` 的 `validate_current_prior` 只接受：精确已通过 source-parent 进入当前 NEG-01；当前同 case 已闭合的 `provider_failed/cancelled` 且 `unknown_effects == 0`；当前 NEG-01 通过后进入当前 NEG-02。它还读取真实 closure、完整 inventory、late boundary、前驱身份与 `known_all_dispatched_tools_confirmed_terminal == true`。

UNKNOWN 不满足这些条件。若终态无法恢复，需要先找到或完成绑定本次原身份的独立退休处置读者及其 admission consumer，证明旧生产者不能再作用，同时保留原 UNKNOWN、原 claim 和原 request。不能填写一个成功布尔值，或把未知作用数改成 0 来通过既有读者。

已经核验的两个历史工具不能直接代入：

- `pre-admission-neg01-closure-r10-r1-candidate01/source/host_closure.py` 硬编码 `root-r10-neg01-20261104-01` 与 `9c3da08af7120c56dc3f248c17b18581`，要求该原拒绝的七个已 joined host children、phone rc1 和特定零写入路径。
- `retirement-recovery-r1/PROPOSED-RESOLUTION.schema.json` 是历史 executor 退休 proposal；schema 不是独立 verifier。其要求包括原进程和 listener 退休、journal FD/inode 锚定、完整原件及保留原任务终态，不能仅凭目录缺失成立。

获得合法下一步后，使用当前既有 Root 入口完成当前 NEG-01，再依其原通过 boundary 进入 NEG-02。原始失败闭合只按现有同-case 分支处理。不要把旧组合 NEG-01/NEG-02 或 parser recheck 作为两个当前 `ROOT-RESULT.json`。

## 3. BUILD 的唯一构造路径

远端项目根目录：

```text
/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1
```

现有 R6 入口都在 `followthrough-fc33-install-build-controller-r6-01/source/`：

| 入口 | 职责 | 当前状态 |
|---|---|---|
| `bind_actual_controller_input.py` | 用实际输入 descriptor 绑定原构造器的唯一 None 槽，保留完整 source inverse，生成下一构造请求 | 可读；未绑定缺失实际输入 |
| `derive_component_build_inputs_UNBOUND.py` | 校验当前两个闭合组件及连续边界，生成 BUILD 请求 | `FROZEN_INPUTS=None` |
| `derive_release_install_stages_UNBOUND.py` | 从真实 BUILD、actor 与 retained originals 渐进生成下一阶段输入/请求 | `FROZEN_INPUTS=None` |
| `verify_actual_installation_for_cases.py` | 重读最终安装构造、完整原读者和所有原件 | 无当前实际 installation descriptor |

这些文件已经有精确 SHA256，见 PROTOCOL-MAP 的 `sources`。不用重写它们的验证逻辑，也不手工修改 frozen 源码。

### 3.1 当前组件构造输入

schema：`hepta.fc33.actual-component-build-construction-inputs.v1`。

必须恰好提供 `schema, case_results, output_root, build_output_root, build_idempotency_key, build_timeout_seconds`。`case_results` 必须恰好包含 `NEG-01`、`NEG-02` 的真实原 `ROOT-RESULT.json` descriptor（`path, bytes, sha256`）。两个输出根必须是项目根下明确且不同的新目录；原 BUILD timeout 在 1–300 秒内。

构造器重新验证所有连续 closure/inventory/boundary 和实际当前顺序，成功状态仅为 `ACTUAL_COMPONENT_INPUTS_VERIFIED_BUILD_NOT_EXECUTED`，输出 `requests/BUILD.REQUEST.json`。这时还未 BUILD。

### 3.2 使用既有 binder

绑定输入 schema：`hepta.fc33.actual-constructor-input-binding.v1`。

字段必须恰好为 `schema, constructor, actual_inputs, output_root, execution_idempotency_key, execution_timeout_seconds`。constructor 只能是 `component_build` 或 `release_install_stage`；`actual_inputs` 是上述实际输入文件的完整 descriptor。输入树不能有 null 或虚构值，execution timeout 为 1–300 秒。

以下只是命令形态；变量必须来自真实已核验输入。当前缺少组件原件，尚不具备调用这一 BUILD 构造链的前置条件：

```bash
RAZR60_PROJECT_ROOT="/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1"
/usr/bin/python3 -I -B "$RAZR60_PROJECT_ROOT/followthrough-fc33-install-build-controller-r6-01/source/bind_actual_controller_input.py" \
  --inputs "$RAZR60_BINDING_INPUT_PATH" \
  --inputs-bytes "$RAZR60_BINDING_INPUT_BYTES" \
  --inputs-sha256 "$RAZR60_BINDING_INPUT_SHA256"
```

binder 的成功状态 `EXACT_INPUT_LITERAL_BOUND_CONSTRUCTION_REQUEST_NOT_DISPATCHED` 只证明生成了 `requests/EXECUTE-CONSTRUCTOR.json`。由单一操作者使用其精确 host/executable/argv/key/timeout 执行一次，保留原 controller start/status/read 和完整输出；然后才能使用产出的 `BUILD.REQUEST.json`。原请求已经有不明结果时先读原尝试，不另发一次。

实际 BUILD 必须得到原 `BUILD-RESULT.json` 的 `SEALED_ACTUAL_RETIREMENT_BOUND`、完整 archive 和原 controller/process 记录。exit0 或文件名存在不足以替代完整 reader 验证。

## 4. 安装、保留原件与最终读者

渐进构造输入 schema：`hepta.fc33.release-install-stage-construction-inputs.v1`，恰好字段 `schema, stage, output_root, actual`。每次用 binder 绑定一个真实输入；每阶段 `actual` 的精确键集合见 PROTOCOL-MAP 的 `contracts.progressive_install.stages`。

| 阶段 | 必须消耗的原件或产生的下一步 |
|---|---|
| `actual_build` | `component_construction, build_result, build_process`；完整 BUILD reader 接受后生成实际 release inputs |
| `install_plan` | 实际 release、actor、private delivery/request 路径、一次性身份前缀和三个原 timeout；生成 stage/start/ready 请求及 before/after observers |
| `ingest_phase` | 某个原 phase 的 actor controller 与 before/after observer；完整保留原 stdout/stderr、source guard 和 carrier，尚待完整 reader |
| `phase_authority` | 由已完成的 stage 或 start 原件生成对应 retention authority |
| `retention_first` | 为该 authority 生成一次首 manifest capture 请求；构造本身不执行 capture |
| `ingest_capture` | 将一次真实 capture 的 controller/observer/原输出保留为 carrier |
| `retention_remaining` | 先核验首 manifest，再生成各 chunk 与末 manifest 的不同一次性请求 |
| `retention_finish` | 全部真实 capture carrier 连续核验，再保留完整安装原字节 |
| `exact8_inputs` | 当前 release、三 phase、retention 及 installed originals；验证四角色八条原 stdout/stderr |
| `final_install_reader` | 只绑定既有安装读者的两个 None 槽，重验全部原件；产生最终 DERIVATION 和 verdict |

实际 phase 顺序是 **stage → start → ready**。每次先确认原请求的 terminal、完整输出和观察原件，再进入下一 phase。retention 的先后由相应 phase authority 和原 manifest 决定；不要先填未来 phase 的 carrier。

最终构造必须为 `ACTUAL_INSTALL_START_READY_READER_BOUND_AND_ORIGINALS_VERIFIED`。之后调用既有 `verify_actual_installation(construction, read_pinned=...)`，其中 construction 是此真实最终 DERIVATION descriptor。该 gate 要重跑完整 reader，并要求：

- `VERIFIED_ACTUAL_INSTALL_START_READY_EXECUTION_ORIGINALS` 和同一当前组合 SHA。
- 实际 BUILD 目录内原字节仍一致；archive、安装字节及 delta 被重算。
- 三个原 actor terminal 与 stdout/stderr 被核验；所有 retained originals 有完整 bookends。
- supervisor、model、sidecar、provider 四角色各自的原身份与八条完整输出来源被核验。

`READY_qualification_scope` 仍只是 `TRANSPORT_ONLY_AT_ORIGINAL_OBSERVATION`。原 PID/PGID/SID/start_ticks、SELinux/UID/GID/exe hash、source/config/service、listener/socket 所有权、idle slot 和读前读后 boot 一致，都属于实际 READY 门；“进程存在”不等于通过。

模型启动绑定是 `READY_BOUND_IMAGE_CANCEL_REQUIRED`，readiness 自己 `model_requests=0`、`health_qualified=false`。要另外收齐新请求下 image/cancel 健康原件及既有 health 读者结论，再进入用户要求的真实业务验收。

## 5. 四项业务和 COMP-01

当前已派生入口：`followthrough-fc33-e2e-execution-controller-r6-01/source/derive_e2e_requests_UNBOUND.py`，SHA256 `7b35b9a0f57ddd9e56948bbcab012b662fd84628d9502e9350d012a2de126acf`。

构造阶段是 `materialize_request → prepare_request → dispatch_request`。它先经当前实际安装 gate，再使用 `followthrough-fc33-e2e-bound-source-r6-01` 内的既有 materializer、Root operator、collector 和 coordinator。实际 E2E coordinator 顺序是 `register → sender-preview → sender-execute → capture-export → collect → close`；capture 已经 export，不再做第二次 export。

先做视觉、中文/emoji/换行、计算器和设置四项真实业务。通过必须来自原 native、业务 sidecar、公开业务回执及按请求要求完成的实际返回。Settings 未请求返回时不强制返回。

当前 R6 构造器明确：**COMP-01 对 E2E-01/02/03 的同一原 return 作第二次独立判定，不发第五个 Send。** 仍单列 `component_direct`，保留原 launch rc、Status/Activity、focus/app/top-resumed 和 keyguard 证据；不能因此追加 model gate 资格。

同一真实尝试发生未知或失败时保存原请求和所有晚到证据。现有 phase 目录、sender label 或原 claim 不能通过改名重跑来消除。

## 6. 可以独立继续的 host 工作与计数规则

在原 bound02 尚未闭合时，可以核对精确源码、依赖、配置和预算；审阅既有 source inverse；补足 source-only 隔离控制的覆盖与原件索引。这些工作不启动新的手机任务，也不把 BUILD/READY 槽位填成已通过。

| PR112 既有记录 | 保留的真实范围 | 当前 fixed19 整项 credit |
|---|---|---:|
| `selected-guards-01` | 13 项 selected host checks，exit0 | 0 |
| `shared-business-01` | 14 个 shared business scenarios，exit0 | 0 |
| `native-public-fixtures-01` | synthetic parser 73 / consumer 12 / trust parser 40 / trust consumer 11 / binding 9 | 0 |
| `native-require-actual-01` | 首次 public-only 副本缺私有原件，exit1；原失败继续保留 | 0 |
| `native-require-actual-retained-01` | 相同 R6 15 源对历史 13 份原件的独立 parser/consumer 复核，exit0；原 guard70仍为拒绝 | 0 |

来源：[原 host RUN-SUMMARY](https://github.com/TrillionniumFoundation/trillionnium-os/blob/22e6105c2effe102c0f120a906752003aedfb37d/projects/razr60/phone-local-v150/acceptance/r10-fixed19-1ad3-20261105/followthrough-20261106-fc33/verification-20261107/cloud/RUN-SUMMARY.json)；[历史原件复核追加记录](https://github.com/TrillionniumFoundation/trillionnium-os/blob/22e6105c2effe102c0f120a906752003aedfb37d/projects/razr60/phone-local-v150/acceptance/r10-fixed19-1ad3-20261105/followthrough-20261106-fc33/verification-20261107/actual-originals/ACTUAL-ORIGINALS-RECHECK.PUBLIC.json)。这些计数不得相加为 fixed19 通过项，也不证明当前 phone 安装或实际业务。

NEG-04、NEG-05、NEG-07、NEG-08、NEG-09 各自必须同时具备 `host_isolated` 和 `physical_native_task`。其余逐项层、条件、缺失原件和 blocker 已写入 FIXED19-LEDGER。新的完整判定应追加自己的原件 descriptor，保留所有旧范围和旧失败。

PR112 deadline 候选解决的是整体观察预算被分段等待突破的已复现问题。137 只确认来自原 shell-v2 exit frame，killer/被杀进程/原因仍未知；不能称因果已经修好。采用候选前须闭合完整依赖/config/预算绑定并重新冻结组合，不能把候选字节悄悄写入本 R6 组合。[证据与候选边界](https://github.com/TrillionniumFoundation/trillionnium-os/blob/22e6105c2effe102c0f120a906752003aedfb37d/projects/razr60/phone-local-v150/acceptance/r10-fixed19-1ad3-20261105/followthrough-20261106-fc33/verification-20261107/navigation/SENDER-DEPENDENCY-REVIEW.md)

## 7. 新 boot 与 USB 脱离桌面

当前 boot 被精确绑定。新 boot 下要重新取得并由读者接受自启、运行身份、四角色 READY、新健康及新业务原件。同一 boot 的较长 uptime 不替代冷启动。

USB 脱离桌面必须观察实际手机本地新任务及业务回执，重连后核对原身份和终态；另保留测试时长、延迟、内存、温升及电量数据。可靠性表述不得超过实际测量时长。P2 不被这 19 项表格或源码检查自动关闭。

