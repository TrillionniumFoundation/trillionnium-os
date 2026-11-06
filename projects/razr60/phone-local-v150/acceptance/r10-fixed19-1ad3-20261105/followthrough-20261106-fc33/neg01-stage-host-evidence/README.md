# 本次 fc33 NEG-01 在 sender 之前停止的实际主机证据

**结论：本次 `root-r10-neg01-fc33-bound01` 的协调器执行停在 stage 的内层手机返回 1，未进入 sender-preview 或 sender-execute。** 这是从精确执行源、完整已发生阶段、实际主机目录与发送标记交叉得出的有限结论；本次手机 material/source push 和 stage 尝试已经发生，不能把它写成“手机零效果”或清理闭合。

本包只增加实际主机原件读取。没有执行手机、cleanup、重发、服务操作、BUILD、安装或 READY；没有增加控制测试场景。990c 消费器与 source-chain 绑定候选仍 HOLD，未发布、未派生。

## 实际原始回执

| 原进程/观察 | Job ID | 完整 stdout / stderr | 终态 |
| --- | --- | ---: | --- |
| Root 实际 NEG-01 链 | `1a1b1d3a2d9-fc05-7b03` | 0 / 1896 | failed，exit 1，双 EOF |
| 本代理 Mac rootout 只读观察 | `1a1b1e28eff-fc05-7b53` | 232288 / 0 | succeeded，exit 0，原日志完整持久；另核终端 EOF |
| 完整 Mac 审计日志只读转运 | `1a1b1e51bb6-fc05-7b60` | 38820 / 0 | succeeded，exit 0，连续分页和双 EOF |
| 本代理 Pocket4 主机存在性观察 | `1a1b1e63649-fc05-7b67` | 5825 / 0 | succeeded，exit 0，双 EOF |
| Root 先前手机只读父目录观察 | `1a1b1dbf291-fc05-7b2b` | 289 / 0 | succeeded，exit 0；完整 operation 原件另存 |

全部控制器原文保留原始 JSON text，核对真实 job 身份、无复用、无超时/取消/自动重试、精确整数 log counters、同步/截断标志、终态持久确认与 EOF。各文件具体 pins 在 `PACKAGE-MANIFEST.json` 和 `VERIFICATION.json`。

Mac 审计原文 232288 字节，SHA256 `e583360bba5aa77db798dcfebaf89ae0bfdf3cff223827b226816c50229a0a25`。因为控制器每页最多 16 KiB，完整原文通过只读原日志的 O_NOFOLLOW、完整 EOF 与 full9 前后校验后 zlib 转运；重建后再核原日志长度/SHA、控制器已存总字节、首 16384 字节与末端 EOF 探针。**没有将首尾两页伪报成连续完整的 process_read 分页。** 转运进程自身 38820 字节通过连续原页完整保全。

## 同一次链停在何处

Mac rootout 是：

`/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-fc33-bound01`

实际观察得到 115 个文件、10,998,073 字节、15 个目录。全部文件都完整读取到 EOF 并记录 SHA256/full9，全部目录均完整枚举名称、核 full9 和前后成员集。其顶层包括 `CHAIN-INTENT.json`、`ROOT-FAILURE.json`、`ROOT-PLAN.original.json`、material 和以下七个实际阶段：

1. prepare-material
2. host-stage-material
3. phone-push-material
4. phone-copy-material
5. phone-push-stage-source
6. phone-copy-stage-source
7. phone-stage

七个阶段的实际同步 host child 都写有 `RESULT.json`，状态为 `ORIGINAL_HOST_CHILD_JOINED`，外层 returncode 0。同步阶段不写 `JOINED.json`；该文件用于后面的异步 sender。本包同时记录它们的实际存在/不存在，未把正常缺少 JOINED 解释为丢失终态。

关键的最后一层关系是：

| 层次 | 实际结果 |
| --- | --- |
| phone-stage 的 Mac host child | returncode 0，stdout 3391 字节完整保存 |
| Pocket4 原 actor | actor_rc 0，成功取得实际手机结果 |
| 实际手机 stage 命令 | rc 1；stdout 空；stderr 明确为 retained-stage parent 身份/名称集合校验失败 |
| Root 协调器 | `phone()` 检查内层 phone rc，抛出 `actual phone command failed; no new key retry`，原 root job exit 1 |

实际 stderr 的最后原因是 `shared parent identity/label/names differ from exact admitted additions`，调用链经过 `verify_retired → retained_stage_parent_profiles → validate_retained_stage_parent_profiles`。本包不判断额外 foreign 目录该如何清理，也不把该错误改写为新组合资格。

`ROOT-FAILURE.json` 记录七个实际阶段、空的 owned host children 和 stream cleanup errors、零 model requests、零 root fixture attempts、零协调器信号和禁止重发。其完整 bytes 与 root 先前独立读到的同一原件逐字一致。

## sender 未进入的交叉证据

实际 frozen root 源为 78566 字节 / `2af78597f211b8b7de32d5f40591e46c4ea5ff7caa3c4a2547ac4325666c2032`；实际 sender 源为 41080 字节 / `53a6e9149cf768211c3c8ba74d3c422f95d78f14efdb8751af1ac55d1a9225d5`。本次只读再次核过这两份实际 Mac 原件的完整 SHA/full9。`SOURCE-CONTROL-FLOW.txt` 保留对应字节源的必要片段：stage 必须成功返回，之后才调用 sender-preview 和 sender-execute。

Mac 实际观察中，本次 `sender-preview`、`sender-execute`、`sender-prepared` 三个目录均 ENOENT；同 label 的 `.actor.py`、`.local-once.json`、`.send-result.json` 也均 ENOENT。

Pocket4 上 `/home/alex/codex-native-guard-chain-r10-r1/e2fdaccd43cec9da1df4d77783db8fdb` 确实存在，保留 inputs/material 和已发生的 phone 阶段；phone-stage 目录有 `ORIGINAL-OPERATION.json`、`actor.stdout`、`actor.stderr`。精确 sender 目录 `/home/alex/codex-hepta-natural-root-r10-neg01-fc33-bound01-root-v150` 为 ENOENT；其 `COMPONENT-PREPARED-NO-SEND.json` 和六种 SEND 标记查询也均返回 ENOENT。子标记查询的 missing ancestor 明确记录为该 sender 目录，不冒充七次独立的既有目录遍历。

Root 先前的手机只读观察还记录本案的 home、journal 和 fixture 三条精确路径为 ENOENT。本代理只保全并核对该先前原件，没有执行新的手机观察。目录缺席只代表记录时点；“本次 root 链未进入 sender”的判断同时依赖原执行源和完整实际阶段历史。

## 原件范围与复验

`read_failed_attempt_host_originals.py` 只读绑定的 Mac/Pocket4 主机路径，不 import 项目模块，不调用 ssh、ADB、手机 actor、清理或 sender。公开正文只允许根的 CHAIN-INTENT/ROOT-FAILURE 与七阶段 INTENT/RESULT/JOINED/stdout/stderr 共 30 份原件、77,606 字节。完整目录里其余文件仅返回外层 descriptor。

`stdin.original`、`inputs/preserved_draft` 及其任何内层 payload 均没有写入本包或 Git。它们继续留在实际主机；清单只含 path/bytes/SHA/full9。`VERIFICATION.json` 单独列出这些 outer-only descriptors，便于核对没有把它们作为公开原文输出。

`verify_retained_evidence.py` 只验证本目录已经保全的真实原件，不运行 fixture 或任何外部进程；首次运行已完成。它以 create-only 写 `VERIFICATION.json`，10990 字节 / `24901268bb1b05ea196f8e8a316ee5e4d10b402f07804a541ec02d408f8c888c`。复验应在独立副本中保留原结果后运行，不能覆盖已有原件。

证据范围不包含 foreign-attempt 清理、新组件 closure、全局 sender 活动、实际 BUILD/installed tuple 或业务 E2E 成功。本次 NEG-01 仍是正式组合下的失败尝试；旧 NEG-01 的成功身份继续只属于旧组合。
