# NEG-03–09：当前 R5 源码派生请求（未执行）

本目录把已发布的 release / E2E 源码接入 NEG-03–09 的既有工具。当前只准备了一个可审阅的主机源码派生请求，没有传输或执行该请求，没有创建实际业务请求、nonce、任务、BUILD、安装或 READY 原件。

**Root 应审阅并选择 `publisher-final02/`。** `transport/publish_negative_sources_once.py` 和根目录的旧 PROCESS-REQUEST 是保留的第一版草稿，不是最终请求。两版均未执行；payload、构造器和 SOURCE-INPUTS 相同。第二版只在添加 terminal / proof 文件后再次检查完整输出树的既有文件数和字节上限。

## 最终入口

| 原件 | 字节数 | SHA-256 |
|---|---:|---|
| `publisher-final02/publish_negative_sources_once.py` | 19,652 | `581efadeed85af47e98c68c4037cee4b2599d00987df1f78ca753e917e729335` |
| `publisher-final02/PROCESS-REQUEST.UNEXECUTED.json` | 498 | `1c8dbbff6792d06396b6132f4d37ffc25b59b8c30da906dfc8baa6c490ef4e37` |
| `SOURCE-INPUTS.json` | 2,537 | `639a157ab7609bfad53d910216ed5fc8f86b973962b908af463ac876628ee694` |
| `source/derive_negative_sources_BOUND.py` | 43,413 | `79e6d890090d974577f80839555522efa07949f701951e0bb669693454319517` |
| `transport/SOURCE-PAYLOAD.zlib` | 711,272 | `324bf65adb34b22e870ab8d791216ffcc50f360685934ab7696694b866b5a873` |
| 完整展开的 payload | 2,521,095 | `0d178167de8e3e983b64bc116d8a87d4d04b305d58668a69da5eec670570cf7e` |

构造器只有 `FROZEN_INPUTS` 一个 literal 绑定；其余全源反演等于 43,142 字节的 `d539cb12c5b3d99f4b6066de148f11db78d3ad4210bc034669ebc1bc99c44903` 原件。`SOURCE.patch`、`BINDING-PROOF.json` 保留完整差异与反演依据。

## 实际源码输入

这些 descriptor 指向已存在的源码或历史原件；此处没有制造新的现场结果。

| 输入 | 字节数 | SHA-256 |
|---|---:|---|
| 已发布 source-chain 构造器 | 34,103 | `342cf03f11fcb6cc02fd98f68f44a567603389788de45999c6182ad0a4426c5a` |
| 该构造器的 SOURCE-CHAIN-INPUTS | 3,515 | `e3cc22536e42074ba3fe662101dd4a4c98224de285b0a5c13c32f84d2fac322b` |
| 已发布 SOURCE-BINDING | 3,608 | `c7b074b529b4bbe258303842b3d0b2f3912d8cdf606f803522775b79ba147003` |
| R5 root-chain SOURCE-MANIFEST | 50,107 | `f9145ce2f0e5864a78ed8bece2d926187dc83e8baf15799758200bb646057282` |
| 原 actual policy 完整导出 | 2,667,752 | `69aa6433a11ac4cffb2f1d349cc9f36ec2349a601911c173ebe7d92fff9e0c5b` |
| 对应 POLICY-ADOPTION | 32,638 | `98b5db3d2c9680fff13e50bf64b18ddf9822689641427d204fded84f690d04c7` |
| 已发布 E2E materialize_case_r10.py | 24,834 | `b25125bc0e204ea7aefde6f2a17fa2fb8e5edf132a4b62dfbb546964c1c09290` |
| 已审 material publisher v3 | 16,399 | `842f893107dfff481e516419da3fd9b1e2c2445378903012658530d83429ac82` |

materializer 使用实际新位置 `followthrough-fc33-e2e-bound-source-r5-01/operator/materialize_case_r10.py`。完整绝对路径都在 `SOURCE-INPUTS.json` 和 `publisher-final02/BYTE-BOUNDS.json`。

实际构造器将重新调用 source-chain 公共入口并完整读回其依赖，而不是根据文件名推断采用。它核对 COMBINATION `7969a11b…`、runtime `990c726a…` 的 38 文件、consumer 的 38 / 12 / 42 边界、共享 17 文件与最终 15 生产源、实际 root 三件、policy / adoption 的 44 个权限项。现有 lease、角色、guard、journal 和身份约束保持。任何输入变化都拒绝，不能用旧结果补位。

## 读取和发布边界

原 material reader 的每文件上限是 1 MiB，而选定 policy 原件为 2,667,752 字节。本请求只在调用者的独立 module 中，将完整 `read()` 函数的一个 `<=1048576` literal 改成构造器已有的 `<=16777216`。`publisher-final02/reference/read.original.py`、`source/read_projected.py` 和 `SOURCE-READER.patch` 证明其他字节完全不变。exact3、完整读取、SHA、full9、canonical parent、nofollow、single-link 和重复读取 BOOK 均保留。冻结源、生产 15 源、phone / actor 的 8 MiB 输出上限及图像预算均未修改。

准备的 payload 含 177 个文件、展开成员总计 3,505,344 字节。其中 171 个既有参考源共 3,372,688 字节；最大成员 71,820 字节。8 个直接既有输入共 2,832,956 字节，最大为上述 policy。完整逐文件清单在 BYTE-BOUNDS 中。

运行时沿用：每个源原件 16 MiB；构造器唯一绝对路径池 64 MiB；完整 payload 8 MiB；每个 prepared member 4 MiB；每个最终发布树 32 MiB、256 文件、128 个目录。最终树在加入 terminal / proof 后再核这些边界。实际 transitive 原件数量、完整 full9 BOOK、总字节及最终输出数量只会在真实调用后记录，现在均为 null。

发布器复制已审调用者的七个完整函数。实际 `publish_material()` 只替换精确目录 tuple，保持 held dirfd、create-only、完整目录成员、文件 full9 / byte readback、fsync 和 DERIVATION 最后写入的整个正文，并生成完整反演。audit hook 禁止 subprocess、网络、exec / fork、信号、删除和 rename。它只会在既有工作根下创建两个明确的新目录。

## Root 的一次主机操作

1. 在 `TRANSPORT-PLAN.UNEXECUTED.json` 指定的新 transport 目录，以 create-only 方式放置最终 publisher 和 payload。11 个 payload chunk 均不超过 65,536 字节；必须重组并完整读回 SHA，不能把超时当成功。不要把旧草稿同名 publisher 上传。
2. Root 审阅最终源码与请求后，按 `publisher-final02/PROCESS-REQUEST.UNEXECUTED.json` 发起一次纯主机 process。请求使用现有 `mac` host 和 `/usr/bin/python3 -I -B`，稳定 key 为 `fc33-negative-source-only-native-v3-r5-01`；超时 120 秒。
3. 完整保留 request / start / status / stdout / stderr。若工具超时，按同一个实际 job 对账；不要重放任务。若输出目录已经出现，无论完整或部分，发布器都会拒绝再次创建。
4. 只有实际 controller 成功、完整终态与发布原件读回一致后，才记录源码派生成功。第一棵树的 DERIVATION 只证明输入副本出版，不能代替第二棵树的完成回执。任何失败留下原状，代码不自动清理、覆盖或续写。

源出版预期产生 11 个工具族和 7 个 case 模板；**所有 actual plan、freeze admission、sealed BUILD、four-role READY、owner request、nonce、scope、argv 和 fresh label 均须仍为 null**。源码出版不启动下面的任何步骤。

## 后续用例入口和未完成层

| 用例 | 派生后入口 | 必须由实际用例补齐的原件 |
|---|---|---|
| NEG-03 | `physical-component/source/run_physical_component_once.py` | 同源 geometry fixture 单列；实际旋转分支需 baseline、一次旋转、拒绝且零 input、精确恢复、完整原件 closer。 |
| NEG-04 | `physical-fault/source/run_physical_fault_once.py` | watcher 先 armed，一次新 Send，dispatch 前身份和零 dispatch，再对本轮 owned carrier 用原 pidfd 路径断连，终态与清理闭合。 |
| NEG-05 | 同上 | 独立公开原件证明首次效果，再断开本轮 owned carrier；最多一次效果，未知保持未知，不重放。 |
| NEG-06 | `host-neg06/source/execute_namespace_once.py` | 原协议为 host_isolated：独立 host namespace、真实持有的 HTTP 请求、有界超时、零 dispatch、所创建子进程的 wait 和进程组不存在。不能声称启动了真实模型。 |
| NEG-07 | `physical-fault/source/run_physical_fault_once.py` | 本轮精确 worker pidfd、原结果期限、四文件 pre-late fence、迟到原结果、终态字节保持及最多一次效果，完成后收尾。 |
| NEG-08 | `ui/source/cancel_native_once_r10.py` | 一次新 Send，原模型 active / 零 dispatch，唯一选定任务的 UI Cancel，手机及 P4 全原件，CPU 和 native 独立关闭。 |
| NEG-09 | 同上 | 独立确认第一次效果后，通过既有 operator UI 路径取消唯一任务；保留效果，provider 不再输入或强制返回，双侧全原件和独立关闭。 |

这里保留原 signal / cancel / transport 逻辑，未创建新的 SSH 目的地或凭证，也未允许取消已有非本轮任务。实际 BUILD、安装和 READY 仍待后续真实链路；旧 fixture 和历史任务不能填入这些槽。

## NEG-03 的外屏与旋转口径

固定协议 `37318 / c573959e…` 的 `layer` 是 `component_direct`。操作原文允许“向冻结 mapper/parser 提供未资格 display/rotation observation，或进行一次显式安排的 physical negative”。关闭条件是 screenshot / tap / public-return 拒绝 display 0 纵向资格之外的配置、不能向其他 display 注入输入，并将 fixture 与 physical 结果分开标注。协议还明确优先使用原形状的只读 display receipt fixture；真实折叠 / 旋转需要单独安排并恢复本轮基线。

因此原协议没有额外要求“必须实际使用外屏”。当前工具覆盖外屏的 mapper/parser fixture 与另列的实际旋转入口；不得把 fixture 描述成已测外屏。若实际执行了旋转分支，必须以该次 baseline / rejection / restoration 原件闭合，不能拿 fixture 抵消未完成的物理恢复。完整原协议行和判断保留在 `publisher-final02/NEG03-PROTOCOL-BOUNDARY.json`。本包尚未运行同一实际 release 下的 fixture 或旋转，NEG-03 没有获整项通过。

## 已做的准备核验及限制

本包只核全文件 pin、精确 literal / helper 反演、payload 完整字节、Python syntax、请求 / 清单关系与原协议边界。既有 7 项 observer、70 项 geometry assertion 和 15 项 template 控制仍是原 source-only 控制，不重跑、不累加为新的通过数。没有执行公共构造器正例、source publication、实机用例或模型请求，也没有据准备文件授予任何整项资格。
