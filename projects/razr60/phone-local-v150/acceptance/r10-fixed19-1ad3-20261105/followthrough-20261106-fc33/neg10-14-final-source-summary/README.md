# NEG10–14：最终 15 源的已观察条件映射

本包只整理并完整绑定已经执行过的主机控制，新增必要 NEG14 主机控制的完整原件也在包内。**当前没有 actual BUILD、installed tuple 或 actual READY 资格；没有手机动作、模型调用、真实 native dispatch，也没有宣称五项正式关闭。**

当前共同待关闭门是：实际 sealed BUILD 和实际 installed/start/READY 原件，经对应的受审 reader 验证；其中完整 15 份生产源码必须与本包实际测试过的 15 份字节完全相同。原固定协议没有要求的 RSS 或真实模型 slot 指标，不被本包新增为资格阻塞。

## 主要入口

| 文件 | 用途 |
| --- | --- |
| [CONDITION-MAP.json](CONDITION-MAP.json) | 23 条条件逐条对应精确结果文件 SHA256、JSON pointer、原 case 名、生产源码 pin 与实际符号。23 是映射行数，不是新增测试数。 |
| [HOST-SUMMARY.json](HOST-SUMMARY.json) | 纯汇总入口实际完成的结果：回读并 bookend 87 个文件、1,221,400 原始字节；actual 槽位保持 null。 |
| [EVIDENCE-PINS.json](EVIDENCE-PINS.json) | 26 个直接证据 pin。完整源和保留原件继续沿被固定的 manifest 验证。 |
| [summarize_observed_evidence.py](summarize_observed_evidence.py) | 可独立执行的纯只读汇总器。它不重新运行测试；核源码、结果、原 controller 终态、双 EOF、原件和条件指针。 |
| [bind_actual_source_graph_UNBOUND.py](bind_actual_source_graph_UNBOUND.py) | 等实际原件齐备后的纯绑定候选。FROZEN_INPUTS=None 时，在解析、读取或加载选定 reader 前拒绝。 |
| [ACTUAL-SOURCE-BINDING.template.json](ACTUAL-SOURCE-BINDING.template.json) | 实际输入模板。各 actual descriptor 保持 null，不能当作可执行计划。 |
| [UNBOUND-INTERFACE-OBSERVATION.json](UNBOUND-INTERFACE-OBSERVATION.json) | 已观察的未绑定拒绝：零 read callback；没有运行 actual 正控，不计入 NEG 数量。 |
| [references/fixed19.original-protocol.json](references/fixed19.original-protocol.json) | 原固定协议，37,318 B / `c573959e59fd9fbe7a850d6d2d6d747e3135718493f15de4a8acde850bad93b0`。 |

在完整包目录下复现纯汇总：

```bash
python3 -I -B summarize_observed_evidence.py
```

输出应与 HOST-SUMMARY.json 完全相同。此命令只读取已有文件，不启动测试子进程、模型或手机任务。build_condition_map.py 是同一份静态映射的确定性构造器；目标文件若已存在且不同，会拒绝覆盖。

## 精确源组合

COMBINATION 为 **4,695 B / `7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411`**。其状态原文为 `REVIEWED_COMPONENT_BYTES_NOT_FOUR_ROLE_READY`。

全部 15 份源码保留在 references/native-v3/candidate/source/，完整清单在 CONDITION-MAP.json 的 `sources`，与 COMBINATION.production_files 和原实际测试 CANDIDATE-PINS 三方逐字节比较。五份变化源如下，其余十份保持原组合字节：

| 源文件 | 字节 | SHA256 |
| --- | ---: | --- |
| phone_observation_tools.py | 55,981 | `4f95178996a2d7a604ae56eecd0f7725657222783f5cab5a7ff868f85a8cd086` |
| phone_local_tools.py | 13,927 | `2d0c9cc8f1ff0c643aab3daeef07c12e84541f1c2f0bfd13c8043c5c8fa58930` |
| provider_codex_host.py | 41,618 | `0ea72f9e38307055ead790aa5828143c4ba431ae33c8e44e19c5893073ade5fa` |
| provider_phone_local.py | 70,303 | `0c04bbd0f2d8f88a0795776a23a6cb34bf5f9a88aabc09e8aa3c3ff34c534bee` |
| daily_phone_local.py | 22,059 | `a16be75d5a47a86a7c0d222dc95e8b2373017b3291ce644864e2dd3b763447b8` |

本包没有再修改这 15 份生产源码。native v1/v2 与历史证据保持各自原身份，不能替代最终 v3 的映射。

## 条件到实际证据

| 用例 | 已观察的生产源码行为 | 精确原结果 | 当前剩余明确门 |
| --- | --- | --- | --- |
| NEG10 | budget、expired、foreign image、old round 四项均由真实 PhoneTools.map 在映射/dispatch 前拒绝；状态、mapping record、input write 不变。 | selected guards 的四个具名 case；完整 13 项结果 `1a0e24bb…`。 | actual sealed / installed / READY 同 15 源绑定。 |
| NEG11 | trusted map/accepted turn 的 target、call、tool、scope；严格序列；块/累计长度与编码；完整终态和信号组合；截断；request/config/完整 observation 哈希损坏拒绝。真实消费者链将错误结果降为失败。 | native 结果 `6c62408d…`；parser、consumer、trust、dispatch、ledger 各原数组单独保留。 | 同源实际采用门；下文列协议本身的信任边界，不扩大威胁模型。 |
| NEG12 | 缺/无效确认、缺/错误公开回执、缺/错误返回分别 turn.fail，missing 精确为 input/public/return；局部 coverage 即使列出的条件满足也不能整项成功；迟到终态不重写。 | shared 结果 `0250099e…` 的八个业务场景。 | 同源实际采用门。synthetic 正控不授予现场业务成功。 |
| NEG13 | 真实 O_EXCL 双线程一接受、一拒绝、恰一个 binding；错误 session/profile 在竞争前不消费；旧身份、替换 stream、旧 nonce 再入均拒绝，原 claim/binding 保留。 | 同一 shared 原 14 场景中的模板/并发/real-pipe admission 部分。 | 同源实际采用门。没有重新消耗真实 native/model scope。 |
| NEG14 | 精确认识的两个 rename 容忍；未知 missing、symlink、ENOTDIR 和真实 EACCES 拒绝；逻辑容量首次拒绝零新增消费；retained orphan intent 保留且拒绝新工作；本轮自有进程和 FD/thread 收尾。 | 原 selected 13 项，加独立新 owned 4 项 `5a3690d3…`；不把 13+4 宣传成整项重跑或重新累计的总覆盖。 | 同源实际采用门。资源定义按原 host_isolated 协议执行，未另加 RSS/真实模型 slot 门。 |

### 原运行组和 controller 原件

| 原运行组 | 原数量，禁止跨组累计 | 实际 controller job | 完整结果 SHA256 |
| --- | --- | --- | --- |
| native v3 | parser 73；consumer 12；trust parser 40；trust consumer 11；dispatch binding 9；独立 ledger binding 1 | `1a1b18b95c3-fc05-7980` | `6c62408d6d19460757d0160ac49aaf3b2fa3b1e1673a5220bbf4ba1a1e945968` |
| shared business/admission | 原 14 场景 | `1a1b18878e5-fc05-7966` | `0250099e4209e1f13d5def2b38298826b3e574e3adf95048986f45f3362a75f2` |
| selected image/filesystem | 原 13 项：4 图像、8 文件系统、1 资源 | `1a1b19980ee-fc05-79c6` | `1a0e24bb1d9caa9e7b95669bdedea9470ff769f4ac3335b0aef1e898cc0d4d90` |
| 新 NEG14 必要补充 | 4 项 | `1a1b1f12896-fc05-7b9d` | 内层 `5a3690d3111a5cca31332aa363853ab1d821d71e153997465484fd190075f648`；外层 `55ac79c28a0d8c382b60d9076dbd7997e55f406067145564c65489746884ae3b` |

四组均保留 start/status/read，实际 exit 0、完整且 durable、无 timeout/cancel/自动 retry、stdout/stderr 双 EOF。stdout 中完整 result 的长度与哈希继续匹配保留原件。汇总器只核对这些已发生运行，不生成新测试计数。

## NEG14 新 4 项的准确范围

完整源码、17 个输入原件、publication、controller 请求与回执、36 个回读文件位于 neg14-owned-capacity01/。原输入 15 份生产源码 + config + tool client 均完整 pin。公开 daily CLI 实际经过 load_local_config 与 validate_executor，没有旁路该 gate。

1. **真实权限拒绝。** 隔离 namespace 的自有目录权限导致内核 `PermissionError errno 13`。生产 evidence_item_size 和 os.walk 的 onerror 两条路径实际传播错误。旧 selected 13 项里仍保留的 EACCES callback 是合成异常同对象检查；它与本次真实 EACCES 明确区分。
2. **公开逻辑字节容量。** 使用生产 CLI 公开最低 `--max-evidence-bytes 1073741824`。预留 128 MiB 后，实测 evidence 总量 939,524,095 字节时仍存活；增加一字节至 939,524,096，首次拒绝。旧 claim 完整字节与 full9 不变；没有额外 claim、template binding、worker record、dispatch 或 provider connection，ownership lock 可重新取得。稀疏文件的真实 st_size 用于该逻辑预算。**没有填满磁盘，也未触发 ENOSPC 或 200,000 文件计数上限。**
3. **保留孤儿启动凭据。** 明确 synthetic 的未 join intent 被实际 daily admission 拒绝，READY 未成立；intent 与旧 claim 完整原件保持不变，没有伪造 join。没有创建真实模型孤儿 worker，也没有终止其他会话的进程。
4. **本轮资源收尾。** 两个自有 daily 子进程实际 wait、pidfd terminal；原 PID/PPID/PGID/SID/start_ticks 保留；两组 census 为空且 kernel signal 0 为 ESRCH。外层 bwrap namespace 子进程另有实际 wait/组消失。内外 FD/thread 回基线，自有测试目录移除；真实 worker admission 始终为零。成功路径不发送非零终止信号。

原协议 NEG14 明确 `layer=host_isolated`，要求 confirmed worker/child/file-descriptor cleanup 回到实测基线。本包没有把 RSS、全套 installed runtime 或真实模型 slot 的未测量范围改写为新的关闭门。其现场指标若后续采集，可作为同一全量报告的额外原始观察。

本地容器 namespace preflight 被内核拒绝后，没有去掉 unshare 隔离；转用已授权且已有的 pocket4 bwrap 路径。该环境说明见 neg14-owned-capacity01/LOCAL-ENVIRONMENT-NOTE.json。原实际成功 run、publication 和只读 collection 的三个独立 job 均保留，未重新执行原任务。

## native 校验的信任边界

完整 call 来自真实 map，request digest 和 config fingerprint 从可信 call/scope/config preimage 构造；不是采信返回值的自洽身份。完整 observation 和 registry terminal receipt 也由消费者重算。实际历史 NEG01 的两份原调用只读核过当前 schema 和三个 preimage；不把历史手机行为改标为新组合。

generation 只在 native claim_spawn 后分配，当前协议没有一个消费者可先验取得的独立 admission counter 或 MAC。代码验证其精确类型、合法范围和完整 receipt/observation digest 一致性。攻击者同时改写 generation 以及全部未签名哈希时，本协议无法独立区分；本包不声称拥有这种证明。

event record elapsed_ms 严格验证类型和范围，但实际 producer ObservationDigest 不包含该字段。terminal.elapsed_ms 包含在 digest 中，改动拒绝。未知 schema 和未知事件种类均 fail closed；没有隐藏 fallback。

## 实际原件齐备后的绑定步骤

当前 `FROZEN_INPUTS=None` 和 actual 模板空槽必须保留，不能拿旧 reader 的 FIXED 身份代填。

实际 sealed BUILD 与 install/start/READY 原件齐备后，由唯一 Root 完整审查后绑定 ACTUAL-SOURCE-BINDING 的实际输入 descriptor；其中 install reader 本身必须已经绑定真实 FROZEN_INPUTS 和 FROZEN_EXECUTION_PLAN，且 SOURCES.release 指向同一份实际 release reader。本候选不改写 reader 常量。

纯入口 `verify_actual_source_graph(inputs_raw, *, read_pinned)` 实调受审 install reader 的公共 API。该 reader 自行执行真实 release/BUILD、exact8、三阶段 actor、完整原件与 READY gate。入口随后沿其已核 original_map 的显式 original→retained 映射读取完整 shared15，与本包实际测试的 15 份字节逐一比较，再做最终 bookend。不会猜测 archive member 或 host/phone alias。

正向绑定尚未执行。返回也只标明已有 host 条件与实际 installed source graph 对齐，保留 READY 的 transport-only scope，不生成新的业务、whole-case 或 fixed19 credit；最终关闭仍按原固定协议作决定。本包没有增加任何新的手机计划、nonce、scope、信号或部署动作。
