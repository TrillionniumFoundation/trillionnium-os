# razr 本地模型与后台工具任务：最终第 27 案验证快照

本报告对应 2026-11-16 的 Hepta `0.69.0`，应用源码提交 `f2f1b8710f4b33dcf2ae5f7512d9ee4472215f6e`，APK SHA-256 为 `bc683d4a3685883a3a7c1be623e947a7cf04978f150c26e7deeec88f442cba5d`。本版只新增一次受影响的 LFM2.5-8B-A1B 官网机票复测；前 26 个真实任务的原结果不变。最近的 Notes 与自然价格证据保留在 e999 构建，没有将它们写成新包上的重跑。安装保留原 session、preferences、模型配置和可访问性绑定；实际安装前后严格主屏 guard 均通过。第 27 案结束后已另行恢复 LFM3 默认配置，这属于配置恢复，不增加真实任务，也未追加新推理。详见 [安装审计](BC683D-INSTALL-AUDIT.json) 与 [默认配置恢复审计](BC683D-LFM3-DEFAULT-RESTORE-AUDIT.json)。

**当前有完整真机证据的是：LFM3 在手机 Hexagon NPU 上生成工具调用，并在后台 Moto 笔记中完成创建、保存、列表核对、同项重开与正文核对。购物、网页机票和原生携程尚未达到用户要求的完成标准。** 因此，本报告的 `all_requested_capabilities_qualified` 明确为 `false`，不会把“可以运行模型”“通过编译”或“已清理进程”当成业务完成。

完整数据见 [PHONE-VALIDATION.json](PHONE-VALIDATION.json)，当前源码、编译输入、签名及必要主机门槛见 [BUILD-AND-HOST-VALIDATION-f2f1b8.json](BUILD-AND-HOST-VALIDATION-f2f1b8.json)，上一个 ff0a 构建另见 [6e0129 构建证据](BUILD-AND-HOST-VALIDATION-6e0129.json)，上一阶段绑定另见 [e999 构建证据](BUILD-AND-HOST-VALIDATION-cfacefe.json)。证据文件以 SHA-256 关联原件；公开报告不包含私人笔记正文、截图、设备序列号、网络地址或签名密钥。

## 默认模型与实测选择

第 25 案实际配置为 `LiquidAI/LFM3-1.7B-GGUF` 的 `lfm3-1.7b-qad-q4_0`，模型 1,049,615,680 字节，SHA-256 `43a7d09a0e9cba91b63eb7052488b9564569bddfd65754d2e426465e572a7452`。运行时为 GenieX `v0.10.0`、SDK 提交 `071f609995470bdb0e0769ab964754adfaab7e47`，`compute=npu`、设备 `HTP0`、上下文 8192、4 个推理线程，未允许自动 CPU 回退。

在已经测试的普通 Notes 工具任务中，LFM3 的已测响应时间和较小的权重文件支持将它作为当前默认模型。下面是各自真实单次请求，前三个模型对照使用同一早期 APK，但提示长度、tokenizer 与当时系统状态并非完全受控；后续回归使用不同构建。它们不能当成控制变量跑分或通用智能排名。

| 模型和后端 | 请求提示/生成 token | Prefill tok/s | Decode tok/s | SDK TTFT | App 请求耗时 | 实际结果 |
|---|---:|---:|---:|---:|---:|---|
| LFM2.5-8B-A1B，NPU | 5116 / 139 | 595.96 | 20.30 | 8.63 s | 33.53 s | Notes 闭环通过，早期构建 |
| Orvena-4B，NPU | 5421 / 132 | 339.62 | 7.54 | 16.04 s | 45.24 s | Notes 闭环通过，早期构建 |
| LFM3-1.7B，NPU | 5138 / 129 | 871.33 | 24.09 | 5.90 s | 15.07 s | Notes 闭环通过，早期构建 |
| LFM3-1.7B，NPU，较早 5dfa | 5183 / 136 | 871.43 | 23.31 | 5.948 s | 14.346 s | 新唯一 Notes 闭环通过 |
| LFM3-1.7B，NPU，最近 Notes 的 e999 | 5191 / 134 | 867.37 | 23.43 | 5.985 s | 14.309 s | 新唯一 Notes 闭环通过 |
| Orvena-4B，OpenCL GPU | 5412 / 1 | 101.62 | 不构成有效稳态测量 | 53.37 s | 73.017 s | 请求超时，任务失败；随后普通 UI 恢复空闲 |

最近 e999 Notes 的原生请求耗时为 14.285288 s；后台目标 display 创建至终态决定为 22.294 s。这两个时间各有明确单调时钟范围，不等于完整任务从受理到清理的总时长，也没有使用主机收证耗时冒充推理或任务耗时。

运行日志确认加载 Hexagon v79 库、选择 HTP0，并将 25/25 层下放到 HTP0 后端。日志还报告 6 个 HVX、1 个 HMX、8 MB VTCM 等运行时元数据。它们不是独立的逐算子硬件利用率、功耗或 TOPS 测量。日志枚举到 Adreno 830，不代表当前 NPU 请求同时使用了 GPU；通用日志中的 “GPU layers” 字样也不能单独识别设备。较早的 34 个资源样本中系统 MemAvailable 最低约 6.23 GiB，原生进程 RSS 不包含全部 DSP 共享/ION 内存，不能当成模型总内存。

## 最近 e999 的三项真实后台回归

| 独立案例 | 模型与动作 | 完成判定 | 清理与主屏记录 |
|---|---|---|---|
| 唯一 Moto Notes | 1 次本地模型请求选择 `notes.create`；controller 执行 2 个受约束 child 操作 | 创建后正文、保存列表、同项重开、稳定正文均核对；通过 | 内外 display 均释放，worker 正常退出；13 个已保存焦点样本一致 |
| 小米官网自然价格 | 未进入模型；没有工具动作 | 原生推荐子节点几何范围检查拒绝；失败 | 正常清理，无 Stop；18 个已保存焦点样本一致 |
| 南航官网测试机票 | 2 次本地请求：先 wait，再 click 实际订票入口 | 入口点击已派发并进入 booking_new；后续完整观察超时，未提交查询；失败 | 正常清理，无 Stop；19 个已保存焦点样本一致 |

Notes 的模型真正决定了一次工具调用。后续“返回保存—列表查找—点开同一项—核对正文”由已授权的确定性 controller 工作流完成，child 记录明确 `model_issued=false`。最终 `completion_actor=controller/tool_workflow`、`model_reported_success=false`、`model_done_synthesized=false`。这证明了本地模型调用工具及真实保存核对，不能扩写成每个 UI 步骤都由模型自主规划。

该 Notes 的首次重开帧已经含完整正文，因而没有实际触发“首次 AX 正文缺失后有界重读”分支。列表正文精确相同，编辑器沿用既有 40 个换行后缀规则；没有声明数据库持久字节、重启后持久性或新数据库条目 ID 已验证。目标 display 120 的 broker 正常 exit 0；外层控制器 display 119 的最终 release 回执绑定原 lease。第一次空回执轮询原样保留，后续有效回执及最后 window 清单证明两者均释放。详细证据见 [E999-NOTES-AUDIT.json](E999-NOTES-AUDIT.json)。

自然价的 owner/contract 与所有已保存 capture binding 已核对，范围是 `bounded_natural_official_product_price.v1`，不要求完整单件规格。第二组 DOM 取得只读资格后，原 `compareNative` 在 `contains(recBox,rowRect) && !overlap(targetBox,rowRect)` 处拒绝，错误为 `visible native recommendation escaped its container`。这是原有通用几何门槛；新结构诊断针对另一种 typed changed-row 失败，因此本例没有产生那份结构证明。此时观察阶段仍余约 6.797 秒，不能把本例改写成 RPC 超时或模型失败。

两份保存的 retained AX 投影确有推荐子节点越出父矩形；至少一个 clickable 子节点还与推荐区外的 clickable 兄弟几何相交。它们不能恢复原私有比较首个拒绝行，也不能证明命中/遮挡行为或变化无害。完整边界见 [NATURAL-PRICE-E999-GEOMETRY.public.json](NATURAL-PRICE-E999-GEOMETRY.public.json) 与 [工程判断](PRICE-GEOMETRY-ENGINEERING-BOUNDARY.zh-CN.md)；没有删除比较门槛来取得通过。

网页机票首页修复已到达实际模型：第二步输出 click n38，执行器接受并真实派发，随后进入 `/booking_new` 的新页面 epoch。后续从 52 节点空壳变为 795 节点表单，旧括号正确拒绝并启动只读重观察。该既有 bookingPending 阶段只有固定 6 秒；最后第二次完整捕获发出时仅余 1368 ms，随后到原截止点失败，没有第三轮模型请求或查询。两个已保存 DOM 相同不能拼成新的完整 native bracket。本例证明入口提示修复产生了实际入口点击，仍不是查票完成。测试日期/城市属于固定测试数据，不代表用户真实行程。详细清理与动作证据见 [E999-FLIGHT-AUDIT.json](E999-FLIGHT-AUDIT.json)。

此前 5dfa 三例原判定保留：Notes 通过；自然价在另一树路径 bounds 变化后耗尽观察预算；网页机票 20 个模型动作全部为 no-effect wait，未点击或查询。它们没有因本次入口修复而被追认为成功。

## ff0a 的机票复测：已到可查询表单，但模型提前结束

第 25 案使用同一套 LFM3 配置，累计 9 个模型请求、7 个实际点击：订票入口、出发城市入口、北京、到达城市入口、上海、日历入口及完整月份绑定的 11 月 17 日。日期单元格的真实复合标签为 `17¥490`；本例实际经过新日历标签匹配，且随后由新表单读回核对出发地、目的地和完整日期。日历价格注释不是航班结果或可订票价。

最后一帧已经是 `official_query_ready`，唯一允许点击的 `n10` 是查询按钮，下一步提示明确要求仅点击一次查询。LFM3 却输出 `done(failure)`，并在文字中误称查询已经完成。任务记录中的查询尝试、原生查询派发及结果核验均为 false。最后动作排空时原任务仍余约 224 秒，实际原生上下文 admission 正常，不能把这次提前结束归为任务到期、上下文溢出或 UI 没有查询入口。一次模型失误也不能推导一般成功率。

第 2 步较早的 `done(failure)` 因观察过期被拒绝，随后作了新的观察和模型决策；最后第 9 步的失败结束被接受，但没有手机操作效果。这是已有 stale 动作路径，未产生新增 typed 预派发恢复证明。三条加载等待分别属于首页初始 32 秒阶段的两次重观察和既有城市选择器 16 秒阶段的一次重观察，`bookingPending` 都为 false。因此，本例不构成新增 booking 16 秒分支的实机因果验证，旧 e999 的 6 秒失败原件继续保留。

整个任务只创建一个保留的 warm worker：同一 generation 接受并完成 9 个请求，模型 hash、SDK init、model create 各 1 次，model reset 9 次。任务结束时 App 层独立记录该 worker 实际正常 exit 0；不能把 9 个请求说成 9 个 worker 退出，也不能把 native 自报的计划退出当成实际退出观察。本案的 9 次请求 App 耗时为 11.502–16.306 秒，SDK decode 为 16.14–23.98 tok/s；各步提示和生成长度不同，不是统一输入的稳态跑分。后台目标创建至终态决定为 266.230 秒，仍不包含更早受理和更晚清理。

完整动作、query-ready、日历读回、原生回执及清理见 [FF0A-FLIGHT-AUDIT-v2.json](FF0A-FLIGHT-AUDIT-v2.json)。该例仍是业务失败；未派发真实查询、没有航班结果，更没有订票。

## 同 APK 的 8B 对照：捕获尚未稳定时提前结束

第 26 案实际加载 `lfm2.5-8b-a1b-q4_0`，权重 4,844,678,368 字节，SHA-256 `48ed1465d761311b2fd57b7fb46cf969a20b3a8281945b04e10f52bd1609e715`。原生回执与核心日志确认 HTP0、25/25 层下放到该后端、8192 上下文、4 线程且无自动 CPU 回退。一次冷启动请求正常生成 117 token，输入 3446 token，App 耗时 33.726 秒、native 28.530 秒，pp 506.36 tok/s、tg 15.02 tok/s、SDK TTFT 6.852 秒。模型实际运行资格已确认，业务仍失败。

首次首页观察发生变化后，控制器进行了一次原 32 秒阶段内的只读重观察；后一次 callback 因 visual callback 前后 DOM 变化而 unavailable，直接发布待捕获状态。模型实际输入是 `official_page_capture_pending`，节点与允许点击集合都为空，grammar 只允许 wait 或失败/部分 done。8B 选择了 `done(failure)`，没有执行任何点击、城市/日期选择或查询。随后终末独立观察才识别出 `official_home` 和 n38 订票入口，该帧没有再送给模型。

这也暴露了一个准确的软件提示缺口：等待域本来提示只可等待或报告未完成，但 `withProgress` 在未确认城市时将它覆盖为先选择城市和日期。提示与当帧允许的操作不一致，点击权限本身仍被正确关闭。观察返回时原只读阶段还余约 28.9 秒，最后动作排空时原任务还余约 436.584 秒，不能把本例归为任务超时或算力不足。新增 bookingPending 16 秒和 typed 预派发恢复均未实际触发。

这是同 APK、同目标、同 480 秒宿主观察上限的独立任务；应用原期限没有改变。LFM3 最后面对的是有合法查询按钮的 query-ready 帧，8B 面对的是尚无合法点击目标的 pending 帧。不能从两次不同状态直接排出模型的一般规划能力高低，也不能保证若 8B 选择 wait 就必然成功。证据见 [8B 任务审计](FF0A-LFM8B-FLIGHT-AUDIT.json) 和 [第 26 案上下文诊断](FF0A-LFM8B-CONTEXT-DIAGNOSIS.public.json)。

模型切换使用显式审阅的私有配置 CAS 与空闲 controller 精确进程退出/重载，没有 force-stop，没有普通 UI 模型选择。四次完整主屏 guard 的原 activities/windows 快照已重新执行同一纯函数校验，配置逐字节读回，原失败 session 保留；这属于测试 setup，不增加实际任务数量，见 [配置切换审计](FF0A-LFM3-TO-8B-SETUP-AUDIT.json)。第 26 案快照结束时为 8B 配置 `334ab319f5b3a1b28d30afaabee031ef03ea6eb5c8c2563adaadb90fd285dc53`，后续默认配置决定以实际最终回执为准。

## bc683d 的唯一受影响机票复测

本次两文件修订针对第 26 案明确的软件问题：最终仍为待捕获阶段时保留等待提示；只有已经开始的初始阶段、同身份、固定 DOM 变化原因且恰好剩一次读取时，才拒绝旧 pair、关闭旧私有原生观察并获取完整新 pair。原 32 秒阶段、原任务截止点、最多两次额外读取、动作授权和完成条件均未放宽；已提交查询或待选择读回的高优先级提示保持不变。

第 27 案继续使用已集成的 LFM2.5-8B-A1B / HTP0，6 个本地请求依次作出 5 次真实点击：订票入口、出发城市入口、北京、到达城市入口、上海。全部点击 accepted、dispatched 且不 stale；执行器均绑定目标 display 126 和原 generation，并记录实际 effect 与 worker 排空。第 6 步是被接受的 `done(failure)`，没有派发手机动作。

最后送给模型的页面仍为 `official_query_form`，唯一允许点击的是 n24 日期控件，purpose 为 `choose_departure_date`，缺少 `actual_selected_complete_date_confirmation`；grammar 允许 click、wait 或失败/部分 done。8B 却把前 5 次点击理解为已经完成搜索和选择，提前结束。实际没有进入日历、没有完成完整日期选择、没有查询 reservation、查询派发或航班结果。这是本例可见的终止/状态判断失败，不能说页面已无可继续能力，也不能把模型文字当成查询证明。

独立查看保存的完整末帧仍可见北京→上海、11 月 17 日周二、1 成人及查询按钮，没有可见登录或验证码。模型实际收到的是结构化节点，不是这张 PNG；结构化域仍要求先完成日期确认，屏幕上存在查询按钮不等于模型当帧获准查询。最终动作排队时原任务期限还余 257.257 秒，终态决定时还余 246.703 秒。原生精确输入为 4435 token，含生成及预留后的 4947/8192 上下文准入为 true；Java 启发式提示不是原生拒绝原因。

同一 warm worker 完成 6/6 请求，模型 hash、SDK init、model create 各 1 次，reset 6 次；App 层在任务关闭后确认唯一 worker 实际 exit 0，未经强杀。各请求提示 3480–4435 token、生成 126–180 token，App 耗时 13.447–30.643 秒，native 13.436–24.622 秒；SDK pp 501.31–614.71 tok/s、tg 14.74–21.56 tok/s、TTFT 5.832–8.893 秒。首请求包含本任务的加载成本，输入/输出长度不同，不能当统一输入的稳态吞吐或通用模型对比。后台目标创建至终态决定为 233.289 秒，不包含之前受理和之后清理。

本案没有 `web-initial-capture-retry` 或 typed 预派发恢复记录，6 份实际模型输入也没有 pending 阶段。三份只读加载等待来自已有 initial captured-pair 的第 1/2 次重观察及城市阶段第 1 次；`bookingPending` 全为 false。因此本案没有实际覆盖新增 unavailable 重读、pending 文案或 booking 16 秒分支，不能把进入首页归因于这些新分支。目标 126 和外层 125 的原 lease 均释放，最终 window 清单中均不存在；主机没有 Stop、超时接管或主屏输入，任务按失败正常清理。详细证据见 [第 27 案完整审计](BC683D-FLIGHT-AUDIT.json) 与 [实际提示、上下文及性能摘要](BC683D-FLIGHT-CONTEXT.public.json)。

最终默认配置已从 8B 的 `334ab319f5b3a1b28d30afaabee031ef03ea6eb5c8c2563adaadb90fd285dc53` 恢复为 LFM3 的 `b1fa9a0f9f23562b667217063ce491eeb5bfe489f3dd45044d1ae733e2056ef2`：`lfm3-1.7b-qad-q4_0`、NPU、8192 上下文、4 线程。配置提交和逐字节读回成功，原失败 session 保留；4 组保存的主屏 guard 原件重新校验均通过，完整焦点一致、0 主屏输入、无 force-stop，原空闲 controller 的精确进程退出已记录。

这次恢复的 `native_profile_verified=false`：没有为确认恢复而额外运行一次新 APK 上的 LFM3 推理，更没有第 28 个任务。默认推荐仍来自先前真实 Notes 工具链的响应时间和较小权重文件；不能表达成全部 App、复杂查票或任意任务的最佳模型已经得到证明。

## 原生携程与网页流程必须区分

原生 Moto Notes 是真正的目标 App 工具流程。价格和南航机票案例则使用独立 web helper 中的官网页面，它们不能替代原生小米商城下单或原生携程查票的资格。

原生携程此前在启动前被 `APP_ALREADY_ON_MAIN_DISPLAY` 拒绝，没有启动模型、派发 App 动作或搬动旧任务。只读检查发现当前用户的 display 0 已有携程 `singleTask` HomeActivity 任务；虽然该任务 STOPPED 且不可见，它仍可被 Android 复用。现有 broker 已使用额外任务 flags，包级他屏任务门槛仍有实际保护作用。关闭或迁走用户主屏任务不是本轮允许的测试方法；这也不是模型算力失败，更不能概括成 Android 一律不支持后台多屏。

已有四次历史“小米价格”测试实际属于带单件规格和价格条件的 legacy contract，现有域没有它的完整规格完成路径。四次失败均按原 owner/contract 保留；新的自然价格请求是独立范围，不能替代或洗掉旧失败。

## 后台运行依赖与主屏证明范围

产品的目标 App 虚拟屏 broker 在手机上由 controller 通过既有 `su` 授权启动，使用安装 APK 内的代码和本地 socket/lease；它需要可用的 root 授权、已启用的可访问性服务和解锁状态。测试期间额外承载 Hepta 控制 UI 的外层虚拟屏则是主机/ADB 测试辅助程序。桌面 Hepta 入口只在调用者 display 打开 controller，不会自行创建这个外层测试 display，也不会自动 Start。没有把外层测试基础设施写成已交付的独立手机后台控制 UI；断开主机和重启后的全流程尚未验收。

当前 controller 编译后的 manifest 没有 INTERNET 权限；本地模型推理由手机运行，不接外部模型。官网查价/查票本身仍需要网站网络，目标 App 的正常网络与“使用外部模型”是两回事。

上述 e999 三例、ff0a 两次机票和 bc683d 复测均执行了严格 prepare：启动外层控制器前拒绝 display 0 的任何 Hepta controller 任务（包括 STOPPED），真正启动前再次读取 activities/windows，启动后也不允许通过重新定义焦点基线接受主屏迁移。使用原 guard 函数重放实际保存的三组快照均通过，`own_ui_transfer=false`。主机锁不把 Android 的快照与启动变成原子事务。

| 构建与案例 | 保存的焦点样本 | 运行中最大采样间隔 | 包含准备阶段的最大间隔 | 结论 |
|---|---:|---:|---:|---|
| e999 Notes | 13 | 4.650 s | 40.901 s | 每个已保存样本均非空，完整 focus 同起始值 |
| e999 自然价格 | 18 | 4.809 s | 71.999 s | 同上 |
| e999 网页机票 | 19 | 4.951 s | 124.502 s | 同上 |
| ff0a LFM3 网页机票 | 65 | 5.077 s | 44.489 s | 同上；内外 display 和唯一 worker 均释放 |
| ff0a LFM2.5 网页机票 | 19 | 4.993 s | 56.938 s | 同上；内外 display 和唯一 worker 均释放 |
| bc683d LFM2.5 网页机票 | 58 | 5.127 s | 59.927 s | 同上；三道 prepare、内外 lease 和唯一 worker 清理均核对 |

这些结果与主屏 input 计数为 0 是两个独立事实；仍存在未采样间隔，未测量前台并行触控延迟或帧率。405f 的旧网页机票案例保存了焦点起止变化及部分 null 样本，原因无法从现有证据确定，报告保留这一失败边界，不归因于用户或系统。

只读能力检查发现 VDM 服务存在但创建列表为空，支持 secondary display/managed users 特征，当前只有 user 0，visible background user 的两项有效配置均为 false。没有通过创建普通后台 secondary user 解决携程的实机证据。AppFunctions 属于后续官方方向；本机发现服务，但针对携程、Moto Notes、小米商城的标准 AppFunctionService 查询未发现已启用入口。它没有被调用，也不是当前可用方案。

## 更大的 MoE：能运行与能完成工具任务的边界

MiniCPM-V 4.7 35B-A3B 的转换 bundle 已在手机完整核验 45 个文件、19,315,173,512 字节。独立 MobiInfer 进程的两个固定 mock JSON 和一次取消，经过严格离线 CLI framing 复核后有合格证据；日志记录 HTP0/HTP1，以及 41/41 层下放到 HTP 后端，两个完整案例 decode 约 4.37 / 4.62 tok/s，系统 MemAvailable 最低约 5.72 GiB。HTP0/HTP1 是逻辑会话，不能说有两颗 NPU。

这不是 Hepta App UID 中的模型集成，也没有 Hepta 工具调用或业务成功。其提示仅 115/142 token，不能外推到当前约 5k token 的 controller 请求。原 B1 装载失败、B2/B3 内存保护取消、B4 原解码器失败判定都保留；B4 是对固定非模型 CLI 尾缀的离线复核，没有重写原件。模型转换来自 fengerhu1 的固定 revision，OpenBMB 是底座模型作者，不能把该转换包称为 OpenBMB 官方发布。详细参数、内存 workaround、34 项 framing 检查和来源见 [MOE-35B-STANDALONE.md](MOE-35B-STANDALONE.md)。

## “全量测试”的实际范围

当前固定快照共 **27 个实际启动任务：9 个 Notes 目标经独立验证，18 个目标未完成；网页价格和机票的验证完成数均为 0**。前 26 个案例对象逐字段保持原样；最后一次只增加受影响的 8B 网页机票复测；另保留两次 Start 前 lifetime guard 拒绝，未计为模型任务。504 项通过的是原始 model/action/观察/清理证据的一致性核对，不是 504 个业务成功，也不是统计成功率。配置切换 setup 同样不计入任务数。没有宣称任意 App、购物下单、支付、原生携程或所有设备状态都已通过。

当前 f2f1b8 两文件修订的必要 host gate 是：Session 精确提取的方法 25 cases / 68 assertions，旧基线编译通过并在目标反事实中按预期失败；pending 提示和真实 metadata receipt gate 两侧各 22 阶段 / 49 条不变量及 5 条期望行为检查，旧代码仅两个 pending 提示为红，新代码全部通过。两侧所有阶段逐字段比较，仅这两处 next_goal 改变，controls、page key、query 和 completion 资格保持。实际原 request/reply/BINDING 经过生产 Receipt.verify；AX、未来 pair、IPC、时钟与其它阶段包络明确为模拟。Host 的 JSON-java Map-null 行为用一个公开的测试依赖适配点对齐 Android，未改生产或原件。原依赖差异与 test-null 重载的前两次宿主失败仍保留，不作为目标旧代码 red。没有将这些门槛与实际业务结果混算。

上一构建 6e0129 只改 bookingPending 的固定阶段预算，由 6 秒改为已使用的 16 秒档位，仍裁到原任务截止点；同 key 不延长、最多两次只读重观察、完整捕获、身份、租约、取消及所有动作/完成门槛不变。必要 host gate 为原 readiness 18 cases / 129 assertions，以及新 booking budget 9 cases / 45 assertions。精确旧 6 秒代码在同一 7.312 秒模拟序列中按预期失败，旧代码其余 8 cases / 39 assertions 通过。52/795 节点 DOM 来自实际保存证据；AX、IPC、时钟和重复成本序列为模拟，不能当作新阶段实机通过。最终合并输入逐字节匹配已执行的门槛源码，没有重复跑无关测试。

前一 cfacefe 组合实际执行的必要门槛是：首页 16 阶段、31 条断言及 3 条期望提示检查；失败结构诊断 8 个合成用例、31 条断言。两项均通过。首页组件此前还在旧/新两侧执行 query 40/187、result lifetime 31/99、composition 17/70，并保留精确首页旧代码 red；结构组件另有旧诊断 15/32。它们没有在组合时无理由重跑，也没有累计为业务成功数。

此前源码 8d 的必要组合主机门槛均通过并保留原构建身份：

| 门槛 | 实际执行范围 | 数量 |
|---|---|---:|
| 预派发恢复 | 实际 Session 方法及 Controller 控制流；平台/模型/IPC/时钟为 mock | 66 cases / 145 assertions |
| 完整 capture receipt verifier | 生产 verifier 的合成回执边界；当前组合未重放私有 callback | 20 cases / 21 assertions |
| Footer 只读观察范围 | 合成自然价格目的及完整 native 边界；不放宽完成/动作门槛 | 49 cases / 53 assertions |
| 固定预算页面就绪 | 生产读取循环与受控 native/IPC 模拟 | 18 cases / 129 assertions |

组件阶段还保留了精确旧代码的行为 red、1 份实际 unavailable callback 的不改原件重放、43 项购物观察与 28 项 quote 完成回归、19 阶段 controller/Notes 回归，以及旧 legacy purpose 必须拒绝的实测 DOM 重放。它们按各自源码和回执列出，没有重复累加成一个“全 App 通过”数字。47d 和 c662 阶段的 canonical 等价、7/8 轮播绑定、日历标签、Notes 正文就绪等原门槛也保留对应版本结果。

普通生成中 Stop、Orvena GPU 失败后的普通恢复和独立 35B 资格使用各自原构建，不在每次仅 Java 修订后无理由重跑；当前 APK 的 18 个 native library 与上一资格构建逐字节一致，Stop 原生检查点也保留。Stop 原 r2 false 与后续严格 r3 离线判定同时保留，见 [STOP-GPU-VALIDATION.json](STOP-GPU-VALIDATION.json)。

## 构建、安装与复现边界

当前应用冻结 manifest 包含 2047 个源码/测试成员，实际编译输入为 316。相对 ff0a 只有已审的 Domain 与 Session 两个生产文件改变，其余 314 个编译输入逐字节相同；18 个 native library 和二进制 AndroidManifest 也相同。APK 内实际 build identity SHA-256 是 `00148e3fd13e41f489865eb65c661fd26694d2713a6a26c319daaf51f8e46ae8`；应用源码 manifest SHA-256 是 `754f88b5bc60ed82557192314e74f8ed28526e031fc7f40d6f195350330d57d0`。使用原证书的 v3 签名，证书 SHA-256 `202d00f853589c753069189086e0c76cb308d11745c33e70200985e4de3129d5`。

安装成功并保留 session、preferences、模型配置和可访问性绑定，没有清空用户数据。最终配置恢复记录的 SHA-256 为 `b1fa9a0f9f23562b667217063ce491eeb5bfe489f3dd45044d1ae733e2056ef2`；它不改变第 27 案真实使用的 8B 配置。MainActivity 当前展示模型信息，没有模型 profile/backend/context/threads 的选择保存控件；受审的配置 CAS 不能表述成已经交付的普通 UI 模型切换。公开的源代码、合成测试与 sanitized receipts 可以复核；涉及原始网页/AX/笔记的可选重放只给 hash 与结论，原件不随仓库发布。任何后续 report-only commit 都不替代上述 APK 的实际源码提交身份。

## 研究与后续隔离路线

模型、V79 算力解释、GenieX/LiteRT/ExecuTorch 和大 MoE 研究见 [NPU-MODEL-RESEARCH.zh-CN.md](NPU-MODEL-RESEARCH.zh-CN.md)。该研究引用固定截至 5dfa 的 21 任务证据；当前快照统计以本报告的 27 任务为准，同 APK 两模型的机票结果及输入阶段差异分别保留。UI-Venus 只完成主机侧集成准备验证，未进行真机推理与工具派发。

保留主屏原生携程任务的后续候选是合法 managed profile 的明确安装身份隔离；当前尚未创建 profile，也没有实现 profile-aware 全链路或携程 singleTask 启动资格。具体 15 文件身份传播与清理范围见 [PROFILE-ISOLATION-PLAN.zh-CN.md](PROFILE-ISOLATION-PLAN.zh-CN.md)。这份设计不能作为已支持主屏携程和后台携程并行的证明。
