# Hepta 后台计算器最小真机验收驱动 r2（准备状态）

本目录只准备了驱动、验收规则与进程身份解析回归。**未执行验收驱动入口、未联系手机、未运行手机推理、未产生任何真机通过结果。** `test_process_identity.py` 仅从生产文件 AST 提取两个纯解析函数及所需常量，以合成输入测试；不导入或运行 driver main、host helper、ADB。结果在 `PREPARATION.json`，不能称为设备测试通过。上一版文件保留在上一级目录，r2 的四个文件在本目录内独立冻结。

## 本轮实际前置阻断

2026-11-10 最新已提供的 Root 现场读取时间为 14:57:59 UTC：原 owner 仍持锁；直接读取的 `files/qualification-scope.json` 仍为 enabled 的 `c426-nano-v34-lifecycle-r3`；正式 Hepta 无障碍此时已 enabled。早先“正式服务停用”的状态已被后续恢复覆盖，不应继续当作当前事实。独立只读查到的旧流程回执显示，14:45:57.758 的显式恢复已完成并读回正式 service bound；14:47:42.196 的 scope-remove 回执记录执行成功、scope 不存在，其源码要求删除后和 normal MAIN 后两次缺失读回。

14:47 与 14:57 的 scope 状态差异尚未定位。不能猜成缓存、ADB `-H` 差异或某个 writer 重建，也不能凭旧删除回执忽略较新的“存在”观察。随后 host 工具报告 `tunnel_client_not_connected` / `Tunnel-client did not poll`，新增 remote 读取已停止；这是连接阻断，不是权限拒绝。相关已读证据保留在上一级 `audit-evidence/`。候选源码发布或 host 构建准备不表示已安装 APK 或通过本测试。

驱动首先调用已核验 `v35_identity.py` 的 `operation_lock()`。它只读打开现存 `/home/alex/.local/state/hepta/razr-operation.lock`，使用 `LOCK_EX | LOCK_NB`，检查持有 fd 与 pathname 身份，并在每条 ADB 命令前再次检查。此处“共享”指所有合作脚本共用同一锁文件，**不是** `LOCK_SH` 读者锁。锁忙时没有任何手机命令；不会等待、抢占、删除、替换或重建锁。

拿到合法窗口后，驱动仍会拒绝现存 scope 文件、未释放后台 journal、活动任务、未知旧清理状态、中断 latch，以及未正常启用或无法从系统 Bound services 读回的正式 Hepta 无障碍服务。它不迁移配置，不修改无障碍设置，不调用 Magisk 授权，不以删除 scope 来扩大测试范围。

## 为什么使用现有可见按钮

已读实际 adapter 源码：`MainActivity.acceptScopePrefill()` 对 `auto_task` 或 expected scope 把 `backgroundMode` 设为 false；`beginTask()` 的后台分支仅接受 `source="user_button"`。scope 文件存在也会拒绝后台分支。`LocalTaskSession` 没有另一个可用的后台私有 nonce 自动入口。

因此本测试不能复用旧 `auto_task/test_nonce` 后声称后台通过，也不新增 exported receiver。测试准备时，在已安装候选 APK 的正常主界面做以下选择：

1. 输入精确指令：`打开计算器，计算 23 乘以 19，确认屏幕显示计算结果后结束任务。`
2. 点击“选择后台应用范围”，仅选择本次已核验的计算器包，点击“使用所选应用”。
3. 将“后台起始应用”设为该计算器，勾选“在后台空间操作”。
4. 保持 Hepta 主界面可见。计算器在任何其它 display 上都不能已有 task；如有，由现有正常 UI 关闭后再准备新测试。
5. 确认 Hepta 已具有正常的既有 su 授权。`--existing-su-authorized` 只是操作员对现状的声明，不是授权实现，也不证明授权有效。若开始时弹出授权界面，则本轮主屏保持条件会失败；不要把点击授权后的运行合并进这次基线。
6. 确认正式 Hepta 无障碍服务已绑定。优先用普通截图观察准备 UI。若另一个已授权准备流程必须使用一次 UI dump，退出后要重新核对正式服务已绑定，再进入本驱动。**推理期间禁止 `uiautomator dump` 或 UiAutomation**，避免抑制/替换正在工作的无障碍服务。

默认驱动进入 `ARMED` 后，由现有可见“开始任务”按钮发起一次任务。若由现有 UI 操作者以 ADB 点击该按钮，可以选择 `--start-tap X Y --prepared-screen-sha256 SHA`：坐标必须来自刚刚实际查看的完整主屏截图，驱动会重新截图并要求字节 SHA 完全相同，才发送一次 `input -d 0 tap X Y`。不要猜坐标；新增后台选择区域使旧版按钮位置失效。状态栏、键盘或页面变化导致 SHA 不同，会直接拒绝，不自动改坐标或重试。

默认模式下，驱动运行期间其他 ADB 操作者不得绕过同一锁；屏幕上由机主直接点击按钮不涉及另一个主机 ADB 流程。若全程由主机远程操作，应使用上面的单次截图绑定点击模式，让触发与只读观察同处一个锁持有期。

## 调用模板（尚未执行）

下列尖括号都必须替换为现场已经读回的值；不能直接复制为真实运行命令。

```sh
python3 /ABS/background-phone-tests/r2/background_calculator_acceptance.py \
  --identity-helper /ABS/remote-audit/v35_identity.py \
  --source-tools /ABS/reviewed-source/tools \
  --adb /ABS/adb \
  --adb-host <existing-adb-host> \
  --adb-port <existing-adb-port> \
  --serial <exact-razr-serial> \
  --apk-sha256 <exact-installed-candidate-apk-sha256> \
  --expected-uid <ordinary-hepta-uid> \
  --runtime-config /ABS/expected-runtime-config.json \
  --target-package <exact-calculator-package> \
  --result-view-id <exact-calculator-package>:id/<observed-result-id> \
  --existing-su-authorized \
  --out /ABS/new-background-calculator-evidence
```

可选单次可见开始按钮点击还需加上：

```sh
  --start-tap <fresh-start-button-x> <fresh-start-button-y> \
  --prepared-screen-sha256 <sha256-of-the-visually-reviewed-current-screencap>
```

`result-view-id` 必须来自真实计算器观察，不能从模型声称的结果推测；本目录不捏造 Motorola 计算器控件 ID。运行前应记录精确 ID，或者先保留观察证据、补完独立控件识别后再安排一轮正式测试。

脚本不安装 APK、不下载或配置模型，也不发送包含正确答案的模型提示。`437` 只作为主机端结果比较值，指令只含 `23` 与 `19`。实际 UI 动作须由手机本地模型产生。

## 身份和本地推理证据

驱动在任务前后比较安装 APK 的真实字节 SHA 与 ordinary UID；Hepta 必须是单一 base APK，精确匹配命令行提供的候选 SHA。计算器本身的 APK 集合和 UID 也前后比较并纳入报告。配置文件要求与已准备的本地 `runtime-config.json` 完全同字节。`compute` 必须为 `npu` 或 `gpu`，模型配置必须落在已发布 `model_profiles.py` 的实际模型白名单中。

为避免另写一个较弱的“推理通过”判据，驱动复用 SHA 固定的 `phone_acceptance.collect_evidence()` 与 `warm_receipts.collection_verified()`，收集并核验每个模型 request、对应 native output、prompt/grammar/output SHA、实际加速器选型和 offload 日志，以及同一 task worker generation 的退出/清理回执。还从独立系统 `ps` 观察中把 native worker PID 绑定到 Hepta ordinary UID，单独核对 broker PID 是 root 或 shell。

### r2 修复的进程筛选误判

r1 仅按 ARGS 包含 broker 类名及 generation 筛选，可能把 `su -c '...app_process ...Broker --generation ...'` 启动包装进程误当成 broker。若 su 客户端保留 ordinary UID，真实 root broker 运行正常也会误判失败。

r2 只接受精确 `/system/bin/app_process[32|64]` 或相应短程序名，加固定 `/` 和完整 broker 类名；也接受完整类名作为 argv0 且保留完整会话参数的形式。必须是六个不重复 flag-value 对，generation、socket、owner UID、单一 allowed package、540000 ms TTL 都精确匹配；不识别的形式拒绝。`su`、`sh`、`env` 等包装程序不因内嵌命令文本而成为 broker。重复采样必须指向同一个实际匹配 PID，且其 UID 为 0 或 2000。仅有包装进程时不能通过。

这些是系统 `ps` 的 UID/PID 与 argv token 身份，不是 `/proc/PID/exe` 的可执行字节证明。厂商可能截断或改写 argv；缺少精确 generation 时判为未验证，不回退到 substring 搜索。

纯解析 fixtures 包含 root broker 格式、shell UID broker、完整 Java argv0、普通 UID su 包装加真实 broker、shell 包装、仅包装、假类名、假 generation 子串、重复 flag、缺失 flag、错误 socket/owner、普通 UID 的真实 app_process，以及多 PID 冲突。它们是明确标记的合成解析样本，不是伪造的手机观察，也不提供任何模型或手机成功证据。

驱动固定以下 helper 字节；缺文件或 hash 不同就拒绝，不从 Python 缓存或任意 sys.path 位置加载替代品：

| Helper | SHA-256 |
|---|---|
| `v35_identity.py` | `a4a751cf03956783e551f54b16dd37769f00d5b7cd2a0225b667becbc6e6d003` |
| `phone_acceptance.py` | `baa43b0379c25a7f7f8e03afc41ac1e92b4e1483462726d7eadc9d5a40f60f7a` |
| `warm_receipts.py` | `d5ab468b1b3155195d24b771376581dd441fd59a20b71feda98af4074fcaa3d5` |
| `model_profiles.py` | `9ba9403bdf64c2d765b31ffbbed2e95ac846f50df6ecb4e21efd4ebc926a397a` |

当前引用的源文件分别来自本任务 `remote-audit/` 和完整只读 `controller/tools/`。已再次实际读取本地 `remote-audit/v35_identity.py`，确认为 34830 bytes / `a4a751cf…`，与 PINS 一致。将来上传这些精确字节到本任务自己的运行目录，并将该路径传给 `--identity-helper`；不要复用身份未核对的旧远端副本，也不为 `b83ee871…` 等未读版本放宽 PINS。

## 通过条件与原始证据

结果必须同时满足下表；任何条件缺失，`qualified` 都为 false。结果不以 `model_reported_success` 单独判定。

| 检查项 | 所需证据 |
|---|---|
| 正常普通 APK 入口 | 新 task ID，`origin=user_button`，无 debug nonce；OWNER 的指令与 SHA 精确匹配 |
| 固定后台范围 | `background_request` 只有真实计算器包；无 HOME 或主屏 fallback；generation、display ID、task ID、owner SHA 一致 |
| 起始应用来源 | `background-bootstrap.json` 必须写 `bootstrap_source=owner_selected_initial_app`、`bootstrap_model_issued=false`；它不计为模型发出的 open |
| 真模型工具动作 | 每个 `step-NN-action.json` 有 `model_issued=true`，关联真实模型 run/raw output，并绑定同 generation 的后台 before observation；至少一个被接受并派发的 effect |
| 目标结果 | 最终真实计算器窗口的精确 result view ID 文本为 `437`；在某个模型发出的 effect 前后，该结果由非 `437` 变为 `437`，防止沿用旧画面；最终截图字节 SHA 与 observation 一致 |
| 本地 NPU/GPU | 所有模型 request / worker / runtime / accelerator 证据通过既有严格 verifier，普通 UID native PID 被系统观察到 |
| 显示与 task | 系统 `cmd display get-displays` 读到同名 `hepta-bg-<generation>`；目标 task 仅在该 ID；实际 flags 包含 TRUSTED、OWN_FOCUS、STEAL_TOP_FOCUS_DISABLED，不含 SECURE/ALWAYS_UNLOCKED；broker 回读 720×1280、240 dpi、IME hide |
| 主屏 | display 0 `mCurrentFocus` 与基线一致，InputDispatcher 的 FocusedDisplayId 始终为 0；记录采样数、最大采样间隔和单次采样时间 |
| 清理 | 同 generation 的 broker `ok=true,state=RELEASED`；app cleanup known；broker process exit 已观察且 exit code 0；新 journal 已删除；连续两次系统完整观察中既无该 display ID，也无该 name，且该 display 的 task 容器也不存在 |
| 完整结束 | task 不再 running/pending/blocked，模型 worker 完成已核验清理，controller status 是 model_reported_done，且前述独立目标验证也成立 |

所有 ADB 原始 stdout、stderr、argv、时间和返回码在 `commands/`；结构化系统样本在 `system/`；task、截图和 model run 证据在 `evidence/`；顶层 `RESULT.json` 汇总。单个私有文件在手机侧读取前受 16 MiB 上限与逐级非 symlink 检查。输出目录必须是全新的绝对路径。

主屏结论严格限于采样点：`dumpsys` 命令之间是顺序读，不是系统原子快照。默认 1 秒间隔再加命令耗时，不能证明两次采样之间从未发生焦点瞬变；报告保留实际间隔，不能移用历史 Probe 的 0.187 秒采样数据。

本轮使用机主选择的初始计算器作为 bootstrap。即使通过，也只证明这条已选应用的本地模型后台执行链；`model_issued_app_discovery_qualified=false`，不能称为模型自主发现和打开任意应用，也不外推购物、机票或备忘录全量兼容。

## 超时与失败

Controller 任务上限 480 秒、客户端 broker TTL 540 秒；驱动默认观察至任务识别后 560 秒。TTL 与 deadline 的存在不能替代释放读回。ADB 断开、调用超时、无法解析系统格式、model/action 绑定错误，都会使本轮不通过。

本驱动不猜“停止”坐标，不 force-stop，不杀手机 PID，不补发或重试任务，不直接作为 shell 客户端连 broker。活动任务超时或观察中断时写 `cleanup_status=UNKNOWN` / 需要检查正常可见“停止”按钮。随后由现有机主 UI 停止或清理，并另保存系统释放证据；不能把主机 adb 子进程结束或 broker 进程消失当成 display 已释放。

Android 厂商系统的 dump 格式仍需现场确认。解析不到 display 0、唯一 focus、明确 display/task 关系时保留 raw，判为未通过；禁止把不识别的文本当成“没有虚拟屏幕”。

## 此测试之后的最小扩展验收（本目录未执行）

完成上面的单条闭环后，再逐项单独记录：运行中按现有“停止”按钮；锁屏中止与解锁后不自动续跑；主屏已有目标 app 时 launch 拒绝且不迁移；IPC 丢失/应用中断后 journal 保留并通过正常“清理上一次后台空间”核验；TTL 到期释放；第二个会话被拒绝。每项都要使用同 APK ordinary UID 客户端并重新绑定 exact APK/config/generation，不能用 shell 直接调用 broker 代替客户端测试。

这些属于真实失败路径验收，不能把 pure-Java broker protocol 测试、旧 shell Probe、本驱动 AST 语法检查或 r2 合成进程解析回归加总为手机端测试通过。

## Android 公开源码参考

系统文本观察使用 AOSP 实际输出约定：

- [DisplayManagerShellCommand](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/services/core/java/com/android/server/display/DisplayManagerShellCommand.java)：`get-displays` 枚举真实 Display 对象。
- [Android 16 DisplayContent](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android16-release/services/core/java/com/android/server/wm/DisplayContent.java)：每个 display 的 `mDisplayId`、`mCurrentFocus` dump。
- [AccessibilityUserState](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/services/accessibility/java/com/android/server/accessibility/AccessibilityUserState.java)：Bound services 与 Enabled services 分开输出；启用配置本身不等于服务已经绑定。

这些源码说明解析设计，不替代 razr 厂商构建上的实际验证。
