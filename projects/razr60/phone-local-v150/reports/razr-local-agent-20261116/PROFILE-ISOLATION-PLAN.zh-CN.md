# 在保留主屏携程任务时运行独立后台携程：最小实施清单

日期：2026-11-16。此文件是只读源码与官方 Android 16 契约分析，不是 profile 或携程实机资格报告。未创建用户/profile，未执行 phone I/O，未修改当前构建。源基线为 5dfa APK / 8d277617ae0263631d2bcdd30d5022e3c6cf7897。

## 结论

合法 managed profile 是可继续验证的身份隔离路线。普通完整 secondary user 在本机 visible-background-users=false 的配置下不是已可用替代。现有 DisplayManager 虚拟显示可以继续作为候选显示机制；没有必要先迁移到 VDM。

但这不是改一个 user 参数即可完成的工作。当前 Hepta 在安装身份、启动、任务检查和完成证据中依赖 user 0。携程 launcher 的 singleTask 还会被独立的启动模式资格拒绝。只有同时补齐“哪个 profile 的哪个安装实例、哪个新建 task、哪个真实窗口、哪一份清理证据”，才能让主屏 user 0 的同包任务保持原样。

最低改动的候选架构是：Hepta 控制器、本地模型和既有模型文件继续留在 user 0；后台任务明确选择一个正常配置的 managed profile 中的携程实例；现有已获授权的 broker 在同一不可变目标合同下查询并启动该 profile。没有理由为此复制整套模型到另一个 profile。此架构尚未实现。

## Android 16 的精确显示边界

已从官方 Gitiles 读取固定 refs/heads/android16-qpr2-release 源，对应一手源码哈希与官方 URL 见[来源清单](PROFILE-ISOLATION-SOURCES.json)；原始文件不随本报告发布。AOSP 源码不是 Motorola 固件逐字一致的证明。

1. UserVisibilityMediator 760–776：当前用户或其已被框架记录为可见的 profile，在默认显示上可见；当 visible-background-users 功能未开启时，也在 secondary display 的用户可见性检查中返回 true。1167–1178 的判定依赖 mStartedVisibleProfileGroupIds，不等于任意“进程仍在运行”的用户都合格。
2. 同文件 399–405、490–501：不允许把 profile 当独立完整用户直接 start/assign 到副屏。它应先作为当前父用户的 profile 正常启动。此限制与“将已经可见的 profile 的 Activity 放到父用户使用的副屏”是两个不同问题。
3. 普通非当前完整用户，在 779–784 且 visible-background-users=false 时不可见。本机已保存的两项 effective=false / real=false 查询，排除了把普通第二用户当作现成并行 UI 路线。
4. ActivityTaskSupervisor 434–449、1294–1389 仍检查多显示支持、调用者权限、公开/私有显示与用户可见性。用户可见性通过不等于所有 App 自动有副屏启动权。
5. 若另外改走 VDM，GenericWindowPolicyController 308–316 还要求适合远端显示的 Activity 标记和被允许的 profile；VirtualDeviceImpl 1470–1491 按 DPC nearby-app-streaming policy 形成 allowed users。VDM 不是自动克隆器，也不免除当前权限或 profile 政策。

因此不能从“普通 secondary-user 可见性 false”推出工作资料必然不可用，也不能从上述 AOSP 分支推出本机 managed-profile + A11y + 携程启动已经通过。后者仍缺合法 profile、用户同意、账号登录和实机资格。

官方接口也支持显式 profile：LauncherApps.resolveActivity / getApplicationInfo / startMainActivity 接受 UserHandle；但其能力、导出要求和 display 权限应按真实调用者验证，不能作为任意跨 profile 服务或任意第三方组件启动权。

## 必须修改的实际路径

下表路径相对于：
projects/razr60/phone-local-v150/android-local/lfm3-controller/src/org/trillionnium/hepta/

| 路径与位置 | 当前实际契约 | 最小必要变化 |
|---|---|---|
| local/BackgroundUiPreferences.java 29–50、82–108、125–149；local/BackgroundTaskTarget.java 21–49、77–85 | 已保存 UID/signers，但 map、初始选择、范围和 targetSha 以 package 字符串为核心；installed() 用当前 Context 的 PackageManager。 | UI/持久选择标识包含 userId、不可复用的 userSerial、parent/profile type、完整 UID、package、signers/安装版本。普通/工作同名 App 必须可区分。目标必须来自显式选择，模型或网页不能改 profile。 |
| local/QualificationScopeConfig.java 200–205、223–230；local/NativeAppEvidence.java 25–44 | native 安装捕获只查当前 Context，且要求完整 UID 在 10000–89999；会拒绝真实 profile UID。 | 通过合法 profile-aware 查询捕获和重核真正安装状态、完整 UID、APK 集/签名及启用状态。普通应用类型可校验 appId，但 UID 必须同时精确属于选定 user/profile；不得仅算术拼出 UID 或把阈值删掉。 |
| local/BackgroundSession.java 45–110、170–195、222–225、562–567；background/BrokerProtocol.java 73–116、120–173 | Selection 和 broker 配置没有目标 user；ownerUid 10000–89999；launch 请求仅带 package。持久 journal 验证控制器自身 UID。 | 区分 owner/controller identity 与 target profile identity。保留当前 user 0 控制器时无需放宽 owner peer-UID gate；新增目标 profile 合同及其 digest 到配置、每个请求/响应和 journal，版本化解析并拒绝旧/缺字段 profile 请求。 |
| background/BackgroundDisplayBroker.java 139、183–195、306–317、369–371、395、546–560 | shell Context 的 PM 解析；startActivityAsUser 最后参数写死 0；Back 注入的目标 UID 也来自 user 0 PM。 | 同一个显式 target UserHandle 用于解析、启用/导出/安装复核、启动和 Back 的完整 UID 绑定。启动前再核 userSerial、profile running/unlocked/非 quiet 与策略；失败不得退到 user 0。 |
| background/BackgroundDisplayBroker.java 604–674、541–542 | TaskRow 只有 display、visible、top、packages；一个 root 的子任务包集合被合并；APP_ALREADY_ON_MAIN_DISPLAY 只按 package。 | 保留每个任务/叶子的 userId、完整 UID、taskId/token、组件与 display，不以 root 的单一 user 代表全部子任务。相同 user/profile 的主屏旧任务仍拒绝；另一个 user 0 的同包 task 只能在已证明目标 profile 隔离时排除冲突，并持续检查它未搬移。不能直接删除此 guard。 |
| background/BackgroundOwnedTaskPolicy.java 27–36、78–92；BackgroundTaskOrganizer.java 76–88；BackgroundOwnedSingleTask.java 72–77、284–295 | Activity 拒绝 UID >=100000；标准路线仅 launchMode=0/documentMode=0。Xiaomi 特例专用，其容器/叶子又固定 t.user==0。 | 必须单独资格化 profile 中携程的启动与任务所有权。已观察的 Boot 是 singleTask=2，现策略即使没有同包主屏冲突仍拒绝。不能把 Xiaomi 特例泛化为携程许可；导出的 standard 入口也需验证完整正常跳转和 owned-task 清理。 |
| local/HeptaAccessibilityService.java 392–403、1220–1228、1478–1499、2141–2174；local/PhoneObservation.java 169–181 | 已严格绑定 generation/display/window/package，但观察对象未携带目标 user/full UID。getWindowsOnAllDisplays 后选指定屏的 application root。 | 增加由可信框架/已认证 broker 读回的 window→task→user/UID 关联，并随观察、派发前复核传播。不能从节点 package 文本推断 profile。新字段需进入 frame/digest 与 native permit 的相等检查。共享父用户 A11y 是候选，但仍须本机验证权限和 DPC 限制。 |
| local/NativeAppObservation.java 17–48；local/NativeAppEvidence.java 85–132；local/NativeAppSession.java 55–90、327–338；local/LocalTaskController.java 406–414 | Installed 与 frame 已绑任务/目标/安装/显示，但 frame 本身没有 profile；验证安装的闭包继续查普通 Context。 | Installed、frame、ActionGuard、结果/最终完成证据都必须引用同一个 profile identity。允许同包跨 user 并行后，不能只凭相同 APK hash、package、window 来等同安装实例。现携程版本/APK资格和业务结果守卫保留。 |
| local/BackgroundSession.java 170–176、428–458、532–568；background/BackgroundDisplayBroker.java 711–744；BackgroundOwnedSingleTask.java 的 owned token / user 检查 | journal 的 owned_task_retirement_required 目前针对 Xiaomi；普通清理主要证明本次显示消失，owned 分支另证 task 消失。 | profile 携程需自己的 owned-new-task 身份/退出与 recents 证据。清理仅作用于本次 userSerial/full UID/task token/lease；不得 force-stop 同包全局实例、删个人任务或删 profile。重启恢复/取消也重核 userSerial，未知身份保留 CLEANUP_UNKNOWN。 |

准确的启动策略类名是 BackgroundOwnedTaskPolicy；先前简表中提到的 BackgroundLaunchPolicy 不是该源码树中的文件。

## 系统和用户前提

- 本机已有 managed_users / activities_on_secondary_displays feature，当前已保存用户列表只有 user 0。尚无 managed profile、DPC 或 Hepta 跨 profile 实测资格。
- 正常 provisioning 需要合法 DPC / profile owner 流程与用户可见的系统同意。应从实际 DPC 调用 isProvisioningAllowed(ACTION_PROVISION_MANAGED_PROFILE) 判断资格，不能只凭 feature。现有管理策略、添加 profile 限制或配置状态仍需只读核对。
- Profile 的数据与账号独立。个人携程登录、cookie、支付凭据不会自动继承；需在工作资料中的携程正常登录。不能拷贝个人 App 私有数据或凭据来伪造连续登录。
- 每次任务要求 profile 正常运行、解锁且非 quiet；父用户不变。isUserUnlocked(UserHandle) 与 isQuietModeEnabled(UserHandle) 是实际可查询状态。不能自动解除 quiet、弹出工作资料解锁页或回退主屏来维持执行；这些都可能影响主屏。
- Android 官方说明 A11y 和 IME 等服务可与父用户共享；DPC 可限制可用 A11y 服务和截屏。应验证现有 Hepta 服务是否能读取目标副屏并严格认证 profile 窗口；不能假设安装另一份 Hepta 就会得到独立 A11y 环境。
- 现有 trusted / own-focus / steal-top-focus-disabled、IME hide、禁止 secure/always-unlocked 等显示守卫保持。创建 profile 的系统交互与首次登录属于单独配置过程，当前尚未执行，不应算“后台 App 测试已完成”。

## 下一项可执行工程步骤

建议下一步只在独立 host 分支做 TargetProfileIdentity 的不可变合同及传播测试，暂不创建 profile、不接当前生产入口：

1. 一个已明确选择的 managed profile 作为唯一新范围：ownerUid 保持 user 0；target=(userId,userSerial,parentId,profileType,fullUid,package,component,APK/signers)。
2. 先打通选择→broker 请求/响应→按任务粒度的冲突判定→观察/permit→journal/cleanup 的纯数据合同。针对同包不同 user、同 user 旧主屏 task、混合 root 的不同 user 子任务、profile 删除重建同 userId、quiet/locked、PM 回退 user 0、UID 不匹配和 foreign cleanup 做少量拒绝反例。
3. 在此合同及启动模式资格设计被审查后，再安排正常 profile 配置与单独真实显示资格。第一项真实验收应只验证目标 profile 启动/观察/取消/owned-task 清理及原 user 0 task/display/focus 不变；不得同时把查票成功作为显示资格的替代证据。
4. 携程真实查票/其他业务验收另计。Profile 隔离只解决实例空间，不补足尚未验证的页面解析、模型决策或结果证明。

当前可以作出的工程判断：managed profile 路线在 AOSP Android 16 上有可解释的副屏可见性基础，且能提供不同 user 的 App 数据/任务身份；当前 Hepta 尚缺上述完整身份传播和携程启动资格，因此不能交付为“已经支持主屏原携程与后台携程同时独立运行”。

## 官方来源

- Work profile 数据/账号/共享服务与跨 profile intent：https://source.android.com/docs/devices/admin/managed-profiles （已读网页39–70）。
- 普通 App 的 profile 兼容：https://developer.android.com/work/managed-profiles （已读51–60、138–167）。
- 多显示启动权限：https://source.android.com/docs/core/display/multi_display/activity-launch （已读103–117）。
- UserManager serial、running/unlocked、quiet：https://developer.android.com/reference/android/os/UserManager （已读3915–3921、4172–4185、4223–4264、4325–4335）。
- DPC provisioning / A11y / streaming：https://developer.android.com/reference/android/app/admin/DevicePolicyManager （isProvisioningAllowed、setPermittedAccessibilityServices、setNearbyAppStreamingPolicy）。
- 明确 profile 的 launcher 查询/启动：https://developer.android.com/reference/android/content/pm/LauncherApps （resolveActivity、getApplicationInfo、startMainActivity）。
- 固定 Android 16 AOSP 基址：https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android16-qpr2-release/
  - services/core/java/com/android/server/pm/UserVisibilityMediator.java
  - services/core/java/com/android/server/wm/ActivityTaskSupervisor.java
  - services/core/java/com/android/server/wm/ActivityStarter.java
  - services/companion/java/com/android/server/companion/virtual/GenericWindowPolicyController.java
  - services/companion/java/com/android/server/companion/virtual/VirtualDeviceImpl.java

本轮 Gitiles HTML 在网页工具中不可打开，官方 ?format=TEXT 原始读取成功；原始文件留存于私有审计归档；完整 SHA、官方 URL 与复核范围见配套来源清单。未声称未成功打开的网页 ref 可用于在线引用。

## 既有真机事实原件

B 表示既有私有设备证据归档；以下只列相对案例名和原件 SHA，不发布原件。

- B/ctrip-activityinfo-inspect-81c5-02/RESULT.json，SHA 568a572128fe1e3d01809a9bb68798cfcd277efe87fe627577c1b3d10b7bd869：Boot exported singleTask；FlightInquire exported standard；Home 非 exported singleTask；Splash exported standard；同 affinity，unresizeable。
- B/ctrip-background-inspect-81c5-01/activities.txt，SHA 62cb2e367f6869b89472a30d8ce913d9a5b8eb4af781775c412952cb7247ba74：主屏携程 task 1184 STOPPED、非 finishing；本轮没有关闭或搬移。
- B/background-capabilities-81c5-02/RESULT.json，SHA f045ebe3e618e496a5c0d3f5621b54cc79996e1875f145a8e271fa1a9a8c4cf1：只读查询，用户0；两项 visible-background effective/real 为 false。此前保存的 VDM service/config 存在不构成启动权限或克隆能力。
