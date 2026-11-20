# Profile recents UID 解析修复

本候选只修改 `ProfileTaskPolicy.java` 的 recent-task 身份行解析。冻结应用源码没有修改，也没有执行手机命令、Android APK 构建或远端提交。

## 实际失败与官方格式

实际完整 recents dump 保留 22 条任务。其 `effectiveUid` 包含 `u0a481` 等平台格式以及十进制 `1000`。旧解析器只接受十进制，因此在尚未创建目标虚拟显示、尚未启动 profile App 时以 `PROFILE_RECENT_USER_UNKNOWN` 拒绝。

Android 16 QPR2 的 [Task.dump](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android16-qpr2-release/services/core/java/com/android/server/wm/Task.java?format=TEXT) 使用 [UserHandle.formatUid(PrintWriter,int)](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android16-qpr2-release/core/java/android/os/UserHandle.java?format=TEXT) 输出 effectiveUid。它与同一行的 mCallingUid 是不同身份，后者不能替代前者。数值边界取自同分支 [Process.java](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android16-qpr2-release/core/java/android/os/Process.java?format=TEXT)。

| 格式 | 按该 producer 解码 |
|---|---|
| 十进制 | 保留既有非负 int full UID 输入；拒绝符号、前导零、溢出 |
| uNaM | user=N，appId=10000+M，M 为 0–79999 |
| uNsM | user=N>0，appId=M，M 为 0–9999 |
| uNaiM | user=N，appId=90000+M，M 为 0–9000 |
| uNiM | user=N，appId=99000+M，M 为 1–999 |

官方 producer 在 appId 恰好 99000 时输出 ai9000，而不是 i0。本实现保留这个精确边界。full UID 使用 long 计算为 user×100000+appId，再验证 int 范围；仍必须与原 userId 字段满足 fullUid/100000==userId。字母格式的数字必须规范，未知类型、重复身份键、跨 user 矛盾和别名表示均拒绝。十进制完整 UID 的兼容输入不等于声称 formatUid 会对所有 UID 输出十进制。

## 未改变的条件

完整 dump 的原始任务结构、连续编号、任务详情和身份集合完全一致检查继续执行。显式 profile 身份、PM 安装信息、专属 profile 的 live/recents 空集要求、owned-task 清理条件以及个人 user 0 任务保护均未放宽。没有以 caller UID、默认 user 0 或 package appId 推断未知身份。

## 已执行的限定验证

- 旧生产源码与候选均编译成功，编译 stderr 为空。
- 原 profile coordinator：27 例、227 断言通过。
- UID 解析：14 组、69 断言通过，覆盖格式与边界、重复字段、未知格式、完整性及 user/UID 绑定。
- 同一份完整真实 dump：旧源码精确报 PROFILE_RECENT_USER_UNKNOWN，候选 22 行、26 断言通过，原件 SHA 未变。
- 真实设备只出现十进制和 a 格式；s/ai/i 是按已核官方 producer 的宿主边界验证，没有伪称为本机实测。

可移植 runner 为 `tests/run_host.py`，参数包括 `--source`（完整基线组件目录）、`--candidate-policy`、`--java-home` 和 `--output`。私有原件只通过可选 `--actual-recents` 明确传入；要重放旧红新绿时，`--source` 必须指向修复前基线。原始 dump 不包含在候选或公开 fixtures 内。

这证明了精确解析缺陷及其修复，没有证明 profile App 窗口、工具派发或业务任务完成。原失败及 cleanup_unknown 仍保留。
