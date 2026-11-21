# HEPTA 本地桌面入口

这个独立 Android 入口包让桌面快捷方式、组件和设置页的“打开”按钮进入手机上已安装的 HEPTA 本地控制器。v2 将目标从旧的 owneropen 界面改为 org.trillionnium.hepta.local/.MainActivity；它不会发送任务指令或自动点击控制器的开始按钮。

## 组件与行为

- 应用包名仍为 org.trillionnium.hepta.entry，versionCode 为 2，versionName 为 2.0-local。
- 应用列表中的图标仍打开 EntrySetupActivity 设置页，保留添加快捷方式、添加桌面组件和打开控制器的按钮。
- 快捷方式 ID 仍为 hepta-workspace；快捷方式和组件的稳定目的地仍为 OpenHeptaActivity。
- 转发使用明确的本地 MainActivity 组件，并保留调用者实际的 displayId。
- 可用性判断检查同一个本地组件的 exported、enabled 与应用 enabled 状态；manifest 的 package visibility queries 与目标一致。
- 保留原 widget provider、快捷方式确认回调、启动 flags 和桌面公开 pin 流程。
- 该包没有 TileService，不修改系统快速设置磁贴列表。旧 owneropen 应用及其磁贴属于独立模块。

## 构建

需要 Android SDK 的 platforms/android-34/android.jar、build-tools/34.0.0 和 JDK 17。在本目录运行：

    python3 build_unsigned.py \
      --sdk-root "$ANDROID_SDK_ROOT" \
      --jdk "$JAVA_HOME" \
      --out ./out-entry-v2

输出目录必须尚不存在。脚本只在给定目录构建 unsigned APK，执行资源编译、Javac、D8、ZIP 对齐和 badging 检查，不签名、不安装，也不联系手机。

编译 SDK 沿用 v1 的 API 34，minSdkVersion 与 targetSdkVersion 均为 36。D8 对目标 API 超出该编译器已知范围的提示会保存在构建日志中；本模块使用的公开接口均可由 API 34 编译。

## 签名与部署

签名材料由部署方提供。升级已有入口包必须沿用已安装 org.trillionnium.hepta.entry 的原证书，才能保留现有快捷方式和组件身份。本目录不包含私钥、密码、签名脚本、签名制品或私人主机日志。

部署方应在安装后检查设置页的打开按钮、已存在的快捷方式或组件能进入本地控制器，并保留当前屏幕；同时确认仅打开界面不会创建或开始任务。此入口模块不承担控制器内部的模型推理、工具授权或后台任务调度。
