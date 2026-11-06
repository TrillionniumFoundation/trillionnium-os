# R6 第四阶段源码兼容修复

实际第四阶段 job `1a1b2a31057-fc05-7f16` 在写出 case-controller 源目录前退出 1。前三阶段已完成的 release、controllers、E2E 源码不变，旧 job、输入绑定目录与原候选源码全部保留。

## 确定原因与一行修复

`controllers_stage()` 生成 binder 时，嵌套 `SOURCES` 内两个 descriptor 的插入顺序是 `path, bytes, sha256`。`controller_context()` 从 `sort_keys` JSON 加载实际 DERIVATION 后得到 `bytes, path, sha256`，随后 `repr` 产生不同的源码字节。语义相等不能满足原有全字节反演门，因此拒绝正确触发。

继任源码只把该处两项变为 `descriptor(report['helper'])` 和 `descriptor(report['stage'])`。这与原 producer 使用的 descriptor 顺序一致。原完整字节比较保持，其他验证保持，`FROZEN_INPUTS` 仍为 `None`。

实际 9,462 字节 binder 的原件由独立 Mac 完整读取取得。必要的五项控制执行了原函数中的真实 AST assignment：旧调用重现 mismatch，修复后的调用重建全部 9,462 字节，精确等于已实际发布 binder。完整 source inverse 与未绑定零 callback 拒绝均成立。本次五项控制不与旧候选的十五项相加，也没有重新派生或执行前三阶段。

## 源码

- 继任 rebinder：45,121 字节／`27db832a529f59d46e25b02eaecf2b9ac5c8ac9675c5bb91387a6fed4a8ee9b9`。
- 继任 input binder：6,411 字节／`06a6ba81796c1dff54b4224c4a549061deed27deb5a26cb56ede118b5a420d31`；只更换完整 SOURCE descriptor。
- 原 rebinder：45,097 字节／`3d6cf7e6c7129f7433762de03bbe612c4181e5b63835e692c02604415bf5cef4`，保持原件。
- 五项控制：`RESULT.json`，1,411 字节／`31de849e6682fc431af3273ed9fed7d1b81592cf9f0ee0f834c10a6bc9e07995`。

独立只读 job `1a1b2a7b164-fc05-7f2b` 完整结束，5,528 字节 stdout、0 stderr、双 EOF。它已观察原 case-controller 输出目录、新 successor source package 目录、新 input-binding 目录均为 ENOENT。各 publisher 仍使用 create-only 检查，不能从这次观察推断未来不会出现竞态。

## 唯一后继路径

1. Root 执行本目录 `publication/PUBLISH-SUCCESSOR-REQUEST.UNEXECUTED.json` 一次，只发布继任源包。
2. 完整读回后，执行 `publication/BIND-CASE-INPUT-REQUEST.UNEXECUTED.json` 一次。它读取原实际 921 字节 case source 输入，使用新的 `followthrough-fc33-r6-case-controller-input-binding-fix01` 目录，输出新的 source-only request。
3. Root 读取这份新的 `requests/PUBLISH-SOURCES.json` 后执行一次。只有第四阶段的 case-controller 源会被发布，目标仍是已经观察未创建的 `followthrough-fc33-e2e-execution-controller-r6-01`。

旧失败请求不能重发，旧绑定目录不能覆盖。所有请求都只处理 host source；没有手机、BUILD、READY、materializer、nonce 或业务 dispatch。
