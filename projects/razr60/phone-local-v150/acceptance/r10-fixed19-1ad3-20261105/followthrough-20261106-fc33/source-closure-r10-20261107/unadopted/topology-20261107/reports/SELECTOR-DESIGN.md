# 完整保全 reader 的离线派生 selector

## 本次交付与证据范围

本增量实现并实测了 `R9.verify_retained_transport_archive → R8.verify_retained_staged_archive → R7.verify_retained_preaccept_archive` 的完整离线组合。每个旧来源仍先按原 pin 完整读回；新的 validator 使用独立 module、独立 `__file__`、新源 hash 和 fresh globals。R8 scope 与 R7/R8/R9 三个实际 inventory 调用点均显式选择新派生函数。当前及 source-parent 的纯 `inventory_value` 也可独立选择，但没有接管完整 source-parent boundary reader。

`SELECTOR-CANDIDATE-MANIFEST.json` 列出所有旧来源、新派生源码与函数身份。`tools/build_selector_manifest.py` 可重建该 manifest；默认仅输出 stdout，`--output` 只能创建新文件。完整历史来源不改写，独立新代码不会被标记成旧 publisher 或旧 reader。

## 实际完整组合差分

只读 Mac job `1a1b872991c-12894-f78` 完整终态为 succeeded/exit0，stdout 31,632 B、stderr 0，两个 EOF，terminal publication、output complete、output durable 均为 true，无 timeout/cancel/automatic retry。原始 stdout SHA256 为 `7d3fffb4e5f71444e3889a15b69b29bc677f3d4641c60bd2189cc2620d5f2dd1`。源码、归档与 manifest 的完整字节及九字段元数据前后读回相同。

完整原/派生返回对象逐项全等，包括 49 roots / 3,991 entries 的完整 inventory、原失败语义、host/scope 结果和嵌套 retained bindings。五次外部原件读回的 descriptor 与顺序相同。七种完整拒绝路径同异常类型、文案和读回次序：分别破坏 R9 archive、R8 reader、R8 manifest、R8 archive、R7 archive；同时破坏 R9 archive 与 R8 reader 时第一原件 guard 先拒绝；入口 descriptor 不符时零读回拒绝。

原 `global_unknown_effect_count:null`、`native_terminal:null`、`remote_cleanup_proven:false`、`native_case_credit:0`、`new_nonce_authorized:false`、`retirement_accepted:false` 全部保留。这里的返回值是历史证明的数据投影；其中历史来源说明不代表本次执行仍使用旧 validator。新的执行代码身份由单独的 construction receipt 说明。

Mac / Python 3.9.6、三轮交替、无 profile/trace 的完整函数中位数：

| 测量边界 | 原实现 | 派生实现 | 比值 |
|---|---:|---:|---:|
| 整个 `verify_retained_transport_archive` wall time | 2.547043042 s | 1.560952625 s | 1.631723475× |
| 同一完整函数 CPU time | 2.545899 s | 1.560159 s | — |

固定留存原件预先读入 immutable bytes；每轮重新解压、检查全部字节与结构、构造嵌套模块并执行完整验证，没有使用上次 PASS 或返回对象作缓存。外部文件 I/O 和顶层 module 创建不计入此函数测量。该数字不能当作手机整段 stage 的耗时，也不能与其他机器、局部谓词或单独 scope 的倍率相乘。

仓库的 `reports/selector-full-safe-summary.json` 只保留来源 pins、终态、安全摘要和测量。完整 process request、stdout、原 readset、原源码导出包保留本机，按摘要的字节与 hash 可追溯。

## 可重复构造与身份绑定

`candidate/derived/reader_selector.py` 保持固定实现身份 `de7dc784654dec65f0e6d2d7fd81918caf9c3c634d152295c1fb7928cf04a5c2`。每个显式 replacement 都要求唯一原位置，并做 whole-byte inverse；完整子模块的新 hash 也由 portable 测试固定。

调用方使用 `candidate/derived/bound_selector_loader.py`：先独立校验实际 selector 源 pin，再要求声明的 `implementation_source` 与实际 compile 的 bytes 完全相同，之后才在 fresh module 中构造 selector。这个 wrapper 有自己的源身份，不使用循环 self-hash 字段。已测完整 Mac harness 同样从一份实际 bytes 编译 selector，并把同一份 bytes 传入 constructor；此后新增的绑定 wrapper 只在 portable 层补强调用方的 fail-closed 契约，不改变已测 retained verifier 函数。

portable 命令：

```sh
HEPTA_TOPOLOGY_SYNTHETIC_ONLY=1 python3 -B tests/test_reader_selector.py
python3 -B tools/build_selector_manifest.py
```

CI 可在 TemporaryDirectory 的候选副本运行；默认不写报告，`--report` 只接受尚不存在的新路径。synthetic 模式为 11 tests、1 个明确 private fixture skip、5 个完整 module constructors、36 个 source/namespace/identity 拒绝检查、30 个完整 inventory outcome 对照。启用本机保全 fixtures 后另有 4 个真实 49-root / 3,991-entry binding 对照，11 tests 全部通过。原 v1 的 35 个文件逐项保持原 hash。

## 尚未满足的生产采用边界

1. **完整 source-parent boundary reader 未派生。** 当前 `source_parent_reader()` 加载 `reference/source_parent_late_boundary_r4.py` 原件后校验旧 `__reviewed_source_sha256__`、旧 source overlay、旧 module globals、旧 combination/policy/adoption，并返回 `historical_reader_functions_changed:false`。其三个公开方法是 `boundary_from_original`、`closed_boundary_originals`、`require_failed_ancestor_tail`。若这些旧函数调用的新 inventory 实现改变了历史 reader 执行代码，就必须建立新的 implementation provenance；不能继续返回原 exact-reader 声明。纯 source-parent inventory 的成功不等于此完整 reader 已采用。

2. **生产 selector 和 policy 未接入。** 当前 late-boundary 的 `retained_failed_staged_originals()`、`retained_failed_transport_adapter()`、`effective_current_prior_inventory()`、`source_parent_reader()` 仍遵循冻结代码路径。新 derived R9/R8/R7 组合是可审阅候选，不能通过替换旧 module global、冒用旧 hash 或覆盖历史原件偷偷生效。新的采用 source、manifest、review、head/base checks、freeze 与原件保全必须明确绑定新实现。

3. **整条 `verify_retired`、实时门和预算未验证。** 本候选没有执行进程组/锁门、live inventory、stage、phone、CAS、reservation 或 fresh admission。历史 property/environment/non-native 边界家族的重复校验也未被本增量整体重构。没有 PASS cache、结果缓存、live observation 缓存或预算放宽。原 stage transport 90 秒与业务 turn 300 秒仍是各自原合同；lease 期限依创建/加载合同，不从 stage 剩余预算上界推导。

4. **当前案例与发布资格不变。** 当前 fixed19 19 项均仍无当前组合 credit；NEG01 失败须按同次原件结算后才能推进 NEG02。BUILD、安装、READY、独立新 nonce health、真实业务、回滚、日常/独立运行与显示支持范围仍需各自真实证据。本离线 PASS 不授予任何 runtime admission。

本增量为可重复、身份明确的未采用候选，下一步可以做独立源码 review 与正式采用设计；不能据此重放旧 stage 或直接发新 nonce。
