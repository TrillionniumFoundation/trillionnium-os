# 未采用的 inventory 拓扑优化候选

本包交付三个独立纯函数候选、可重建 constructor、差分测试和原字节性能证据。当前 R10 冻结源、历史原件、原 reader hash 和旧运行结果都未被修改。包内测试通过不会授予 runtime admission、retirement、fixed19 credit 或生产资格。

## 已验证的结果

- 当前 `inventory_value`：801 次完整函数差分、1,754 次根拓扑对照，接受/拒绝、异常类型和文案、返回结构、输入不变全部一致。真实 R9 after 的完整函数在 Linux 上约 147.405 ms → 63.908 ms（7 轮无 profile）。
- source-parent `inventory_value`：独立绑定其原 source identity，同样通过 801 次完整函数和 1,754 次拓扑对照。
- R8 `verify_complete_scope`：真实保全 R8/R7 archive 重建的完整 scope 返回全等；6 个完整函数拒绝/优先级 case 结果一致；另有 291 个拓扑子图对照。Mac 上使用同一个未改 original inventory reader，3 轮无 profile 中位数 0.983765750 s → 0.254996375 s（3.85796×）。

两个机器、不同函数边界的结果不能合并估算 stage。全调用链 selector/采用策略及原 90 秒 stage 预算仍未通过；[覆盖与采用边界](reports/DERIVED-VALIDATOR-COVERAGE.md)列明具体未闭合调用点和受限 provenance 字段。

## 文件入口

- `CANDIDATE-MANIFEST.json`、`DERIVED-CANDIDATE-MANIFEST.json`：原源、新函数、派生整源、patch 的完整 bytes/SHA-256 与 claim ceiling。
- `candidate/inventory_value.py`、`candidate/derived/`：无运行入口的未采用函数片段及补丁。
- `tools/build_candidate.py`、`tools/build_derived_fragments.py`：固定原字节校验、唯一变更点和 whole-byte inverse；不改历史文件。
- `reports/differential-results.json`、`reports/derived-differential-results.json`：含真实 retained inventory 的离线差分原结果。
- `reports/benchmark-results.json`：Linux 当前完整函数及局部 predicate 的分列测量。
- `reports/scope-full-mac-results.json`：原 job 完整 stdout 7,790 B，SHA-256 `a2e88c6090c8706a818865eafab5ae88cd1ea1cbca821d12b4b26379c65d6990`。
- `reports/scope-full-mac-execution.json`：原 request/script/argv、job identity、authoritative terminal、两个 EOF 与源码/archive 前后 pins。
- [fixed19 当前状态](reports/FIXED19-STATUS.md)：确切 19 项、五项实机故障层、BUILD/health/回滚和日常/显示支持门槛。当前 19 项均 HOLD。
- [准入前 observer 设计](reports/OBSERVER-DESIGN.md)：未来新受审诊断通道的设计；没有补造旧终态。

## 可重复的 portable 检查

在本目录运行：

```sh
python3 tools/build_candidate.py
python3 tools/build_derived_fragments.py
HEPTA_TOPOLOGY_SYNTHETIC_ONLY=1 python3 tests/test_inventory_topology.py
HEPTA_TOPOLOGY_SYNTHETIC_ONLY=1 python3 tests/test_derived_topology.py
```

Synthetic-only 模式不读取私有 `.zlib` fixtures，显式跳过对应测试，分别得到 788 次完整函数与 1,754 次 roots 对照；派生 scope 子图有 285 个纯合成对照。结果写入 `*-synthetic-results.json`，不覆盖保存的真实 fixture 报告。CI 可先将候选目录复制到 TemporaryDirectory 后运行。`PORTABLE-DELIVERY-MANIFEST-v1.json` 固定第一批 35 个文件和全部 hash，排除私有 fixture archive。

本地完整 retained fixture 检查去掉该环境变量；对应 `.zlib` 原字节与来源 pin 在 `fixtures/MANIFEST.json`，不应把缺少私有 fixtures 的 CI 运行宣称为真实原件测试。

Mac 完整 scope 复核脚本为 `tests/scope_full_replay_readonly.py`。它只读取明确的固定 R7/R8 原件，并将结果写到 stdout；执行参数及原 job 已保全在 execution 原件。它不会调用手机或新任务，不写 Mac 原件，不用于运行原 stage。

## 采用要求

新派生代码要有自己的 source/module identity、明确的新 selector receipt 和正式采用审阅。不能借用旧 reader identity，也不能缓存旧 PASS 或放宽预算。R10 当前失败的原 nonce 仍已消耗；新候选只有在完整保全/采用/fresh-input/CAS/单次 reservation 完成后，才可能进入新的实际准入。旧请求不重放。
