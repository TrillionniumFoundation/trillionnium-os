# 990c runtime 的独立源码绑定候选

**当前状态：HOLD。没有运行 Mac 发布入口，没有调用 source-chain 派生，也没有执行手机、BUILD、安装或 READY。**

Root 已报告 R5 实际 freezer 和独立 preparer 成功，随后新 NEG-01 在 stage 的 `verify_retired → LATE.retained_stage_parent_profiles` 目录 names 校验失败，尚未进入 sender。该失败仍在调查；若 runtime 需修正，本目录保留原件，重新生成独立候选。本目录只固定了 `990c726a…` 的源码身份，不授予新 NEG-01 或新组合资格。

## 已经落到本地的精确字节

| 文件 | 字节数 | SHA256 |
| --- | ---: | --- |
| `source/release_boundaries.py` | 249860 | `d65923a2323f4590d41291f3606e4b7bc550eaf800826f819c8f4bb1a102f479` |
| `SOURCE-CHAIN-INPUTS.json` | 3515 | `e3cc22536e42074ba3fe662101dd4a4c98224de285b0a5c13c32f84d2fac322b` |
| `source/derive_reviewed_release_sources_BOUND.py` | 34103 | `342cf03f11fcb6cc02fd98f68f44a567603389788de45999c6182ad0a4426c5a` |
| `publish_and_derive_source_chain.py` | 141612 | `d6bfac4486ccd444bfe9ee98f1d1536b6453751200677d6bee5c6f5698360a27` |

消费器唯一变化是 `PACKAGE_SHA = None` 的 RHS 换成实际 runtime manifest SHA256 `990c726a1fff139761494cc19cf091deb269201f27ea947dda4a5833e3a72f2a`。逆向还原到完整 249798 字节 / `016d25b5467c96f96f25f7b2d9d606e40ea18a72421e549d0ab630a01f9c2349`。

构造器唯一变化是 `FROZEN_INPUTS = None` 的 RHS 换成上述完整 `SOURCE-CHAIN-INPUTS.json` 三字段 descriptor。逆向还原到 source-chain43 的完整 33827 字节 / `4c8f32d518c4cf17308f561587eeaf12702b8b9addf0bd8e5ad335a33e941835`。两条变化的 before/after、全文件父子 pins 均保存在 `BINDING-PROOF.json`。

没有改动 `PACKAGE_FILE_COUNT = 38`、`CURRENT_COMPONENT_CHAIN_LENGTH = 12`、`COMPONENT_ROLE_BUDGET = 42` 或组合 `7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411`。这些值来自该 runtime 与实际 source-parent 记录；它们不是可自动迁移到修正后 runtime 的默认值。

## 仅由 root 执行的单次入口

入口已包含上述四份准备文件的固定压缩载荷。载荷解压后先校验完整长度/SHA256。它只做主机源码工作，且两个目标目录必须都不存在：

1. `B/followthrough-fc33-release-source-binding-r5-01`：读取并核对 Mac 既有消费器、构造器、实际 frozen runtime、freeze/controller/preparer 源身份；重新完成两条完整逆向；发布 bound consumer、bound constructor、输入、原父源和发布回执。
2. `B/followthrough-fc33-release-source-chain-r5-derived01`：调用真正的公共入口 `derive_reviewed_source_chain(inputs_raw, read_pinned=material.read)`；发布它返回的 14 份源文件，以及直接的 `SOURCE-BINDING.json`、`SOURCE-CHANGES.json`、`CONSUMER-RUNTIME.json`、输入/构造器原件和最后写入的 `DERIVATION.json`。

`B` 的完整值是 `/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1`。

Root 解除当前 HOLD 后，若仍决定采用这份精确 runtime，可通过已有 Mac controller 发起一次 Python 进程：

```python
process_start(
    host="mac",
    executable="/usr/bin/python3",
    args=["-I", "-B", "-", "--publish-source-candidate-once"],
    stdin=complete_publish_and_derive_source_chain_py_text,
    idempotency_key=actual_new_source_publication_key,
    timeout_seconds=actual_bounded_host_timeout,
)
```

这不是实际调用记录；identity 和 timeout 由 root 为真正进程选定。保留 start/status/read 全原文，确认最终终态、完整原始输出和 EOF，再读取两个目录的实际回执及所需完整源文件。若进程或第二目录发布失败，保留原目录与控制器回执，调查后另定后继动作；入口不会覆盖或自动重试。

发布函数来自已经审过的材料 producer `842f8931…`。入口只抽取 `publish_material`，把它的闭合目录 tuple 分别改成 `('', 'source', 'reference')` 和 `('', 'source', 'contracts', 'preview-module')`；每次要求完整函数逆向，仍保留 held dirfd、O_EXCL、O_NOFOLLOW、单链接、full9、精确成员集、全字节读回、终态最后写入和资源关闭逻辑。其余材料 producer 逻辑不执行。

准备期间只运行了本地单 literal 派生和编译/载荷完整性检查；**没有为该发布入口新增控制场景，也没有执行它的 happy path**。原 source-chain43 的 43 项回归和消费器 55 项控制保持原各自源身份，不计作当前 Mac 发布成功。

## 下游接口

派生后的 `SOURCE-BINDING.json` 必须直接保存 `result['source_binding']` 的九键对象。E2E 构造器读这个原件，并要求其中 `readiness` 三字段 descriptor 精确等于实际最终 collector。不要把整个 result 或 report 包在该文件外层。

派生成功也只产生源码候选。`verify_install_start_ready_UNBOUND.py` 的 `FROZEN_INPUTS/FROZEN_EXECUTION_PLAN`、retention 的 `FROZEN_PHASE_AUTHORITY/FROZEN_RETENTION_INPUTS` 和 producer 的 `FROZEN_SCOPE` 仍为 `None`。新两案 closure/LEASE、BUILD、stage/start/READY、四角色原件、所有实际效果身份都不在本次输入中。

相邻 `../install-ready-input-templates/` 包含其后的 25 份精确形状和 295 个未绑定槽索引。实际源码最终变动时，应先重新派生 source chain，再用实际输出 descriptor 填这些模板。
