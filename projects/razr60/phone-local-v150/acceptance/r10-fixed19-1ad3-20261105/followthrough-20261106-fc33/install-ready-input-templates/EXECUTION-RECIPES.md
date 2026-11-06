# 精确入口、填值与原件保全

## 1. 正式源码链

当前 source-chain43 构造器的 Mac 原件路径：

`/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/followthrough-20261106-fc33-release-source-chain01/source/derive_reviewed_release_sources_UNBOUND.py`

33827 字节 / `4c8f32d518c4cf17308f561587eeaf12702b8b9addf0bd8e5ad335a33e941835`。

它提供 API，不提供 BUILD CLI。直接运行该源的 `__main__` 会退出，即使已经单 literal 绑定也应通过模块加载后调用公共 API：

```python
result = bound_constructor.derive_reviewed_source_chain(
    complete_source_chain_input_bytes,
    read_pinned=actual_complete_original_byte_reader,
)
```

`result` 的五键和全部文件名在 `SOURCE-CHAIN-RETURN-CONTRACT.json`。按返回的路径/字节发布 14 个 source candidate。单独写 `result['source_binding']` 为一份九键 JSON 原件；E2E 的 `formal_source_binding` 指向它。`readiness` 精确三字段指向这批 `source/collect_r10_readiness.py`。`changes` 可证明 collector 仅把旧 `BOUNDARY_CONSUMER_SHA256` 换成最终 bound consumer 的完整 hash，逆向回原 `2b4ff90f…` 源。

源码链返回不包含 BUILD-RESULT 或 archive；所有安装/retention FROZEN 槽仍为 None。现有 990c 单 literal 准备和单次入口在 `../R5-release-source-binding01/`，目前 HOLD，不能据此填 actual published/readiness descriptor。

## 2. 真实 BUILD

填模板 05 的真实进程参数，不通过虚构 `build_result` 调用 reader 来生成预先 argv。`release_reader.expected_build_command` 要读取完整实际 build-result descriptor；它用于事后匹配真实原始调用。

```text
python3 -I -B <derived/source/build_release_r10.py>
  --inputs <derived/contracts/FINAL-INTEGRATION-INPUTS.json>
  --inputs-sha256 <actual formal raw SHA256>
  --output <fresh actual BUILD directory>
  --retirement-inputs <actual complete retirement inputs>
  --retirement-inputs-sha256 <actual raw SHA256>
  --component-boundary-inputs <actual new closed prefix inputs>
  --component-boundary-inputs-sha256 <actual raw SHA256>
  --policy-adoption-inputs <actual fixed adoption original>
  --policy-adoption-inputs-sha256 <actual raw SHA256>
  --shared-materials <actual shared/SHARED-MATERIALS.json>
  --shared-materials-sha256 <actual raw SHA256>
```

主机 `mac`；现有 reader 接受 `/usr/bin/python3` 或 `/opt/homebrew/bin/python3` 及正常化的 `-I`/`-I -B` 形状。具体实际命令留存原文。实际 sealed BUILD 不传 `--material-only`。

退役模板 04 的 `report/operator/ancestor_retirement/failed_predecessor` 均为真实原件。可选 `original_operation_evidence` 若使用，必须是实际 `name/path/bytes/sha256` 行列表；无此可选证据时按原 builder 的既有语义省略或使用空列表，不能保留 null。这不替代新组件完整闭合。

实际 builder 必须返回 `SEALED_ACTUAL_RETIREMENT_BOUND`，保留输出目录全部原件及实际 controller start/status/read。stdout 是 `json.dumps(report, sort_keys=True)` 后加 LF；BUILD-RESULT 是 pretty JSON 后加 LF。reader 核类型保持的 canonical 对象一致，不要求两种外观编码相同，也不能重写 stdout 去假造对应。

按模板 06 填实际 archive、release manifest、SOURCE-SEAL、MODULE-MANIFEST、seal-binding 等。实际 shared17 每一份 full bytes 都要保留。调用派生的 `verify_final_release_inputs`，记录完整返回值。该返回是主机 BUILD 原件已核，不是 phone READY。

## 3. 安装 phase 的精确请求

模板 07 的 actor 原源 pin 5652 字节 / `179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22` 固定。实际 actor 路径在 P4 项目内；archive 与 installer 放同一个实际 GNU 私有交付目录，且 archive bytes/SHA 必须等于已核 BUILD。

使用当前源码链派生的 protocol：

```python
protocol.validate_plan(plan, release_verdict, release_input_value)
expected = protocol.expected_phase(
    plan, phase, release_verdict, release_input_value, actual_retirement_sha256,
)
```

`phase` 只能为 stage/start/ready。保存 `expected['request_raw']` 原字节和 `expected['dispatch']` 原提交对象。dispatch 必须原样使用已有 actor 的 host/executable/args/cwd/idempotency_key；不要自己重新拼 root shell、环境或 argv。protocol 已包含实际 GNU 环境、精确源 guard、guard 的 source/full9 和当前进程身份回执。

三 phase 的 label/request_path/idempotency_key 各自唯一。timeout 为源中允许的正整数范围。必须保存模板 08 的全部九键原件：controller dispatch/start/status/read、actor before/after、request、intent、baseline、result 及独立原始 phone stdout/stderr。

controller CLI stdout 是较小的原 actor summary；它不能替代完整 actor `result.json`。后者与原始 phone streams 必须另按实际 full bytes 保全。controller stream 的 raw hex/text、长度、EOF、同步/截断状态都保持原始类型；`False`、`0` 和 `0.0` 不可互换。

## 4. stage/start retention 的两次独立绑定

始终保留源码链返回的 `verify_install_start_ready_UNBOUND.py` 原样，作为 retention 的精确 INSTALL_READER helper。最终 install reader 绑定实际 FROZEN_INPUTS 时生成独立新源，不覆盖 helper；否则会破坏 retention 的源 pin 并形成自引用。

每个实际 phase 完成后按模板 09 或 10 保存 phase authority JSON 原件。对该 phase 的独立 retention verifier 副本，仅把 `FROZEN_PHASE_AUTHORITY` 绑定到这份实际输入的三字段 descriptor，再调用：

```python
scope_raw = phase_retention.derive_scope_from_actual_phase(
    actual_phase_authority_bytes, read_pinned=actual_complete_original_byte_reader,
)
```

此 API 返回已经验证的 canonical compact UTF-8 JSON + LF。stage authority 只含 stage；start authority 必须含 stage 与 start，且原 stage 终态不晚于 start 创建时间。stage scope 的 generation 为 None；start scope 的 generation 取实际启动后 supervisor 的四字段身份。scope 与 phase result/stdout、完整 BUILD、archive、retirement、component/policy pins 和实际 source identity 相连。

生产捕获请求由现有入口派生：

```python
R, C, rraw, template_raw = phase_retention.source_context(read_pinned)
P = R.reviewed(read_pinned(R.SOURCES['protocol']), R.SOURCES['protocol'], 'protocol')
op_raw = C.manifest_operation()
expected = phase_retention.expected_operation(
    C, P, template_raw, scope_raw, op_raw, actual_unique_capture_identity, actor_plan,
)
```

`expected_operation` 内部调用 `C.bind_source(scope_raw, template_raw)`，只把 producer 的 `FROZEN_SCOPE` 绑定为准确 scope pin，生成全部 root command/request/dispatch。不可把人工填的文件路径作为泛化读取授权。

捕获顺序固定为：首 manifest → `C.chunk_operations(scope_raw, first_manifest_raw)` 返回的全部操作 → 末 manifest。每次实际操作使用不同 label/request_path/idempotency_key，不能与 stage/start/ready 重用；上一操作完整终态后再发下一操作。实际 operation 数量来自 manifest 的真实长度，不预填一个假定值。

保全上限保持不变：STAGED-PRESERVATION 原件允许至多 32 MiB，通过 1 MiB chunks 和每次至多 2 MiB 响应拼回。原 actor 的 8 MiB shell cap 不提高，也不能推断 32 MiB 文件可由一次 stdout 搬回。每 chunk 仍重核整文件哈希、full9、根目录与首末 manifest 一致性。

实际 operation 全部保全后填模板 12/13；对该 phase retention 副本再绑定 `FROZEN_RETENTION_INPUTS`。调用：

```python
retained = phase_retention.retain_installation_originals(
    actual_retention_input_bytes,
    Path(actual_fresh_host_retention_output),
    read_pinned=actual_complete_original_byte_reader,
)
```

这会重验实际 operation，拼回完整原件，经 held dirfd 精确写入/读回，输出 `RETENTION-RESULT.json` 和原始 phone descriptor 到 retained host copy 的映射。分别合并 stage 三文件与 start 两文件；五个 `install_originals` descriptor 来自这些已核输出。

## 5. 四角色 exact8 与最终安装 reader

模板 14 的 READY source 是同批派生 collector 的 phone 原件；READY original 是这次实际 ready phase 的完整 phone stdout。module 原件包括 manifest/binding/service/helper；四角色 identity 为 supervisor/model/sidecar/provider；三个 child bind 及它们引用的原进程/初始流文件也必须在实际 originals reader/map 可精确读到。

先调用派生的 `verify_resident_output_bindings`。然后填模板 15，把 stage/start retention 返回的五原件、三 phase、执行 plan、release/exact8 inputs 和全部 original_map 绑定到最终 install reader 的独立副本：

```python
verdict = actual_bound_install_reader.verify_install_start_ready_originals(
    complete_actual_install_reader_inputs,
    read_pinned=actual_complete_original_byte_reader,
)
```

最终 reader 要求 stage ≤ start ≤ ready 的实际控制器时间顺序；READY 原始 bytes 必须同时等于 exact8 原件和该 ready phase stdout；STARTED supervisor 必须等于 READY/exact8 同一实际 generation。任何迟到、截断、超时、取消、原进程身份漂移或缺失原件都不能补写成成功。

上述 verdict 只覆盖它声明的实际执行/原件范围。它不自动给 E2E-01/02、业务公开回执、显式返回、冷启动、长期健康、原父进程 wait/EOF、rollback 或完整 scope census 授权成功。
