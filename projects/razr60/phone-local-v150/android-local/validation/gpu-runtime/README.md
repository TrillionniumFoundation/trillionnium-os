# Independent GPU validation

This directory corrects one validation false negative without changing the
frozen Android source or rewriting an earlier run. The pinned GenieX runtime can
select `GPUOpenCL` while llama.cpp labels its model allocation `OpenCL model
buffer`. The original predicate searched only for `GPUOpenCL model buffer`.

`gpu_log_validation.py` accepts `OpenCL` as a **model-buffer label alias** only
when the same stderr contains all of the following:

1. An explicit `Using 1 device(s): GPUOpenCL` selection, with no conflicting
   selected backend.
2. `llama_prepare_model_devices: using device GPUOpenCL (...)`.
3. A positive `load_tensors: OpenCL model buffer size = ...` allocation, or the
   original `GPUOpenCL` label.
4. A positive `load_tensors: offloaded N[/M] layers to GPU` result.

Device enumeration, generic `GPU` strings, KV or compute buffers alone, zero
allocation and zero offload do not pass. Warnings and fallback lines remain
visible. This establishes positive tensor offload; it does not prove every
operator executes on the GPU or measure power and utilization. Native identity,
model/output hashes, budget, process exit and goal predicates remain separate
requirements.

## Offline replay review

```sh
python3 review_gpu_replay.py \
  --replay-dir /absolute/path/to/retained/replay \
  --source-dir /absolute/path/to/that/replay/frozen/app/source \
  --output /absolute/path/to/a/new-review.json
```

This command has no ADB or network code. It verifies the replay's exact source
manifest, local input and raw-output hashes, selected model profile, native
budget/device/return codes, and the host's owned process-exit record. It creates
one new review file using exclusive creation and leaves the original report
unchanged. A corrected result is named `model_only_completed`; it never grants
phone action authorization or a successful phone goal.

The function `install_for_new_run(acceptance)` is available for an explicitly
recorded **new** validation run. It changes only the in-memory GPU log predicate.
Callers must retain this module and its hash in their new run's validation
provenance. The function does not modify the on-disk driver or App source, and
does not relax any native, action or final-UI gate. It is not called by the
offline review command.

Run the focused regressions with:

```sh
python3 -m unittest -v test_gpu_log_validation.py
```

No phone UI, model weights, private keys or original runtime logs belong in this
source directory. Device evidence is retained separately by the operator.
