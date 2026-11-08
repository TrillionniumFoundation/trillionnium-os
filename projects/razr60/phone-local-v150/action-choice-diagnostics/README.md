# Local action-choice diagnostic candidate

**Work in progress. Host-only renderer; no model or phone-action qualification.**
This source explores a numbered action menu whose target metadata stays in a
trusted descriptor table. It does not change or bypass the existing Android
action parser, freshness, process ownership, cancellation or completion gates.
No model output is executed by these files.

Read `DIAGNOSIS.md` for the source-backed findings and limits. `SYSTEM.txt` is the
exact 606-byte Chinese candidate instruction; `render_choice_probe.py` is the
unchanged isolated renderer used to prepare controlled prompt comparisons.

```sh
python3 render_choice_probe.py --record /path/to/private-record.json \
  --out /path/to/new-private-output-directory
```

The input must be a JSON record containing `prompt` in the existing Controller
framing (`UNTRUSTED_DATA` followed by JSON, then `OWNER` and the original task).
The input record and generated files may contain private UI and task data; keep
them outside public source control. Output creation is exclusive. The program
does not contact Android, ADB, a model, a server or another application.

This renderer cannot recover fields omitted by the existing lossy observation
projection. It records that limitation and retains every supplied label and the
original owner bytes without further truncation. Its legacy c/t/s-based menu is
for inference-only comparison; production requires complete action capabilities
and binding to the same immutable pending observation.

The admission record uses the existing conservative raw/NFC UTF-8 byte upper
bound with the current 4096-context Qwen3-VL profile and a fixed visual allowance.
It is not an exact tokenizer count, not a generic bound for other models, and not
proof of semantic coverage. Over-budget cases are marked not admitted.

The public directory contains no test fixtures, raw UI, device output or model
weights. Python syntax and byte identity with the isolated candidate were
checked. No semantic success, end-to-end task completion or Android integration
is claimed.
