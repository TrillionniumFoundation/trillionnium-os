# Public Code23 exact-source CI adapter

This independently versioned helper derives from `ui-venus-runtime-rebuild-v1` at commit
`cc4a7035760383a126e4510002139d88667e0b97`. Its App admission pin is exactly
`5559ef2ad8e9b7e8d886dfc9f3bf6b4cce2fde7170a7cb40ba0b6ce1061a8b4f` (public source commit `dea29e5a630180509a31568efd7cea481aa61a57`).
The previous helper remains unchanged and continues to reject this source.

Only the App source identity, the MNN producer helper identity where required,
and the MNN diagnostic revision label differ. Compiler qualification, build
flags, upstream MNN commit, original build receipts, runtime bytes, ABI checks,
and source/head/run/attempt transport checks are unchanged. The compiler
qualifier and the existing UI-Venus contracts are copied byte for byte.

The public App source maps to the privately retained Code23 r2 build source as
documented in `../code23-publication-037c-r1/SOURCE-MAPPING.json`. These CI
helpers do not relabel that earlier build. A new successful CI run must rebuild
and verify its own artifacts; host unit contracts do not establish a native
build, installation, model performance, or device functionality.

Run the source-binding contracts from
`../mobimind-ci-host-split-v9-code23-037c` with
`python -B -m unittest -v test_code23_source_binding.py`. The workflow also
runs the unchanged UI-Venus rejection contracts in its new directory.
