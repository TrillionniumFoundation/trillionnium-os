# Qwen3.5 4B experimental text selection

The ordinary model chooser and offline importer expose the existing pinned
Qwen3.5-4B-Q4_0 artifact. NPU and GPU are explicit choices. The default and saved
automatic target profiles are unchanged. Saving a selection does not qualify a
backend, perform inference, or enable vision.

The 5 GiB minimum is engineering admission headroom, not a measured peak.
The worker still verifies the exact existing filename, size, SHA-256 and runtime.
It uses the model's GGUF chat template with enable_thinking=false. Real device
generation and tool-task tests are required before choosing it as a default.

Run run_host.py with absolute --source, --output, --java-home and --json-jar.
It first executes the existing settings suites, preserving the 43/196
transaction, 15/100 generation, 8/36 context and 30/243 visual case/assertion
contracts. The shared menu inventory assertion is deliberately updated from
six to eight choices; the first six choices retain their original mapping.
Then five separate Qwen cases exercise the actual extracted ordinary owner
button, settings transaction and engine bodies through explicitly identified
host Android/positive-asset boundaries.

The additional cases cover both compute choices, selected-menu readback,
exact configuration restoration, no qualification claim, closed text/visual
allowlists, the production MemAvailable parser threshold, the actual Engine
lowMemory refusal and rejection of an incorrect pinned weight size.
The offline import suite separately covers the fifth model and two projectors.
No test here performs Android input, native model inference or positive
hardware qualification.
