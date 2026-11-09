# Code18 merge and prompt admission

This candidate starts from the frozen UI-Venus17 model-only source and adds the observation-fields17 text-controller changes from their common Code16 parent. It does not add a visual dispatcher. The private UI-Venus17 and observation-fields17 sources remain unchanged.

The prompt now carries one lossless scalar table of all recorded task-history rows. `columns` names each position, `refs` contains repeated long strings, and `rows` preserves original order and repeated actions. An empty array or omitted trailing cell means the field was absent; `[i]` refers to `refs[i]`; explicit null, false, zero, and empty strings are retained. Recorded effects are observations, not proof of task completion. Private raw evidence remains unchanged.

Every enabled, non-password, same-package observed node with click, edit, or an actually observed scroll direction must remain in the prompt. Optional catalogue entries and non-actionable text may still be omitted with explicit counts. There is no 32-node action-domain cap. If the full required domain and full recorded history do not fit the unchanged Java admission heuristic, the round fails explicitly before model inference. The existing native exact tokenizer remains the final context gate. No silent model truncation, context enlargement, automatic model retry, or action/freshness relaxation is introduced.

The UI-Venus model-only candidate uses a separately compiled Q4_0 worker with a new profile and complete source/ELF pins. The original Q4_K_M worker is retained in its historical candidate. The projector, official input protocol, shared process lease, and three-journal recovery retain their original behavior. This path does not dispatch GUI actions. Model-file naming does not establish backend support or runtime qualification; actual complete model hashes and a real ordinary-App probe remain required.

The text runtime already supports explicit 4096 and 8192 configurations. This change does not select a new default or alter the native exact-token budget. A separate 8192 test candidate may be selected by a reviewed configuration transaction; host admission scores are not measured model token counts or functional success.

The fixed GenieX download helper retries only an HTTP 500/502/503/504 response before any archive body is opened, at most three attempts with two/four-second delays. The URL, TLS checks, byte/SHA verification, and extraction restrictions are unchanged. Body, TLS, 4xx, and hash errors are not retried.
