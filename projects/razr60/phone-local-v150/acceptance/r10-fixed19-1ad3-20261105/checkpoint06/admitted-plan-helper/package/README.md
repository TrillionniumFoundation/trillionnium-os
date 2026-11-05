# Admitted runtime-prefix Root plan helper — source only

The only code change from the frozen 0d742 helper is the `FAILED_PRELAUNCH_VERIFIER` RHS. It now pins the reviewed e78d verifier at its canonical Mac evidence path. Whole-file reversal of that one RHS reproduces 0d742 exactly. Stage13 and every historical file remain unchanged.

This package does not create a nonce, request, plan, lease or phone action. The local admission reference identifies e85b, but local evidence verification is not represented as an actual Mac execution. Root must first stage and independently run the exact final verifier against its actual retained originals. Only then may Root supply a new authorized identity to the helper. All original runtime32/Root3, budgets, actual08 history, failed-nonce exclusion and unused-output checks remain byte-identical.

The source reference records both failed attempts as failed. Later absence never repairs their original parent join or EOF. The frozen verifier reference is evidence; execution reads its pinned canonical path. `INTERFACE.json` gives that exact path and the required order. No staged entrypoint is run by this delivery.
