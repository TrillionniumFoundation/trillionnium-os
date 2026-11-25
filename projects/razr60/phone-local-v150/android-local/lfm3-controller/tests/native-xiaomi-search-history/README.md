# Xiaomi search history prefix

This is a narrow compatibility change for the installed Xiaomi APK
(version 20261010, base SHA-256
95883c057eb15bc6e50a82f2e22da13b77980871624f60a2fb9e50cfdf4a8373).

The archived task f5fb4ae516044e3e9abb6141f9eb8e8c reached the empty search
editor. Its three attempts to enter AX3000T were all rejected before dispatch.
Every original complete census had a static "搜索历史" heading at 0/6/0 and one
AX3000T history item at 0/6/1 with its text child. The recommendation heading and
refresh control were therefore at 0/6/2 and 0/6/3, whereas the earlier template
expected them at 0/6/0 and 0/6/1.

The new branch requires this exact, complete single-item prefix, including
class, capability, reference, label, containment and order. None of the prefix
nodes becomes variable or a permitted click target. The original complete-node
membership, unmodified non-recommendation values, disjoint recommendation
enclosure, allowed variable fields, query identity, profile/window ownership,
original age/deadline, private Session guard, original NodeRef, final complete
census and single effect claim remain required. The existing no-history branch
is unchanged. The generic non-web controller messages now describe validation
failure rather than asserting that every refusal was caused by screen movement.

## Required focused gates

Both commands take an external --recorded-dir containing the three immutable
step-02/03/04-action.json archives. Their full byte sizes and SHA-256 values are
checked before reading any census. Private task archives are not part of Git.

- run_host.py --source CANDIDATE --base-source EXACT_1FAB_SOURCE --recorded-dir RAW --output NEW --java-home JDK17 --json-jar JSON
  compiles full actual pure classes in both variants. The baseline must
  reproduce all three original heading refusals. The candidate must pass the
  exact 70 named positive/negative cases. Real pairs are kept distinct from
  explicitly labelled host counterfactuals.
- run_service.py --source CANDIDATE --recorded-dir RAW --output NEW --java-home JDK17 --json-jar JSON
  reuses the unchanged existing input-bridge Android IO ports and complete
  production Session. The Service type/original-reference/final-census bodies
  remain verbatim. All 12 named cases and their exact per-case assertion counts
  are required. The original three recorded node populations drive the new
  branch; host profile IDs, clocks and platform effects are explicit synthetic IO.

The unchanged old empty-input and filled-query pure gates remain required.
The parser and direct-card runners keep their complete earlier source pins.
protected_history_prefix.py accepts only the exact reviewed current or parent
file and reverses the new block to the full parent SHA for a proof copy. Both
runners still compile the actual current production source.

Host passing results are not phone execution, successful search, current price,
ordering, payment, or a publication/install qualification. The original f5fb
task remains failed, with no search text dispatched and no verified price.
