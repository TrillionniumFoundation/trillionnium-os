# G1 `be6e681` independent signing handoff

This ops branch is **not** the canonical implementation branch and is not evidence. It carries only a non-promotable request template for an independently administered signer.

## Immutable request identity

```text
repository      TrillionniumFoundation/trillionnium-os
pull request    34
base commit     4142fe2864f05ac2a35037b4b025f4f1f0a5d35f
base tree       ce143d2d6865622a75e88aee0878927fb1bebeb5
head commit     be6e681c02996ee8c0fd25c29943aad21c66292e
head tree       a686aa24e4a3afc6527511022d2374e1d1c27fdc
GitHub merge    91c28f34e0601a00bfe832232cd8be0fc3e7ac7e
source run      33596149698
ordered run     33596149634
Android run     33596149715
evidence run    33596149679
```

Any base/head/ref/PR retarget invalidates the request.

## Required independent procedure

1. Read the live PR object and confirm the exact tuple above.
2. Confirm a fresh eligible non-author approval on the exact head. Do not inherit the stale `e790486…` approval. The PR author and current commit author/committer are ineligible for the current independence role.
3. Download the protected aggregate artifact and all support artifacts using their live GitHub IDs.
4. Verify the GitHub-reported artifact digest and independently SHA-256 the downloaded bytes.
5. Parse the ordered-merge receipt from run `33596149634`; copy its exact deterministic merge commit, tree and ordered parents into a fresh request outside this repository. Never sign the placeholders in the checked-in template.
6. Run the live verifier against the current PR/review/run/job/artifact objects and produce the complete v2 unsigned receipt.
7. Under a separately administered, currently valid and non-revoked trust root, sign the complete receipt outside this repository. Pin the receipt bytes and verification material out of band.
8. Run the offline verifier with exact subject, validity, revocation and role-separation checks. A successful verification may propose a non-mutating promotion; it must not silently edit machine truth.

## Prohibited shortcuts

- Do not sign this repository-controlled template.
- Do not treat a SHA-256 content hash as authorization.
- Do not infer the deterministic merge hash from the GitHub prospective merge object.
- Do not use the stale approval or any old source/base artifact.
- Do not let the source author, PR author or repository workflow self-assert the independent signer role.
- Do not merge, deploy, promote, flash, perform destructive tests or release from this branch.

```text
signed=false
promotable=false
zero_gap=false
public_release=false
automatic_redispatch=false
```
