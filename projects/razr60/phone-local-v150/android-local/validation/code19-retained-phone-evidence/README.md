# Code19 retained phone evidence — bounded supplement

This supplement adds four individually reviewed, sanitized audit files. It
does not modify the preceding Code16–19 qualification snapshot, any original
phone verdict, the frozen Code19 source, or the APK.

## Interrupted original nine-case suite

The [recovery audit](interrupted-suite/PUBLIC-SUMMARY.md) and
[its safe data](interrupted-suite/PUBLIC-SUMMARY.json) retain the original
nine-case outcome: **1 pass, 1 unknown, 7 not_run**.

The first case's original pass can be reproduced from its retained model,
action and goal evidence. The second case is only classified as
`supplemental_recovery_predicates_pass_with_late_ui`. Its late independent
UI collection began 392.522 seconds after the terminal record and 109.874
seconds after network restoration. It does not establish an atomic historical
terminal UI observation or continuous offline execution. That case remains
unknown in the original suite. This supplement does not fill in the remaining
seven cases.

The original full-nine plan SHA256 remains
`ef92f1103041d8453f35c13b8718a1834dfd84bd69f2e8afd871c12f8c17983c`.
The safe audit identifies the original suite and assertion digests.

## Completed calculator case in the separate continuation

The [calculator audit](calculator/PUBLIC-SUMMARY.md) and
[its safe data](calculator/PUBLIC-SUMMARY.json) preserve the original
**FAIL**: one launch, 17 steps, 16 actual dispatched effects, task-deadline
termination and known cleanup.

Five examined decision frames retained all 25 current nodes, all required
keypad choices in the actual grammar and the entire prior dispatched
sequence without omissions. The model nevertheless alternated legal choices
that did not advance the requested computation. Fifteen click effects had the
same observation-state digest before and after. The existing repeat guard
tracks only the immediately preceding no-effect action, so alternating choices
can continue.

Sixteen native inferences completed in 25.379–30.487 seconds; the last was
cancelled after 5.021 seconds with exit 143 and dispatched no action.
Performance consumed time but is not established as the sole failure cause.
Neither adding history nor a future cycle guard has been shown to make this
case pass. Other continuation cases are outside this supplement.

## Provenance and qualification limits

Both audits only read retained host evidence. Their complete raw input sets
were independently rehashed and remain private. The public files omit task
and request identifiers, device identifiers, private UI/model text and local
host paths. The approved source files were copied byte for byte:

| Safe file | Bytes | SHA256 |
|---|---:|---|
| interrupted-suite/PUBLIC-SUMMARY.json | 2,827 | `3c6e61b6e707b08598ec787a2f8c13396ae280632b91027f86320a6af01cc624` |
| interrupted-suite/PUBLIC-SUMMARY.md | 1,882 | `2168199d03fbb2320e0c8438e53daafaa59aba5ae1f8f547a47d316b29e61f59` |
| calculator/PUBLIC-SUMMARY.json | 5,241 | `87b52afc262a535029c1e171c2dbee501c00585cd8489ca3dc3e423fc1da5bc5` |
| calculator/PUBLIC-SUMMARY.md | 2,152 | `f3800844fb2c8af84e23601150cafa02a53d19acaccfdb7a9492ec49bdbf0534` |

The original [Code19 build qualification](../code19-build-and-qualification/README.md)
and [earlier dated evidence snapshot](../phone-local-20261109/README.md)
remain unchanged. These read-only audits do not qualify ordinary Start,
Stop, sustained background work, restart, every app, or an unbuilt successor.
No phone command or model inference was performed to prepare this supplement.
