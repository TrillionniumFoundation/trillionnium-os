# Filled Xiaomi product-query stability

This change covers only the already supported Xiaomi product-price workflow and the observed managed-profile `FrameLayout` toolbar: the owner-derived query field at `0/1` and the normal search button at `0/2`. The action remains a newly issued model click in the existing Session tool domain. It does not submit an order or create a product/price completion proof.

## Runtime checks

The complete native census, target/user/display/window/generation/install bindings, hidden IME, reported window set, original button reference, all ancestors and the complete query field remain required. Only observed recommendation chip text/position/visibility/reference changes inside the fixed `0/6` enclosure can vary. The other root children and every other native node remain exact. The filled form is a separate predicate; the existing empty-input observation-publication predicate is unchanged.

The original filled toolbar's query reference is retained alongside the clicked button during the bounded local action handoff. Both owned clones are released by the existing `Graph.close()`. Immediately before the single action claim, the Service performs a complete final comparison, verifies the actual button/ancestor chain, and re-reads the same query node through the same root. An identical-looking replacement query node is rejected.

The existing owner grammar accepts case variants of AX3000T. Eligibility retains that behavior, while the query text, label, input hash and native signature still match the owner's exact spelling.

An unentered stale click can release its consumed product-query reservation only after the exact drained worker/guard proof is durably journaled. The old model run, action, observation and guard remain unusable. A new observation and new model decision are mandatory; the action budget is not reset.

## Recorded fixture boundary

`real-censuses.json` contains the complete 186-node pre-action native tree and the first complete successor tree from the failed November 25 task. Their native node fields are unchanged. Both trees come from the product search screen: query, search controls, hot keywords and product listings. The fixture has no account details, names, addresses, phone numbers, login credentials or purchase history. Its device task UUID is task-identity evidence; it is not an application login token or a dispatch capability.

The original action worker saved a bounded freshness diagnostic, not a complete fresh census. The successor tree's app-tree SHA exactly matches that diagnostic's fresh SHA, but it was recorded by a later observation. The test explicitly records this distinction and does not claim an original-worker replay.

Original source SHA-256 values:

- Before: `1664ddee554790d25e05a8d30e5980debf007f2c5c6f2ea95598cf949fa518bb`
- Successor: `99a6807c218166128a8f9df56dd7466e0707c7be6685bf82baf979e58f1a00cb`
- Successor and rejected-worker fresh app tree: `53f4a2b4e4818f1fa81bf53b150c023e1b16ad6421f37c2b1fb507c0cb4525fb`

The Service/Session test reuses these UI shapes with explicitly synthetic Android objects, profile RPC values, clocks, captures and model callbacks. It executes the actual Session and verbatim extracted Service methods. It is host validation, with zero phone operations; it is not Android runtime, model inference or business-completion evidence.

## Required gates

```text
python3 tests/native-xiaomi-query-stability/run_host.py --source SRC --output PURE_OUT --java-home JDK17 --json-jar JSON_JAR
python3 tests/native-xiaomi-query-stability/run_integration_host.py --source SRC --output INTEGRATION_OUT --java-home JDK17 --json-jar JSON_JAR
```

The integration gate must contain both nonempty `SERVICE-CASES.json` and `SESSION-CASES.json` named reports, each with all cases passing. Their `assertions_total` is one combined counter, so it must not be added twice. It checks that every copied production method body remains verbatim after the explicit host-port adaptation.

The old complete native-action, empty-input and canonical suite remain required. Three old closed source-proof runners use `protected_filled_query.py` only to derive an exact, hash-pinned predecessor proof copy. They continue compiling the current production files and retain their previous fixtures and case assertions.
