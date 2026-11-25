# Xiaomi search history prefix: portable regression

This test covers the original `set_product_query` comparison only. It constructs
explicitly synthetic search history headings and terms in memory from the existing
public, SHA-pinned `tests/native-xiaomi-search-input/real-censuses.json` fixture.
No new device recording, private owner identity, local task archive, or absolute
host path is included or required.

The history prefix can contain multiple terms with arbitrary observed text; those
terms remain exact between both complete censuses. They supply neither the query
literal nor a result, price, click target, or dispatch permit. All variable fields
remain limited to the already classified recommendation chips and passive carousel.
The input field, complete window/profile/owner bindings, and original action
deadline remain required. The existing observation-publication and filled-submit
entry points do not gain this exception.

The generated history nodes use a signature-only test helper to construct
internally consistent references. Their new geometry and history text are
synthetic; this does not replay or reproduce an Android action. The production
comparator decides acceptance. Three separate private, original-worker census
pairs are used by an external host audit; those files and that runner are not
part of this portable suite.

Run from a checkout with JDK 17 and the existing pinned org.json jar:

```text
python3 tests/native-xiaomi-history-prefix-portable/run_host.py --source SRC --output OUT --java-home JDK17 --json-jar JSON_JAR
```

The runner compiles the current eight complete production classes, checks all
named cases and unchanged input/tool hashes, and saves a source-bound result.
The old 99-case empty-input and 51-case filled-query suites remain unchanged.
