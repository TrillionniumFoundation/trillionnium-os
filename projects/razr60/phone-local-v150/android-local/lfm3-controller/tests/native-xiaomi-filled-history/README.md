# Filled query with stable search history

This portable host gate compiles the complete current production classes and calls
the real SUBMIT_QUERY comparator. It generates one-term and three-term history
prefixes over the existing public `native-xiaomi-query-stability/real-censuses.json`.
The added history nodes, geometry, reference signatures and Intent are explicitly
synthetic. They are not the private 6127 device capture, its successful worker's
fresh census, or an Android execution. No private 6127 owner, profile, token, frame
or raw census is copied into this directory.

The production change is limited to `compareFilledQuery` selecting the already
implemented stable-history predicate. Empty observation publication, other action
purposes, original query/target identity, complete membership, geometry, original
action deadline, final live checks and no-authority result flags remain required.

The new cases cover fixed history, allowed existing recommendation drift, changing
or malformed history, wrong recommendation headings, corrupt references, overlap,
query/target/owner/profile changes, original deadline, and unrelated purposes.
The same runner executes the unchanged original 51-case filled-query regression;
it does not edit its fixture or expectations. Existing test utility methods only
construct snapshots and compute synthetic reference signatures. Acceptance always
comes from the actual production comparator.

Run with environment-specific paths passed explicitly:

```sh
python3 tests/native-xiaomi-filled-history/run_host.py \
  --source /path/to/source --output /fresh/external/output \
  --java-home /path/to/jdk17 --json-jar /path/to/json-20240303.jar
```

The fixed org.json jar and existing public fixture retain their original SHA-256
pins. New files use mode 0644. Private original capture replay is maintained outside
the repository source tree and is not a CI dependency.
