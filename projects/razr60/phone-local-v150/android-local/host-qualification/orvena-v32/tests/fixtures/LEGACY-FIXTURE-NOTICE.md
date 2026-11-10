# Anonymized loader regression fixture

`legacy-loader-package/` preserves the loader behavior needed to reproduce the
old valid-bytecode-cache execution bug. Device serials, physical display IDs and
absolute host paths were replaced with synthetic values, and its package
manifest was regenerated. The test injects only a local sentinel exception or
string. These files are synthetic test dependencies, not retained original phone
evidence, approved execution commands or a device qualification package.

`upgrade-select-helpers/` contains the source bytes whose hashes are verified by
the preparation protocol tests. Phone mutation functions are not executed by the
tests. `production-scope-positive/` contains synthetic output from the Java host
scope harness, using synthetic observations and identifiers; it is not captured
phone UI or a model task result.
