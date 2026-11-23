# Exact natural note intent

This suite exercises the actual `NotesOwnerIntent` class and unchanged
`FixedIntentTools` payload validator. It has no Android, model, service, or
dispatch fake and does not establish phone completion.

Supported requests consume the entire immutable OWNER. The returned body is
exactly `owner.substring(bodyStartUtf16, bodyEndUtf16)`, with no trim, Unicode
normalization, date resolution, generated marker, or model-proposed text. A
standard supported request to make a note uses persistence plus readback as its
verification policy. It does not create a reminder or alarm.

The first forms are `记一下：正文`, `正文记一下`, `把正文记到备忘录`, and
explicitly quoted note content such as `新建一条笔记，正文为“正文”`. Some exact
polite prefixes and note synonyms are listed in the production patterns.
Unquoted bodies with ambiguous additional clauses, scheduling language, or
multiple goals are unsupported. Explicitly quoted content remains data,
including phrases such as “不要返回”; an outside restriction remains outside
the body and makes an unconsumed combined request unsupported.

Bodies must be one line and at most 94 UTF-16 units, matching the current
complete-list evidence boundary of less than 95. Longer text is not silently
truncated. Unsupported requests expose no maskable body span. A supported
result can mask only the identical immutable OWNER, replacing exactly its body
span with spaces while preserving every other code unit and all offsets. The
caller still runs the existing authorization compiler. This parser grants no
tool and does not bypass any phase, identity, dispatch, or completion gate.

The original explicit save/list/reopen contract remains in its existing parser;
this class is an additional narrow recognizer, not a replacement.

Run with the formal host JDK:

```
python3 tests/notes-owner-intent/run_host_tests.py --source /absolute/source --output /new/output --release8
```

Without `--release8`, the runner labels its result as Java 8 syntax/target only;
that result must not be used as Java 8 API or Android compatibility proof.
