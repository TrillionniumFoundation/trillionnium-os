# Shared virtual display group consumers

`consumer.patch` updates the existing personal and Ctrip host harness consumers.
The two families have the same power contract. The patch contains only the changed
hunks; it does not publish device observations, task records, or operator paths.

The pinned outer helper reports the actual members of its validated group. The
host accepts a nonempty list of distinct virtual display IDs containing the owned
display. Peers may join or leave without changing the owned token, unique display
identity, or original deadline. The helper's complete typed census, including
disabled displays, remains responsible for proving physical display separation.
The raw DMS/PMS fence independently requires every member of the target group to
be virtual and reports the real list instead of a synthesized singleton.

Releasing the owned display may leave a virtual peer and its group alive. This
confers no input, task, or cleanup authority over that peer. The bounded power
fence continues to compare physical displays 0 and 1 and their group activity.
The task ownership, target app selection, and release predicates are unchanged.

## Reproduce the pure host regression

Apply the patch to a copy of the host package and run:

```sh
python3 -B test_shared_virtual_group.py --package /path/to/package --out /path/to/new-result.json
```

The test imports only the actual `outer_session.py` and `reference/physical_power.py`
consumers. It supplies synthetic helper receipts and complete DMS/PMS dumps. Its
124 checks cover both families, including disabled virtual peers, joins/departures,
release with a surviving peer, physical/unknown peers, incomplete census, own
identity changes, and the unchanged token/deadline restrictions. It performs no
phone operations and does not qualify any real app flow.

The patched outer consumer pins the built helper DEX SHA-256
`02173012cd6c8825966a4a103848d4a33f4888c0ecf89e864fb8bb0bdf584ee2`.
The complete harness must also be rebound to the reviewed source commit, source
manifest, production input map, signed APK, helper path, and promotion evidence
before any phone run. This focused patch does not replace those identity gates.
The original personal host checks must be rerun against the resulting package.
