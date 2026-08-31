# Trillionnium OS Global Definition of Done

Status: **NORMATIVE**

## 1. Documentation and governance

- One active entrypoint and one registered document set.
- No historical development plan, batch, status snapshot, audit narrative or
  archive remains in the working tree.
- Machine truth is the only source for current baseline, program, modules,
  requirements, gaps, objective and evidence.
- Generated views reproduce byte-for-byte.
- Protected integration requires exact-head checks and non-author approval.
- Every claim has a retained evidence identity and explicit negative claims.

## 2. Module readiness

Every active module has:

- primary and backup ownership;
- responsibilities and non-goals;
- declared dependencies and no forbidden cycles;
- unique authoritative state;
- API and state versions;
- ordering and concurrency contract;
- finite resources;
- SLI/SLO;
- tests, benchmark, migration and rollback;
- health, fault and evidence contracts.

## 3. Source scalability

- Broker supports bounded multi-inflight work with per-key ordering and exact
  late-result isolation.
- Job start does not hold a global state lock across spawn, journal or other
  slow paths.
- Registries scale across independent keys while retaining linearity.
- Event durability has segmented/indexed recovery with bounded write and startup costs.
- Turn cancellation is event-driven and event storage is bounded.
- WL-01 through WL-12 establish repeatable system baselines.
- No optimization breaks a hard constraint.

## 4. Global control

- Observe and shadow modes reproduce decisions.
- Leases contain epoch, expiry, budget and fencing.
- Stale writers cannot mutate owned state.
- Controller outage behavior is bounded and independently tested.
- Canary and rollback thresholds are versioned.
- The controller never interprets intent, selects commands or retries uncertain effects.

## 5. Dogfood completion

One exact evidence set proves:

1. clean Android image and one product entrypoint;
2. exact installed Root Linux, Host, Broker, Provider and Codex identities;
3. same-turn shell, pipe job, PTY job and ordinary ADB;
4. raw observations return and Codex continues;
5. exact duplicates do not repeat effects;
6. conflicts fail before effect;
7. uncertain operations are never automatically redispatched;
8. crash, storage, USB, reboot and power-loss states remain inspectable;
9. emergency stop inhibits respawn independently of provider health;
10. source, lock, modules, rootfs, target-files, image and device are cryptographically bound.

This is L4/L5 dogfood completion, not public release.

## 6. Public release

Public release additionally requires:

- reproducible signed artifacts;
- certificate/OIDC and transparency verification;
- AVB and anti-rollback;
- OTA install, rollback and recovery;
- key custody, rotation, revocation and break-glass;
- multi-user, lock-screen, privacy and data-erasure review;
- operations and security approval;
- an independent human GO decision.

Until then `public_release` remains false.
