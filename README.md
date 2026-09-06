# Trillionnium OS

Canonical source for the Trillionnium OS owner-open control plane, Root Linux packaging, Android integration overlays, and evidence-qualified release program.

The active development and qualification entrypoint is [`docs/START_HERE.md`](docs/START_HERE.md). Source tests establish source properties only; installed Root Linux, Android images, physical-device effects, destructive faults, signing, and public release require their own exact evidence receipts.

Current non-negotiable boundaries:

- the provider is the sole semantic principal;
- Hosts, brokers, registries, schedulers, and controllers remain mechanism-only;
- accepted effects with uncertain outcomes are never automatically redispatched;
- source-head, synthetic-merge, build, installed-target, device, fault, and release evidence are separate and non-inheritable;
- `public_release` remains false until the complete authorized release chain exists.

Start with `docs/START_HERE.md`, then use the machine authority objects under `docs/machine/` and generated views under `docs/generated/`.
