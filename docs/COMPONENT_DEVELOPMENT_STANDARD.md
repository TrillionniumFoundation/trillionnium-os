# Trillionnium OS Component Development Standard

Status: **NORMATIVE**

## 1. Component versus module

A **module** is a long-lived logical ownership and state boundary. A **component**
is a concrete build unit, executable, library, package, script, Android module,
service definition or other artifact-producing source unit.

One module may use several components, and one composition-root component may
implement more than one module. A directory compiling successfully does not make
it an active product component.

The current Rust component inventory is the closed combination of:

- root `Cargo.toml` `workspace.members`;
- `docs/machine/module-catalog.v1.json` `default_source_closure`;
- `governance/component-lifecycle.v1.json` for every non-default member.

These sets must cover every root Cargo workspace member exactly once.

## 2. Required local documentation

Every Cargo workspace member has a component-local `README.md`. It must explain,
as applicable:

- the component's purpose and authority boundary;
- whether it is selected by the default owner-open source closure or sealed;
- its associated module contracts or replacement components;
- public binaries, libraries and feature gates;
- the exact local source-test command;
- migration, retirement and product-inclusion restrictions;
- explicit negative claims for installed targets, devices and release.

A source directory without this local guide fails repository qualification.

## 3. Active default closure

Members in `workspace.default-members` must equal the module catalog's
`default_source_closure`, in the same order. They are the only components
selected by an unqualified root `cargo build`, `cargo test` or `cargo clippy`.

Each active default component must have explicit catalog source ownership and link to its detailed `docs/modules/MOD-*.md`
contract and include:

```sh
cargo test --locked -p <package-name> --all-targets
```

Changing the default closure is a product-graph change, not routine Cargo
maintenance. It requires module, architecture, compatibility and evidence
review.

## 4. Sealed non-product members

Every non-default workspace member appears exactly once in
`governance/component-lifecycle.v1.json` with:

- a `sealed_*` classification;
- a concrete reason;
- zero or more existing replacement paths.

A sealed component may remain buildable for source archaeology, compatibility,
negative tests or independently selected qualification work. It must not enter
the default owner-open product graph through feature unification, an implicit
binary target, a packaging wildcard, a test dependency or a transitive default
feature.

Compiling a sealed component does not reactivate it.

## 5. Tests and feature matrices

The baseline local command for each Cargo component is:

```sh
cargo test --locked -p <package-name> --all-targets
```

Feature-gated product, compatibility and conformance lanes add their explicit
feature set. They never rely on `--all-features` where mutually exclusive or
retired authorities exist.

CI reports skipped tests separately. A skipped target-specific test is not a
pass for its target evidence level.

## 6. Promotion, replacement and removal

Promoting a sealed component into the active graph requires all of:

1. an update to the module catalog and lifecycle inventory;
2. a component-local guide describing the new authority boundary;
3. dependency and feature-unification proof;
4. exact-head source qualification;
5. non-author review;
6. the installed, Android, device, fault or release evidence required by the
   affected gap.

Removal requires proving that no active build, packaging, schema, migration or
evidence verifier depends on the component. Git history remains the recovery
source; retired source is not kept merely to make an old test green.

## 7. Evidence ceiling

Component documentation and source tests establish repository-controlled source
properties only. They do not establish installed Root Linux identity, Android
target-files, physical-device behavior, destructive-fault recovery, signing,
OTA or public-release authority.

An uncertain effect is never automatically redispatched.

## 8. Dependency and Markdown verification boundary

The component gate derives module ownership from catalog paths, never from a
README's self-declared links. It checks local Cargo dependencies in package,
workspace-inherited and target-specific tables, including renamed, optional,
build and development dependencies. Every local producer must remain in the
same isolated product closure, and every cross-module edge must be declared by
a consumer owner. For the Host's two-module composition crate, each Cargo edge
must be declared by at least one owner; this does not identify which Rust file
imports the dependency. Cargo's resolved feature/target checks remain necessary.

The two `planned/Cargo.toml` members have separate README commands that select
that manifest explicitly. They are checked for ownership, documentation and
local dependency projection without joining the root default product graph.

Commands must be complete lines inside a visible shell fence; module links must
resolve to canonical module documents. The accepted Markdown subset rejects raw
HTML block openers outside fenced examples, including generic `div`/`table` and
custom tags, declarations, processing instructions and CDATA. It accepts normal
inline HTML within a prose line. This explicit subset avoids treating raw HTML
contents as usable Markdown commands or links. Comments and code examples never
supply navigation requirements. These source checks do not prove all narrative
engineering details; reviewers still check the required explanations in section 2.

The reverse source inventory checks Rust and other source files in active/default
components, both planned components, and selected support trees (`tools/owner-open`,
`tools/evidence`, `tools/build`, Root Linux/ADB packaging and the owned Android overlay). Every
such file has exactly one catalog module owner; adding a file next to an owned
file cannot silently escape the inventory. Host integration tests have the core
composition owner. Ownership includes explicitly retained historical variants
without activating them. Other repository tooling is covered by its own build,
test and governance checks; this inventory does not claim a Python import graph
for every script in the repository.
