# Trillionnium OS Team and Delivery Model

Status: **NORMATIVE**

## 1. Organizational model

Engineers have one primary module assignment. Modules have at least a primary
and backup team. Critical contracts, state and deployment paths require
cross-module review.

Suggested logical teams are recorded in `machine/module-catalog.v1.json`.
GitHub CODEOWNERS may temporarily use individual maintainers until organization
teams are provisioned, but the module catalog remains the organizational model.

## 2. Review classes

| Class | Change | Required review |
| --- | --- | --- |
| D0 | wording or link with no semantic/state effect | module owner |
| D1 | module-internal implementation | primary + backup maintainer |
| D2 | cross-module API or state schema | producer + consumer + compatibility reviewer |
| D3 | concurrency, persistence, resource or lifecycle semantics | module + architecture + performance |
| D4 | semantic authority or Effect invariant | semantic authority + security |
| D5 | evidence, release or claim ceiling | evidence governance + independent reviewer |

Changes are classified by effect, not by file extension.

## 3. Branch and PR model

After the current stacked integration is consolidated, normal development uses
short-lived module branches and a protected merge queue.

```text
module branch
 -> module tests and benchmark
 -> contract and compatibility tests
 -> speculative merge-queue head
 -> system and exact-head checks
 -> protected trunk
```

Long-lived version-number branches are not an integration strategy. A historical
green run never validates a changed head.

## 4. PR contract

Every behavior-affecting PR states:

- affected modules and requirements;
- API/state compatibility;
- ordering and concurrency impact;
- resource-budget delta;
- failure and rollback behavior;
- tests and workload results;
- gaps moved and evidence level;
- explicit negative claims.

A generated status edit without source or evidence is not a valid promotion.

## 5. CODEOWNERS and independence

CODEOWNERS routes review but does not itself prove independence. Integration
approval must be from a non-author on the exact current head. Evidence producer,
target operator, reviewer and release authorizer are separated where the level
requires it.

Any behavior-changing push invalidates stale approvals.

## 6. Architecture decisions

A new module, dependency direction, control authority, incompatible protocol,
global-objective weight family or hard-constraint change requires an ADR or an
update to the corresponding normative global document.

Architecture review decides boundaries and constraints, not every local
implementation detail.

## 7. Documentation changes

Machine truth changes and generated views are atomic:

```text
machine JSON
 + source/contract update
 + generator output
 + verifier tests
 + exact-head evidence
```

Generated files are never hand-edited. Historical documents are recovered only
through Git history and cannot be restored as active authority without a new,
explicit architecture decision.

## 8. Knowledge resilience

Every critical module maintains:

- primary and backup maintainers;
- current runbook;
- state and protocol diagrams;
- development and fault reproduction commands;
- on-call and rollback ownership;
- at least one reviewer outside the primary author group.

A module is not team-scalable until another maintainer can qualify and recover it.
