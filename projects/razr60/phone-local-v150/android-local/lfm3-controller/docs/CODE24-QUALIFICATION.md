# Code24: readable recorded actions and truthful capability prompts

## Problem and change

The previous prompt represented recorded actions using multiple indexed dictionaries and compact rows. When the history projection exceeded its own byte allowance, it could omit the clicked label, typed text or query. A small local model then had to reconstruct task progress from an unfamiliar encoding and incomplete action arguments. Code24 presents the recorded actions in chronological readable objects, preserves recorded argument facts, and does not silently reduce their detail to fit the context. The existing context admission and exact native token checks still decide whether a request fits.

The prompt previously labelled some observed nodes with capabilities that the decision grammar would later exclude because the node was disabled, sensitive or belonged to another package. Code24 derives prompt capabilities and scroll directions from the same eligibility conditions as the current decision grammar. A historical node or a visible but ineligible node grants no action authority.

## Preserved boundaries

The package is `org.trillionnium.hepta.local`, versionCode 24. The ordinary controller still uses the configured local text model and the pinned GenieX/llama.cpp runtime. It does not acquire a network permission, add an external provider, automatically switch models, or connect the separate visual diagnostics to phone actions. Existing strict action parsing, freshness checks, cancellation, process ownership and recovery remain in force.

Model-reported completion remains distinct from independently verified goal completion. No result flag or test assertion is relaxed. Phone evidence may contain private screen contents and is excluded from source control.

## Qualification

Host tests, Android compilation, signed APK identity, installed identity, real model/offload evidence, functional phone tasks and lifecycle/thermal tests are separate results. The existing nine-case core suite provides independent goal predicates. It is run against the exact installed APK and configuration; historical results do not qualify Code24.

This source document describes a candidate. It does not claim a completed production release. Refer to the dated external execution report for actual test outcomes and remaining blockers.
