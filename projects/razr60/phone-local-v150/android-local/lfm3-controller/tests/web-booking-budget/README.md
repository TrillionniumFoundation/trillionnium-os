# Bounded booking document observation

Only the recognized booking-body pending phase uses the existing 16-second city
budget instead of six seconds. Initial document and shopping budgets remain 32
seconds; calendar/query remain six seconds. The phase is created once per page
identity, capped by the original task deadline, with at most two read-only extra
observations. Existing cancellation, ownership, lease and full capture checks stay
intact. No action is replayed and no model or task budget is increased.

The exact old/new production observe, retryLoadingDocument, sameFrame and
loadingKey methods were extracted and executed in the host harness. It uses two
explicit retained DOM captures (52-node shell and 795-node form) with the real
booking detector and full DOM proof replay. AX metadata, clock, native authority,
IPC and future read sequence are simulated. The 7312 ms future pair is a stated
cost model using a measured 2680 ms capture/ACK interval, not a phone replay or
proof of an eventual successful flight task.

Baseline: the complete pair is rejected at the six-second deadline, while eight
boundary cases / 39 assertions pass. Candidate: nine cases / 45 assertions pass.
The existing readiness gate also passes 18 cases / 129 assertions. Its historical
baseline is separate from the cface booking-budget counterfactual. Receipts retain
these distinctions. Integration rechecks all input hashes; it does not rerun the
same gates or count them as business successes.

Reproduce with run_budget_host.py and explicit --source, --baseline-session,
--output, --java-home, --json-jar, --pending-capture and --ready-capture arguments.
The runner requires the hashes listed in its source. Retained private captures
are not redistributed. Keep outputs outside the source tree. The published
template only corrects its introductory comment to name synthetic AX metadata;
test code and assertions remain byte-identical to the executed template.
