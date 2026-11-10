# Owner tool authorization (v37)

The ordinary user task entry now derives an immutable tool contract from the exact
Owner instruction before reserving a task. This closes the observed gap where a
local model could ignore “find first” or propose a click despite “do not click”.
It does not establish that the model understands every natural-language condition
or that a permitted action achieved the user's business goal.

## Supported instruction clauses

The parser is deliberately limited to documented Chinese tool and method clauses.
The UI shows the tool permissions it recognized before Start, and shows a refusal
reason for ambiguous or unsupported clauses that the parser identifies.

- Closed lists such as `只查找、打开和结束` and `本任务只允许查找、打开和结束`.
- Direct prohibitions such as `不点击、不输入`, `禁止点击、输入`, and `不要直接输入答案`.
- A single explicit lookup sequence, for example `先只读查找手机上安装的时钟应用，再打开它`
  or `请先使用本机应用查找工具find_app搜索‘计算器’，再从查找结果打开计算器`.
  It must identify the installed-application domain through an app/APP marker,
  an installed-app qualifier, or the explicit `find_app` tool. Searching for
  flights, goods or document content does not create an installed-app prerequisite.
  Method recognition excludes quoted payload. A literal quoted app query remains
  available from the corresponding original instruction span after the unquoted
  method has been recognized.
- A method clause such as `使用计算器按键计算…` prohibits the `type` tool, which
  replaces text. It leaves observed key clicks available; it never chooses a key
  or computes the expected answer on behalf of the model.

The tool vocabulary is `find_app`, `open`, `click`, `type`, `scroll`, `back`,
`home`, `wait`, and `done`, with the aliases in `TaskAuthorization.java`.
Unknown items in an explicit tool allowlist, conflicting permission clauses,
recognized double negatives, ambiguous quoted tool restrictions, and unsupported
lookup ordering are refused before task reservation. Unconstrained ordinary
instructions retain the existing tool set. The UI summary is not a claim that
all other semantics in arbitrary prose have been parsed.

The Clock regression instruction yields only `find_app`, `open`, and `done`, and
the literal lookup query `时钟`. No Clock package is hardcoded. The broader
instruction about alarms and timers is not a general semantic policy compiler;
this particular task's narrow tool set excludes the offending click/type path.

## Enforcement and task lifetime

`MainActivity.beginTask` parses the actual user text. `LocalTaskSession.schedule`
checks the same instruction hash and saves the contract before its durable pending
reservation. The delayed callback captures that exact immutable contract.
`LocalTaskController` binds a new service-owned Gate to its new task ID before
starting any inference.

The current Gate frame narrows the real GBNF and the parser policy. A forbidden
but syntactically valid action is a terminal authorization violation, not a format
repair opportunity. `HeptaAccessibilityService` checks the captured Gate at main
thread entry and again immediately before each effect API. The existing scope,
stale-observation, persistent-action and cancellation checks remain active.
The current qualification scope also intersects the open-package projection, so
the grammar does not offer an open target the bound scope is known to forbid.

For a required lookup sequence, the initial application catalogue is not a lookup
proof. Only a successful same-task call to the actual local `find_app` search can
record results, with the Owner-derived query, exact catalogue hash, offset and
model-run ID. `open` is limited to that real result page. A model's reason text,
an earlier task, or a different query cannot grant permission. Other effect tools
cannot bypass this initial sequence via a launcher icon. An actual open dispatch
records a pending target; only a subsequent real observation of that target
unlocks success `done`. Partial/failure completion and user Stop remain available.

Release retires the old Gate. A late callback keeps its original Gate and actual
`dispatched` value, but cannot be accepted for a new lease or write a new Gate's
proof. Delayed type readback does not read the retired node.

## Evidence contract

The fixed contract schema is `hepta.owner-task-authorization.v1`, parser
`hepta.owner-tool-clauses.zh.v2`. It contains `instruction_sha256`,
`authorization_sha256`, sorted `allowed_tools`,
`require_find_app_before_open`, `find_query`, `recognized_rules`, and the explicit
`arbitrary_semantic_constraints_verified=false` boundary.

The contract digest is SHA-256 over UTF-8 records `byte_length:value\n`, in this
order: schema, parser, exact instruction SHA-256, each sorted allowed tool,
`true`/`false` for required lookup, then the query or the empty string. It is not a
hash of a serializer-dependent JSON string.

- Session pending/terminal and `owner.json` retain the fixed contract and digest.
- The model prompt contains an immutable current Frame, including task ID, real
  discovery run, result packages, observed opened package and success permission.
- Each action receipt contains the Gate evidence and captured callback lease
  status. Its `last_check` has schema `hepta.owner-action-check.v1`, task ID,
  authorization digest, model-run ID, action, target package and actual decision.
- Scope-observation evidence includes the same task's authorization state next to
  the original observation. `result.json` preserves the final Gate evidence.

Native receipt, exact prompt/token binding, accelerator, cleanup, background and
independent goal checks remain separate. The new contract never upgrades old
phone results or turns a model's success claim into independent goal proof.

## Host verification

`tests/owner-authorization/run_host_tests.py` executes extracted actual service,
ordinary UI and session methods plus the full production Controller with explicit
Android/model IO fixtures. `tests/owner-grammar/run_host_tests.py` emits actual
Java GBNF in five authorization states and checks it using the existing independent
GBNF recognizer. Both accept `--release8` and are included in the full host gate.
The full gate retains `--release 8`, `-Xlint:all` and `-Werror`.

The development executor has a stripped Java 21 installation without the Java 8
API image. Supplemental source/target-8 tests are explicitly labeled; they do not
replace the complete JDK 17 release/API gate, Android build, or phone acceptance.
The genuine local full-gate capability failure is retained. No task, model run or
phone operation is performed by these host tests.

`tests/TaskAuthorizationDomainHostTest.java` exercises 25 content/domain cases
against the real production parser and its actual Gate frame. It is automatically
included by the full host runner's `*HostTest.java` inventory. The former parser
fails the flight-content regression. The v37 parser preserves the constrained
Clock lookup, quoted application queries, existing tool prohibitions and rejection
of unsupported explicit app-lookup order. See `CODE37-TASK-AUTHORIZATION.md`.
