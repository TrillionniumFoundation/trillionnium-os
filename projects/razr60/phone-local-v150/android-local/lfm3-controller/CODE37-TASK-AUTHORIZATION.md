# v37: distinguish app discovery from app content

Version: `37` / `0.37.0-local-task-authorization`.

## Reproduced failures

The v36 production parser interpreted `先在携程查找明天北京到上海的机票，然后打开最便宜的航班查看详情。`
as an obligation to call `find_app` with query `明天北京到上海的机票`. It likewise
treated `先查找蓝牙耳机，再打开价格最低的商品。` as installed-app discovery.
The background entry refuses a pre-open lookup contract, while foreground
execution cannot satisfy it by searching actual flight/product content.

The sequence scanner also consumed quoted note content. For example,
`在备忘录写下“先查找客户，再打开文档”并保存。` acquired an unintended
`find_app(客户)` prerequisite.

## Change

Sequence recognition now uses the existing quote-masked instruction, whose UTF-16
positions match the original text. Only an explicit application/tool domain
creates an installed-app lookup prerequisite. The literal query is recovered
from that exact original span, so `先查找“时钟”应用，再打开它` retains query
`时钟` and the same discovery/open enforcement.

The parser identity is `hepta.owner-tool-clauses.zh.v2`. The contract schema stays
`hepta.owner-task-authorization.v1` because its fields are unchanged. The parser
identity participates in the contract digest, so the new interpretation is not
presented as the old contract.

The parser remains a bounded compiler for documented tool clauses. It does not
prove arbitrary business semantics. In particular, successful task completion
still requires separate evidence from the relevant app.

## Regression and qualification

`tests/TaskAuthorizationDomainHostTest.java` is a production-class regression
included in the existing full host gate. Its cases cover the two reproduced
failures, nested quoted text, app/content distinctions, preserved quoted app
queries, installed-app qualifiers, explicit `find_app`, the existing restricted
Clock task, and conflicting/unsupported explicit tool clauses.

The initial local verification compiles the actual five-class dependency closure
and uses Java 8 source/target on the available JDK 21. It is supplemental host
verification. The independent full JDK `--release 8` gate, Android rebuild,
installed APK identity, model inference and device task acceptance must be
recorded separately for v37. No result from the previous APK is inherited.
