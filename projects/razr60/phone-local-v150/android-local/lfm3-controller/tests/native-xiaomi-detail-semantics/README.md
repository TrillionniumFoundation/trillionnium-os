# Detail price semantics increment

This directory contains the additional synthetic price-role regression for the
reviewed mirrored-price detail layout. It reuses the unchanged public
104-node/60-projection fixture and Fixture builder from
tests/native-xiaomi-detail-mirror. Identities and signatures are synthetic and
private fields are redacted; this fixture is not an original device observation.

The final matrix has four allowed cases: the original ranking “1” and conditions,
“评价1”, “性价比高”, and the existing installment-reduction condition. Ten
refused cases cover currency-free coupon/current/original prices, monthly or
per-period payments, split price captions and amounts, and label-only prices.
Existing promotions remain conditions and are never subtracted from the amount.
No bare-number or single-character “价” predicate is introduced.

run_host.py --source ABS --output FRESH_ABS --java-home ABS --json-jar ABS
--mode current compiles the actual production parser and its pure dependencies.
It does not run the old 83-case suite, Android, a model or an action. Baseline
mode requires the exact preceding production source. The preserved original
baseline report has twelve cases and predates the two new current/original-price
cases: eight preceding-parser acceptance bugs were executed and observed.

protected_price_semantics.py proves the final complete parser bytes back to the
exact preceding mirrored-detail parser. Apply this proof before the existing
protected_detail_mirror predecessor proof; compile current production unchanged.
This overlay does not edit the old predecessor helper or public fixture.

Private step-4/step-5 replay drivers, archive paths, inputs and results live
outside source. They must not be included in repository or public CI inputs.
Their host results verify parsing against original complete frames, not a new
Android business result.
