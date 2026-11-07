# Phone-local provider v150-r6: health owner encoding compatibility

This isolated revision fixes the original health01 terminal-validation crash in provider-r5. Its original model request used the already frozen r5 minimal health layout: the last user message contains a plain string. The old health_contracts.terminal_evidence implementation indexed content[0] as a dictionary, so the first character triggered AttributeError at frozen line167 after the model had produced its correct nonce.

Only source/health_contracts.py changes. It requires a user-message object, then accepts a complete plain string or exactly one typed text part. Either encoding must hash to the exact one-use owner request. No text is inferred or corrected. The nonce remains a free model string checked for exact equality; schema, one-use claim, zero-tools, one original HTTP attempt, stopped response, response/decision bytes, worker join, slot idle and all other production guards remain unchanged.

The other twelve production files, four operator helpers, runtime configuration bytes and fixed19 protocol are identical to provider-r5. The code is installed under provider-r6/source with a separate local-config-r6.json target; both share the existing provider-state. Every original claim/binding/ledger item must remain. The current previous task is the actual failed health01, subject to its separately verified zero-tool closure; do not use the older component03 selection.

## Evidence and limits

- Frozen provider-r5 source seal: f3685aadb004882a3f087e42d43d374bd24564ad56eb472cb638b2f88e96935f.
- Health01 original request-body SHA: <INSTANCE_BINDING_SHA256_REQUIRED>.
- Host-only reproduction retains the old AttributeError stack with line167. It is explicitly a host reproduction of the original input, not a fabricated phone stack.
- Ten focused host checks use copied originals or clearly named synthetic mutations. They cover correct plain string, single text-part compatibility, changed owner, malformed/extra content, wrong nonce, duplicate HTTP attempt, unjoined worker and busy slot.
- The first host test wrapper used the wrong Python exception class for negative cases. That failed attempt remains preserved. The corrected run02 catches the actual frozen ProviderError, passes10/10 and leaves production source unchanged.
- Revalidating the old HTTP originals with this candidate does not rewrite the old native outcome. Health01 stays provider_failed. A wholly fresh nonce and request is required after the new module/source combination is installed and ready.

No phone operation, model request, new nonce, task submission or existing production evidence mutation was performed while building this revision. Native/business/fixed19/fold/coldboot qualifications remain separate actual observations.

## Deployment

The phone payload contains provider-r6/source and the unchanged operator helpers/protocol, the new seal/README/diff, and local-config-r6.json. Runtime binaries, model weights, executor/client, service inputs and all private keys remain separate unchanged inputs. The config holds only the existing private key file pointer; no key file or key-content digest is included.

The start argv is recorded exactly in SOURCE-SEAL-v150-r6.json. It changes only provider-r5/source to provider-r6/source and local-config-r5.json to local-config-r6.json. Root owns installation, service retirement/startup, every fresh request, and actual qualification.
