"""Exact historical proof copies. Current source and actual compiled bodies remain intact."""
import hashlib
PORT = '    /** Fail-only legacy boundary. The dedicated Ctrip bridge compiles the actual helper. */\n    private PostEffectChildWindowCheck recheckPostEffectChildWindow(ObservationRequest request,ObservationProduct product,\n            ObservationEventWatermark pairStart,StaleObservation failure){return null;}\n'
OLD_TEMPLATE = '7f78539e600115f929a743b0e36e4399227faaae2701af64ba2482c122634b6f'
NEW_TEMPLATE = 'fb3fb74feb4e7e67a16953ae80b00a51bdd34a31b0fb799dabc274d8368300ba'
OLD_ACCEPT = '7a62dfd2705982b6cfe0e1d4d9731d665ec0349aa23708e7740ba3238053a058'
NEW_ACCEPT = 'f5c0cc3c284f2b6125a4d8adaaf5781843cf97b8faa9ec5742cef98920a372ca'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def template_predecessor(raw):
    if sha(raw)==OLD_TEMPLATE:return raw
    if sha(raw)!=NEW_TEMPLATE or raw.count(PORT.encode())!=1:raise RuntimeError("unknown complete child-identity template")
    prior=raw.replace(PORT.encode(),b"",1)
    if sha(prior)!=OLD_TEMPLATE:raise RuntimeError("child-identity fail-only port inverse mismatch")
    return prior
def accept_predecessor(raw):
    if sha(raw)==OLD_ACCEPT:return raw
    marker=b"request.postEffectChildDiagnostic.finish();"
    if sha(raw)!=NEW_ACCEPT or raw.count(marker)!=1:raise RuntimeError("unknown complete publication body")
    prior=raw.replace(marker,b"",1)
    if sha(prior)!=OLD_ACCEPT:raise RuntimeError("diagnostic terminal freeze inverse mismatch")
    return prior
