"""Exact historical proof copies. Current source and actual compiled bodies remain intact."""
import hashlib
PORT = '    /** Fail-only legacy boundary. The dedicated Ctrip bridge compiles the actual helper. */\n    private PostEffectChildWindowCheck recheckPostEffectChildWindow(ObservationRequest request,ObservationProduct product,\n            ObservationEventWatermark pairStart,StaleObservation failure){return null;}\n'
OLD_TEMPLATE = '7f78539e600115f929a743b0e36e4399227faaae2701af64ba2482c122634b6f'
NEW_TEMPLATE = 'fb3fb74feb4e7e67a16953ae80b00a51bdd34a31b0fb799dabc274d8368300ba'
OLD_ACCEPT = '7a62dfd2705982b6cfe0e1d4d9731d665ec0349aa23708e7740ba3238053a058'
NEW_ACCEPT = 'f5c0cc3c284f2b6125a4d8adaaf5781843cf97b8faa9ec5742cef98920a372ca'
DIAGNOSTIC_PORTS = '    /** Diagnostic-only legacy ports. They cannot classify a form, alter events,\n     * grant an input, or publish. The dedicated observer bridge replaces this\n     * complete block with the actual production helpers/provider constants. */\n    private static final class NativeCtripFlightPage {static final String PACKAGE="ctrip.android.view";}\n    private static List<Long> ctripDiagnosticMark(ObservationEventWatermark mark){return null;}\n    private static Map<String,Object> ctripSavedGraphGate(ObservationRequest request,CaptureIdentity identity,\n            ObservationProduct product,ObservationEventWatermark persisted,boolean scoped,boolean complete,boolean retry){return null;}\n    private static void recordCtripFormGate(ObservationRequest request,String reason,String stage,IllegalArgumentException failure){}\n'
COHERENT_TEMPLATE = 'fa4359f1b523ead7b8c9373e9fb8c625f09a4f51a9189cbc6af9443538cf020e'
COHERENT_ACCEPT = '272b52c9de2479a6569d92999d3f9c71d5876dd15d1bee92e3f61384984f9fd2'
BOUNDED_STALE_TEMPLATE = 'ea4bfcbb24a933fe585b89c617c8c2444f0ca1f1565d1dddba53f8c1de49bfa6'
BOUNDED_STALE_PORT = '    static final class StaleObservation extends IllegalStateException {\n        private static final long serialVersionUID=1L;final boolean backgroundChildUnavailable;final String backgroundChildPath;\n        StaleObservation(String message){this(message,false);}\n        StaleObservation(String message,boolean childUnavailable){this(message,childUnavailable,null);}\n        StaleObservation(String message,boolean childUnavailable,String path){super(message);backgroundChildUnavailable=childUnavailable;backgroundChildPath=path;}\n    }\n'
PREVIOUS_STALE_PORT = '    static final class StaleObservation extends IllegalStateException {\n        private static final long serialVersionUID=1L;final boolean backgroundChildUnavailable;\n        StaleObservation(String message){this(message,false);}\n        StaleObservation(String message,boolean childUnavailable){super(message);backgroundChildUnavailable=childUnavailable;}\n    }\n'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def template_predecessor(raw):
    # The diagnostic child path is data only. Prove the entire current template
    # inverts to the already accepted predecessor; all unknown bytes still refuse.
    if sha(raw)==BOUNDED_STALE_TEMPLATE:
        if raw.count(BOUNDED_STALE_PORT.encode())!=1:raise RuntimeError("exact bounded stale diagnostic port required")
        raw=raw.replace(BOUNDED_STALE_PORT.encode(),PREVIOUS_STALE_PORT.encode(),1)
        if sha(raw)!=COHERENT_TEMPLATE:raise RuntimeError("bounded stale template whole inverse mismatch")
    if sha(raw)==COHERENT_TEMPLATE:
        if raw.count(DIAGNOSTIC_PORTS.encode())!=1:raise RuntimeError("exact diagnostic-only template block required")
        raw=raw.replace(DIAGNOSTIC_PORTS.encode(),b"",1)
        if sha(raw)!=NEW_TEMPLATE:raise RuntimeError("coherent diagnostic template whole inverse mismatch")
    if sha(raw)==OLD_TEMPLATE:return raw
    if sha(raw)!=NEW_TEMPLATE or raw.count(PORT.encode())!=1:raise RuntimeError("unknown complete child-identity template")
    prior=raw.replace(PORT.encode(),b"",1)
    if sha(prior)!=OLD_TEMPLATE:raise RuntimeError("child-identity fail-only port inverse mismatch")
    return prior
def accept_predecessor(raw):
    if sha(raw)==COHERENT_ACCEPT:
        marker=b"request.ctripReadDiagnostic.finish();"
        if raw.count(marker)!=1:raise RuntimeError("one exact current diagnostic finish required")
        raw=raw.replace(marker,b"",1)
        if sha(raw)!=NEW_ACCEPT:raise RuntimeError("coherent diagnostic finish whole inverse mismatch")
    if sha(raw)==OLD_ACCEPT:return raw
    marker=b"request.postEffectChildDiagnostic.finish();"
    if sha(raw)!=NEW_ACCEPT or raw.count(marker)!=1:raise RuntimeError("unknown complete publication body")
    prior=raw.replace(marker,b"",1)
    if sha(prior)!=OLD_ACCEPT:raise RuntimeError("diagnostic terminal freeze inverse mismatch")
    return prior
