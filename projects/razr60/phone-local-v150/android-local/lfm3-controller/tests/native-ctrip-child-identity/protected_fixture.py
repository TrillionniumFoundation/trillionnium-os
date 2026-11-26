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
def sha(raw):return hashlib.sha256(raw).hexdigest()
READ_DIAGNOSTIC_TEMPLATE = 'ea4bfcbb24a933fe585b89c617c8c2444f0ca1f1565d1dddba53f8c1de49bfa6'
TYPED_STALE_PORT = '    // Explicit Android read-failure port. Existing one-argument callers remain untyped.\n    static final class StaleObservation extends IllegalStateException {\n        private static final long serialVersionUID=1L;final boolean backgroundChildUnavailable;\n        StaleObservation(String message){this(message,false);}\n        StaleObservation(String message,boolean childUnavailable){super(message);backgroundChildUnavailable=childUnavailable;}\n    }\n'
READ_DIAGNOSTIC_TYPED_STALE_PORT = '    // Explicit Android read-failure port. Existing one-argument callers remain untyped.\n    static final class StaleObservation extends IllegalStateException {\n        private static final long serialVersionUID=1L;final boolean backgroundChildUnavailable;final String backgroundChildPath;\n        StaleObservation(String message){this(message,false);}\n        StaleObservation(String message,boolean childUnavailable){this(message,childUnavailable,null);}\n        StaleObservation(String message,boolean childUnavailable,String path){super(message);backgroundChildUnavailable=childUnavailable;backgroundChildPath=path;}\n    }\n'
BACK_READ_TEMPLATE = 'a7ec7dcd36a7e15ab3f5a97606a1082b341cd94e6069ae047281da573e3291ab'
BACK_READ_TYPE_PORTS = '        // Type-only BACK ABI. The original synthetic OPEN IO carrier remains below.\n        static abstract class PostActionReadAccess {\n            private PostActionReadAccess(){}\n            abstract void requireCurrent();\n            abstract long transitionDeadline();\n            abstract void requireOwner(NativeAppSession owner,Object authorization,String task,Object selection,String generation,int display);\n            abstract void admit(boolean retry);\n            abstract boolean admitted(boolean retry);\n        }\n        static final class CalendarBackReadPermit extends PostActionReadAccess {\n            private CalendarBackReadPermit(){throw new AssertionError("BACK authority unavailable in observer-only fixture");}\n            void requireCurrent(){throw new AssertionError("BACK authority unavailable in observer-only fixture");}\n            long transitionDeadline(){throw new AssertionError("BACK authority unavailable in observer-only fixture");}\n            void requireOwner(NativeAppSession owner,Object authorization,String task,Object selection,String generation,int display){throw new AssertionError("BACK authority unavailable in observer-only fixture");}\n            void admit(boolean retry){throw new AssertionError("BACK authority unavailable in observer-only fixture");}\n            boolean admitted(boolean retry){throw new AssertionError("BACK authority unavailable in observer-only fixture");}\n        }\n'
BACK_POST_ORIGINAL = '        static final class PostEffectReadPermit {'
BACK_POST_EXTENDED = '        static final class PostEffectReadPermit extends PostActionReadAccess {'

def template_before_back_read_types(raw):
    # Historical proof only. Actual observer compilation keeps both closed ABI types.
    if sha(raw)==BACK_READ_TEMPLATE:
        if raw.count(BACK_READ_TYPE_PORTS.encode())!=1 or raw.count(BACK_POST_EXTENDED.encode())!=1:
            raise RuntimeError("exact closed BACK ABI and original OPEN carrier required")
        raw=raw.replace(BACK_READ_TYPE_PORTS.encode(),b"",1).replace(
            BACK_POST_EXTENDED.encode(),BACK_POST_ORIGINAL.encode(),1)
        if len(raw)!=38719 or sha(raw)!=READ_DIAGNOSTIC_TEMPLATE:
            raise RuntimeError("whole pre-BACK observer template inverse mismatch")
    return raw

def template_before_read_diagnostics(raw):
    raw=template_before_back_read_types(raw)
    # Proof copy only. Actual compilation keeps the complete three-argument port.
    if sha(raw)==READ_DIAGNOSTIC_TEMPLATE:
        if raw.count(READ_DIAGNOSTIC_TYPED_STALE_PORT.encode())!=1:raise RuntimeError("exact typed diagnostic path port required")
        raw=raw.replace(READ_DIAGNOSTIC_TYPED_STALE_PORT.encode(),TYPED_STALE_PORT.encode(),1)
        if sha(raw)!=COHERENT_TEMPLATE:raise RuntimeError("typed diagnostic path whole template inverse mismatch")
    return raw
PIXEL_TEMPLATE='8f66a666795ee827c9baea55342f96862ccb2d891cbd9c79abc2f813714be212'
PIXEL_TEMPLATE_PREDECESSOR='a7ec7dcd36a7e15ab3f5a97606a1082b341cd94e6069ae047281da573e3291ab'
PIXEL_PHONE_OVERLOAD='        PhoneObservation(String id,String pkg,long captured,int width,int height,int rotation,int window,Rect bounds,\n            File path,String hash,String digest,Object state,Object metadata,boolean truncated,Object rows,String generation,String initial,List<String> packages,Object collectionStats,JSONObject selection,String ownerSha,Map<String,Object> captureEvidence,WindowOwnership profile,\n            ObservationCaptureEvidence capture,PixelNativeCensusEvidence companion){\n            this(id,pkg,captured,width,height,rotation,window,bounds,path,hash,digest,state,metadata,truncated,rows,generation,initial,packages,collectionStats,selection,ownerSha,captureEvidence,profile);\n            if(capture!=null||companion!=null)throw new AssertionError("legacy observer cannot publish typed companion authority");\n        }\n'

def template_predecessor(raw):
    if sha(raw)==PIXEL_TEMPLATE:
        changed=raw.decode()
        original='    static final class PhoneObservation {\n        final String id;final File path;final long capturedElapsedMillis;final Object collectionStats;\n        final Map<String,Object> captureEvidence;\n        PhoneObservation(String id,String pkg,long captured,int width,int height,int rotation,int window,Rect bounds,\n            File path,String hash,String digest,Object state,Object metadata,boolean truncated,Object rows,String generation,String initial,List<String> packages,Object collectionStats,JSONObject selection,String ownerSha){\n            this(id,pkg,captured,width,height,rotation,window,bounds,path,hash,digest,state,metadata,truncated,rows,generation,initial,packages,collectionStats,selection,ownerSha,null);\n        }\n        PhoneObservation(String id,String pkg,long captured,int width,int height,int rotation,int window,Rect bounds,\n            File path,String hash,String digest,Object state,Object metadata,boolean truncated,Object rows,String generation,String initial,List<String> packages,Object collectionStats,JSONObject selection,String ownerSha,Map<String,Object> captureEvidence){\n            this(id,pkg,captured,width,height,rotation,window,bounds,path,hash,digest,state,metadata,truncated,rows,generation,initial,packages,collectionStats,selection,ownerSha,captureEvidence,null);\n        }\n        PhoneObservation(String id,String pkg,long captured,int width,int height,int rotation,int window,Rect bounds,\n            File path,String hash,String digest,Object state,Object metadata,boolean truncated,Object rows,String generation,String initial,List<String> packages,Object collectionStats,JSONObject selection,String ownerSha,Map<String,Object> captureEvidence,WindowOwnership profile){\n            if(profile!=null)throw new AssertionError("legacy observer cannot publish profile authority");\n            this.id=id;this.path=path;capturedElapsedMillis=captured;this.collectionStats=collectionStats;\n            this.captureEvidence=captureEvidence;\n        }\n            PhoneObservation(String id,String pkg,long captured,int width,int height,int rotation,int window,Rect bounds,\n            File path,String hash,String digest,Object state,Object metadata,boolean truncated,Object rows,String generation,String initial,List<String> packages,Object collectionStats,JSONObject selection,String ownerSha,Map<String,Object> captureEvidence,WindowOwnership profile,\n            ObservationCaptureEvidence capture,PixelNativeCensusEvidence companion){\n            this(id,pkg,captured,width,height,rotation,window,bounds,path,hash,digest,state,metadata,truncated,rows,generation,initial,packages,collectionStats,selection,ownerSha,captureEvidence,profile);\n            if(capture!=null||companion!=null)throw new AssertionError("legacy observer cannot publish typed companion authority");\n        }\n    }'
        if changed.count(original)!=1:raise RuntimeError("complete refusing pixel carrier overload required")
        changed=changed.replace(original,'    static final class PhoneObservation {\n        final String id;final File path;final long capturedElapsedMillis;final Object collectionStats;\n        final Map<String,Object> captureEvidence;\n        PhoneObservation(String id,String pkg,long captured,int width,int height,int rotation,int window,Rect bounds,\n            File path,String hash,String digest,Object state,Object metadata,boolean truncated,Object rows,String generation,String initial,List<String> packages,Object collectionStats,JSONObject selection,String ownerSha){\n            this(id,pkg,captured,width,height,rotation,window,bounds,path,hash,digest,state,metadata,truncated,rows,generation,initial,packages,collectionStats,selection,ownerSha,null);\n        }\n        PhoneObservation(String id,String pkg,long captured,int width,int height,int rotation,int window,Rect bounds,\n            File path,String hash,String digest,Object state,Object metadata,boolean truncated,Object rows,String generation,String initial,List<String> packages,Object collectionStats,JSONObject selection,String ownerSha,Map<String,Object> captureEvidence){\n            this(id,pkg,captured,width,height,rotation,window,bounds,path,hash,digest,state,metadata,truncated,rows,generation,initial,packages,collectionStats,selection,ownerSha,captureEvidence,null);\n        }\n        PhoneObservation(String id,String pkg,long captured,int width,int height,int rotation,int window,Rect bounds,\n            File path,String hash,String digest,Object state,Object metadata,boolean truncated,Object rows,String generation,String initial,List<String> packages,Object collectionStats,JSONObject selection,String ownerSha,Map<String,Object> captureEvidence,WindowOwnership profile){\n            if(profile!=null)throw new AssertionError("legacy observer cannot publish profile authority");\n            this.id=id;this.path=path;capturedElapsedMillis=captured;this.collectionStats=collectionStats;\n            this.captureEvidence=captureEvidence;\n        }\n    }',1)
        raw=changed.encode()
        if sha(raw)!=PIXEL_TEMPLATE_PREDECESSOR:raise RuntimeError("whole pixel carrier inverse mismatch")
    raw=template_before_read_diagnostics(raw)
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
