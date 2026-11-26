#!/usr/bin/env python3
"""Execute the production AX empty-loading path with the actual profile guards.
Android collection and broker transport stay explicit host fixtures; no phone I/O.
The original AX suite runs in the same compilation before the new cases.
"""
import importlib.util
from pathlib import Path

HERE=Path(__file__).resolve().parent
PKG=Path('src/org/trillionnium/hepta/local')
spec=importlib.util.spec_from_file_location('empty_loading_ax_base',HERE/'run_host.py')
ax=importlib.util.module_from_spec(spec)
spec.loader.exec_module(ax)
BASE_GENERATE=ax.generate

def generate(source,out,h,snap):
    meta=BASE_GENERATE(source,out,h,snap)
    path=out/'ObserverPipelineHost.java'
    text=path.read_text()
    service=(source/PKG/'HeptaAccessibilityService.java').read_text()
    evidence=(source/PKG/'NativeAppEvidence.java').read_text()
    background=(source/PKG/'BackgroundSession.java').read_text()
    actual={
        'historical_profile':h.body(background,'    void requireHistoricalProfileWindow('),
        'profile_target':h.body(evidence,'    static void requireProfileTarget(ProfileTarget expected,WindowOwnership actual){'),
        'same_owner':h.body(evidence,'    static boolean sameProfileOwner(WindowOwnership a,WindowOwnership b){'),
        'owner_guard':h.body(service,'    private static void requireSameProfileOwner(WindowOwnership original,WindowOwnership actual){'),
        'owner_exception':h.body(service,'    private static final class ProfileOwnershipViolation extends IllegalStateException {'),
    }
    text=ax.once(text,h.body(text,'        void requireHistoricalProfileWindow('),actual['historical_profile'])
    # The fixture's display field is named display. Keep the production method
    # unchanged by supplying its real field name alongside that transport port.
    text=ax.once(text,'    static final class BackgroundSession {',
        '    static final class BackgroundSession {\n'
        '        int displayId;\n'
        '        private final java.util.IdentityHashMap<WindowOwnership,Boolean> profileProofs=new java.util.IdentityHashMap<WindowOwnership,Boolean>();')
    text=ax.once(text,h.body(text,'        static void requireProfileTarget(Object expected,WindowOwnership actual){'),actual['profile_target'])
    text=ax.once(text,'    static final class NativeAppEvidence {',
        '    static final class NativeAppEvidence {\n'+actual['same_owner'])
    text=ax.once(text,h.body(text,'    static void requireSameProfileOwner(WindowOwnership before,WindowOwnership after){'),
        actual['owner_exception']+'\n'+actual['owner_guard'])
    text=ax.once(text,'            if(profile!=null)throw new AssertionError("legacy observer cannot publish profile authority");',
        '            if(profile!=null)live.taskBackground.requireHistoricalProfileWindow(profile,window,profile.taskId,captured);')
    cases=(HERE/'EmptyLoadingCases.fragment').read_text()
    text=ax.once(text,'    public static void main(String[] args)throws Exception{',
        cases+'\n    public static void main(String[] args)throws Exception{')
    text=ax.once(text,'            publicationRecheckCases();',
        '            publicationRecheckCases();\n            emptyLoadingCases();')
    path.write_text(text)
    meta['empty_loading_actual_profile_methods']={k:{'bytes':len(v.encode()),'sha256':h.sha(v.encode())} for k,v in actual.items()}
    meta['empty_loading_inputs']=[h.meta(HERE/'run_empty_loading_host.py'),h.meta(HERE/'EmptyLoadingCases.fragment')]
    meta['empty_loading_boundary']='Same live proof object registry, typed target/UID/owner and original request scheduling; synthetic Android Graph/clock/broker registration only.'
    return meta

if __name__=='__main__':
    ax.generate=generate
    raise SystemExit(ax.main())
