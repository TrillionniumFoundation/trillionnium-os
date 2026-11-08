"""Generate the Android UID publication adapter without altering the frozen upstream worker."""
from pathlib import Path
import hashlib, json, difflib

def generate(root, out):
    source_path=root/'native/worker-upstream.c'
    original=source_path.read_bytes()
    upstream_sha=hashlib.sha256(original).hexdigest()
    assert upstream_sha=='07cd434bea9d1214acef499a69ed204ecef879a6ac05c82f24d062160e2efb3e'
    source=original.decode('utf-8')
    first=source.index('static bool publish(Destination *d) {')
    last=source.index('static void destination_close(',first)
    replacement=(root/'native/publish-appuid.inc').read_text()
    adapted=source[:first]+replacement+'\n'+source[last:]
    old='if(n<=0)return false;p+=n;size-=(size_t)n;'
    new='if(n<=0){int saved=errno;fprintf(stderr,"HEPTA_APPUID_PUBLISH stage=write_all fd=%d errno=%d error=%s\\n",fd,saved,strerror(saved));return false;}p+=n;size-=(size_t)n;'
    assert adapted.count(old)==1
    adapted=adapted.replace(old,new)
    (out/'worker-appuid.c').write_text(adapted)
    difference=''.join(difflib.unified_diff(source.splitlines(True),adapted.splitlines(True),fromfile='frozen/worker-upstream.c',tofile='generated/worker-appuid.c'))
    (out/'worker-adapter.diff').write_text(difference)
    receipt={'upstream_sha256':upstream_sha,'adapted_sha256':hashlib.sha256(adapted.encode()).hexdigest(),
        'publication':'renameat2(RENAME_NOREPLACE)','no_overwrite':True,'fallback_overwriting_rename':False,
        'errno_diagnostics':['write_all','file_fsync','renameat2_noreplace','directory_fsync']}
    (out/'worker-adapter.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return receipt
