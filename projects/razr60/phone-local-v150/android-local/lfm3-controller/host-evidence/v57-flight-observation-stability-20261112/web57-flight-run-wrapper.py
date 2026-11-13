#!/usr/bin/env python3
"""Root-only Flight57 independent RUN after reviewed preparation and the actual cooperative owner normal close.
The original runner acquires the existing nonblocking operation_lock for its whole
execution. This wrapper does not retain/reopen a cooperative-owner lease or send
a page action. Missing actual preparation/review facts reject before source load.
"""
import hashlib,os,re,stat,sys
from pathlib import Path
PREPARATION_SHA256="c527f0ab5b37694db79d5ad89102446523c09b88e74e2bd0edea5a3650a0ba9b"
REVIEW_SHA256="5b82d1fea7677e0133272dcc49ce4f99ce6706d15c4aff96369ff26c1ce4eb73"
PREPARED_SCREEN_SHA256="781e8fda6e6037808f71e13d6fda53b675b82034a6722dfcf6cef8a52232f6d7"
PREPARED_WINDOW_SHA256="9ee6830916a5b11fe9e2cb1ba4286028b341d2a6624be65b7e24d0be638596b6"
START_TAP=[180,1114]
RELEASE_MANIFEST_SHA256="918b8ee2dfaa5f6f23982d60d0da03e378e55b6c7bcaff7ca0e13476a0d8252c"
assert all(isinstance(v,str) and re.fullmatch(r"[0-9a-f]{64}",v) for v in
    (PREPARATION_SHA256,REVIEW_SHA256,PREPARED_SCREEN_SHA256,PREPARED_WINDOW_SHA256,RELEASE_MANIFEST_SHA256))
assert type(START_TAP) is list and len(START_TAP)==2 and all(type(n) is int and 0<=n<=10000 for n in START_TAP)
p=Path("/home/alex/hepta-local-007f-20261111/background-web-adapters-v57-r1/run_background_web_v57_r1.py")
assert all(not q.is_symlink() for q in (p,*p.parents))
with p.open("rb") as f:
    a=os.fstat(f.fileno());raw=f.read(34154);b=os.fstat(f.fileno())
ident=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size==34153 and ident(a)==ident(b)==ident(p.stat())
assert len(raw)==34153 and hashlib.sha256(raw).hexdigest()=="40c9f57b3b06265daf20844c13ca286fa91693ceee2499bc0947b8a37dbc7aff"
sys.dont_write_bytecode=True
sys.argv=[str(p)]+["--case","flight","--lease-number","1","--base-runner","/home/alex/hepta-local-007f-20261111/background-notes-adapters-v53-r1/run_background_notes_v53_r1.py","--identity-helper","/home/alex/hepta-local-007f-20261111/background-prerequisites/v35_identity.py","--source-tools","/home/alex/hepta-local-007f-20261111/v54-main-host-r4/source/tools","--runtime-config","/home/alex/hepta-local-007f-20261111/profile-lfm3-v51-r1/runtime-config.after.json","--release-manifest","/home/alex/hepta-local-007f-20261111/background-web-adapters-v57-r1/RELEASE.json","--release-manifest-sha256",RELEASE_MANIFEST_SHA256,"--preparation","/home/alex/hepta-local-007f-20261111/background-web-v57-lfm3-flight-prepare-r1/RESULT.json","--preparation-sha256",PREPARATION_SHA256,"--review","/home/alex/hepta-local-007f-20261111/ROOT-WEB57-FLIGHT-START-REVIEW-r1.json","--review-sha256",REVIEW_SHA256,"--prepared-screen","/home/alex/hepta-local-007f-20261111/background-web-v57-lfm3-flight-prepare-r1/prepared-main.png","--prepared-screen-sha256",PREPARED_SCREEN_SHA256,"--prepared-window-dump","/home/alex/hepta-local-007f-20261111/background-web-v57-lfm3-flight-prepare-r1/prepared-window.txt","--prepared-window-dump-sha256",PREPARED_WINDOW_SHA256,"--adb","/usr/bin/adb","--adb-host","127.0.0.1","--adb-port","5037","--serial","ZY22LS7WZT","--main-physical-display-id","4630947043778501779","--existing-su-authorized","--start-tap",str(START_TAP[0]),str(START_TAP[1]),"--start-window","90","--timeout","560","--interval","1.0","--command-timeout","8","--out","/home/alex/hepta-local-007f-20261111/background-web-v57-lfm3-flight-r1"]
exec(compile(raw,str(p),"exec",dont_inherit=True),{"__name__":"__main__","__file__":str(p)})
