#!/usr/bin/env python3
"""Root-only Flight54 independent RUN after reviewed r7 preparation and owner16 normal close.
The original runner acquires the existing nonblocking operation_lock for its whole
execution. This wrapper does not retain/reopen a cooperative-owner lease or send
a page action. Missing actual preparation/review facts reject before source load.
"""
import hashlib,os,re,stat,sys
from pathlib import Path
PREPARATION_SHA256=None
REVIEW_SHA256=None
PREPARED_SCREEN_SHA256=None
PREPARED_WINDOW_SHA256=None
START_TAP=None
assert all(isinstance(v,str) and re.fullmatch(r"[0-9a-f]{64}",v) for v in
    (PREPARATION_SHA256,REVIEW_SHA256,PREPARED_SCREEN_SHA256,PREPARED_WINDOW_SHA256))
assert type(START_TAP) is list and len(START_TAP)==2 and all(type(n) is int and 0<=n<=10000 for n in START_TAP)
p=Path("/home/alex/hepta-local-007f-20261111/background-web-adapters-v54-r7/run_background_web_v54_r1.py")
assert all(not q.is_symlink() for q in (p,*p.parents))
with p.open("rb") as f:
    a=os.fstat(f.fileno());raw=f.read(33747);b=os.fstat(f.fileno())
ident=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size==33746 and ident(a)==ident(b)==ident(p.stat())
assert len(raw)==33746 and hashlib.sha256(raw).hexdigest()=="1fd56ea02e6da96ad4150bb05d72f5d219eb40990b02ef8c40e3f2f8579eebd4"
sys.dont_write_bytecode=True
sys.argv=[str(p)]+["--case","flight","--lease-number","1","--base-runner","/home/alex/hepta-local-007f-20261111/background-notes-adapters-v53-r1/run_background_notes_v53_r1.py","--identity-helper","/home/alex/hepta-local-007f-20261111/background-prerequisites/v35_identity.py","--source-tools","/home/alex/hepta-local-007f-20261111/v54-main-host-r4/source/tools","--runtime-config","/home/alex/hepta-local-007f-20261111/profile-lfm3-v51-r1/runtime-config.after.json","--release-manifest","/home/alex/hepta-local-007f-20261111/background-web-adapters-v54-r7/RELEASE.json","--release-manifest-sha256","acfbdf07f671facf65f6919142f8e4646952ec2a55524f313b4a4a5c9bcad3c3","--preparation","/home/alex/hepta-local-007f-20261111/background-web-v54-lfm3-flight-prepare-r2/RESULT.json","--preparation-sha256",PREPARATION_SHA256,"--review","/home/alex/hepta-local-007f-20261111/ROOT-WEB54-FLIGHT-START-REVIEW-r7.json","--review-sha256",REVIEW_SHA256,"--prepared-screen","/home/alex/hepta-local-007f-20261111/background-web-v54-lfm3-flight-prepare-r2/prepared-main.png","--prepared-screen-sha256",PREPARED_SCREEN_SHA256,"--prepared-window-dump","/home/alex/hepta-local-007f-20261111/background-web-v54-lfm3-flight-prepare-r2/prepared-window.txt","--prepared-window-dump-sha256",PREPARED_WINDOW_SHA256,"--adb","/usr/bin/adb","--adb-host","127.0.0.1","--adb-port","5037","--serial","ZY22LS7WZT","--main-physical-display-id","4630947043778501779","--existing-su-authorized","--start-tap",str(START_TAP[0]),str(START_TAP[1]),"--start-window","90","--timeout","560","--interval","1.0","--command-timeout","8","--out","/home/alex/hepta-local-007f-20261111/background-web-v54-lfm3-flight-r1"]
exec(compile(raw,str(p),"exec",dont_inherit=True),{"__name__":"__main__","__file__":str(p)})
