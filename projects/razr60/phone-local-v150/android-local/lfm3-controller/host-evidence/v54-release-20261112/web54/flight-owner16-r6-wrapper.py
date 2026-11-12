#!/usr/bin/env python3
"""Root-only ordinary Flight54 preparation after actual Notes terminal; never taps Start."""
import hashlib,os,re,stat,sys
from pathlib import Path
# Seal only these four values from the NEXT actual cooperative owner.
# None rejects before loading preparation code or invoking any device tool.
OWNER_ROOT="/home/alex/hepta-local-007f-20261111/owner-16"
OWNER_PID="169031"
OWNER_START_TICKS="26909819"
OWNER_BOOT_ID="97d9600f-e081-465c-9e6e-62651e09806b"
assert isinstance(OWNER_ROOT,str) and re.fullmatch(r"/home/alex/hepta-local-007f-20261111/owner-[1-9][0-9]*",OWNER_ROOT)
assert isinstance(OWNER_PID,str) and re.fullmatch(r"[1-9][0-9]*",OWNER_PID)
assert isinstance(OWNER_START_TICKS,str) and re.fullmatch(r"[1-9][0-9]*",OWNER_START_TICKS)
assert isinstance(OWNER_BOOT_ID,str) and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",OWNER_BOOT_ID)
p=Path("/home/alex/hepta-local-007f-20261111/background-web-adapters-v54-r6/prepare_background_web_v54_r1.py")
assert all(not q.is_symlink() for q in (p,*p.parents))
with p.open("rb") as f:
    a=os.fstat(f.fileno());raw=f.read(27464);b=os.fstat(f.fileno())
ident=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size==27463 and ident(a)==ident(b)==ident(p.stat())
assert len(raw)==27463 and hashlib.sha256(raw).hexdigest()=="136503e201844f4ab0481f1db8877a16f6693e161f533ccb9a944d585e0d9181"
sys.dont_write_bytecode=True
sys.argv=[str(p)]+["--test-mode","background_only","--case","flight","--ui-helper","/home/alex/hepta-local-007f-20261111/phone-adapters-v46/moto_note_v46_r1.py","--background-driver","/home/alex/hepta-local-007f-20261111/phone-adapters-v46/background_r12_v46.py","--r7-driver","/home/alex/hepta-local-007f-20261111/phone-adapters-v46/background_helpers_r7_v46.py","--source-tools","/home/alex/hepta-local-007f-20261111/v54-main-host-r4/source/tools","--owner-root",OWNER_ROOT,"--runtime-config","/home/alex/hepta-local-007f-20261111/profile-lfm3-v51-r1/runtime-config.after.json","--release-manifest","/home/alex/hepta-local-007f-20261111/background-web-adapters-v54-r6/RELEASE.json","--out","/home/alex/hepta-local-007f-20261111/background-web-v54-lfm3-flight-prepare-r1","--owner-start-ticks",OWNER_START_TICKS,"--owner-boot-id",OWNER_BOOT_ID,"--adb","/usr/bin/adb","--adb-host","127.0.0.1","--serial","ZY22LS7WZT","--apk-sha256","0729f54704a058049e12041c7f901b1b6650924500663cf9952a03d6a33a8b8a","--main-physical-display-id","4630947043778501779","--release-manifest-sha256","acfbdf07f671facf65f6919142f8e4646952ec2a55524f313b4a4a5c9bcad3c3","--owner-pid",OWNER_PID,"--adb-port","5037","--expected-uid","10481","--command-timeout","12"]
exec(compile(raw,str(p),"exec",dont_inherit=True),{"__name__":"__main__","__file__":str(p)})
