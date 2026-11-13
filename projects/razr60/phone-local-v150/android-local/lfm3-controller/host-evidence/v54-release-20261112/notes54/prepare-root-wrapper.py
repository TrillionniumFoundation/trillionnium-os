#!/usr/bin/env python3
"""Root-only fixed owner15 Notes54 ordinary dual-selection prepare after actual main54 installation."""
import hashlib,os,stat,sys
from pathlib import Path
p=Path("/home/alex/hepta-local-007f-20261111/background-notes-adapters-v54-r1/run_one_v54_helper_then_export_r1.py")
assert all(not q.is_symlink() for q in (p,*p.parents))
with p.open("rb") as f:
    a=os.fstat(f.fileno());raw=f.read(9571);b=os.fstat(f.fileno())
ident=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
assert stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size==9570 and ident(a)==ident(b)==ident(p.stat())
assert len(raw)==9570 and hashlib.sha256(raw).hexdigest()=="ac061e23bdd0c6705b88808273de456b8f4d3a736fda90cb571ca20722781fe4"
sys.dont_write_bytecode=True
sys.argv=[str(p)]+["--kind","prepare","--helper-argv-json","[\"/usr/bin/python3\",\"-u\",\"/home/alex/hepta-local-007f-20261111/background-notes-adapters-v54-r1/prepare_background_notes_v54_r1.py\",\"--test-mode\",\"main_user_coexistence\",\"--ui-helper\",\"/home/alex/hepta-local-007f-20261111/phone-adapters-v46/moto_note_v46_r1.py\",\"--background-driver\",\"/home/alex/hepta-local-007f-20261111/phone-adapters-v46/background_r12_v46.py\",\"--r7-driver\",\"/home/alex/hepta-local-007f-20261111/phone-adapters-v46/background_helpers_r7_v46.py\",\"--source-tools\",\"/home/alex/hepta-local-007f-20261111/v54-main-host-r4/source/tools\",\"--owner-root\",\"/home/alex/hepta-local-007f-20261111/owner-15\",\"--runtime-config\",\"/home/alex/hepta-local-007f-20261111/profile-lfm3-v51-r1/runtime-config.after.json\",\"--plan\",\"/home/alex/hepta-local-007f-20261111/background-notes-adapters-v54-r1/notes-plan-normal-r1.json\",\"--out\",\"/home/alex/hepta-local-007f-20261111/background-notes-v54-lfm3-normal-prepare-r1\",\"--owner-start-ticks\",\"24911394\",\"--owner-boot-id\",\"97d9600f-e081-465c-9e6e-62651e09806b\",\"--adb\",\"/usr/bin/adb\",\"--adb-host\",\"127.0.0.1\",\"--serial\",\"ZY22LS7WZT\",\"--apk-sha256\",\"0729f54704a058049e12041c7f901b1b6650924500663cf9952a03d6a33a8b8a\",\"--main-physical-display-id\",\"4630947043778501779\",\"--plan-sha256\",\"46a375026c4de1f29bdd428de36c5141a4eb1ccf0afdea00538b4aaf95ec319b\",\"--owner-pid\",\"2898006\",\"--adb-port\",\"5037\",\"--expected-uid\",\"10481\",\"--command-timeout\",\"12\"]","--export-out","/home/alex/hepta-local-007f-20261111/background-notes-v54-lfm3-normal-prepare-r1-host-review-r1"]
exec(compile(raw,str(p),"exec",dont_inherit=True),{"__name__":"__main__","__file__":str(p)})
