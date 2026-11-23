"""Explicit refusing compiler boundaries for old pure grammars and manual client gates."""
from pathlib import Path
import hashlib

def add(source, files):
    source=Path(source)
    files=list(files)
    names=[Path(p).name for p in files]
    if any(n in names for n in ('NativeSearchSession.java','NativeSearchPlanning.java','NativeSearchDecision.java')):
        raise RuntimeError('Old pure boundary cannot replace or duplicate actual typed search inputs')
    base=source/'tests/native-app/legacy-boundary'
    files += [source/'src/org/trillionnium/hepta/local/NativeSearchDecision.java',
              base/'NativeSearchSession.java',base/'NativeSearchPlanning.java']
    if 'NativeAppEvidence.java' not in names:
        files.append(base/'search-pure/NativeAppEvidence.java')
    return add_auto_boundary(source, files)


def add_auto_boundary(source, files):
    """Explicit old-domain ABI only; never constructs automatic authority."""
    source=Path(source).resolve()
    files=list(files)
    paths=[Path(p).resolve() for p in files]
    targets=[p for p in paths if p.name=='BackgroundTaskTarget.java']
    if not targets:
        return files
    if targets!=[source/'src/org/trillionnium/hepta/local/BackgroundTaskTarget.java']:
        raise RuntimeError('Only the complete actual target can use the refusing automatic boundary')
    boundary=source/'tests/native-app/legacy-boundary/BackgroundAutoTargetResolver.java'
    if hashlib.sha256(boundary.read_bytes()).hexdigest()!='4341eca0c3e5f4e81eee05e2a89f7bb1070475a59d5e5ff28c8c70016ec70e08':
        raise RuntimeError('The private all-throw automatic compiler boundary differs')
    existing=[p for p in paths if p.name=='BackgroundAutoTargetResolver.java']
    if existing and existing!=[boundary]:
        raise RuntimeError('Old pure boundary cannot replace or duplicate actual automatic inputs')
    return files if existing else files+[boundary]
