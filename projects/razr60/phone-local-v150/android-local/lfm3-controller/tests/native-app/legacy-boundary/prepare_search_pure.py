"""Explicit opt-in only for old pure grammars; shared background outputs stay unchanged."""
from pathlib import Path

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
    return files
