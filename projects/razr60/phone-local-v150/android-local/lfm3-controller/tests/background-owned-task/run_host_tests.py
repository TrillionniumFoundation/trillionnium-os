#!/usr/bin/env python3
"""Run the pure Java outbound-task policy tests; no Android, phone or transport access."""
import argparse
from pathlib import Path
import subprocess
import tempfile

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--javac',default='javac')
    parser.add_argument('--java',default='java')
    parser.add_argument('--out',type=Path)
    args=parser.parse_args()
    source=Path(__file__).resolve().parents[2]
    inputs=[source/'src/org/trillionnium/hepta/background/BackgroundOwnedTaskPolicy.java',
            Path(__file__).resolve().parent/'BackgroundOwnedTaskPolicyHostTest.java']
    for item in inputs:
        if not item.is_file():raise RuntimeError('Missing source: '+str(item))
    temporary=None
    if args.out is None:
        temporary=tempfile.TemporaryDirectory(prefix='hepta-owned-task-policy-')
        out=Path(temporary.name)
    else:
        out=args.out.resolve()
        out.mkdir(parents=True,exist_ok=False)
    try:
        classes=out/'classes';classes.mkdir()
        subprocess.run([args.javac,'--release','8','-encoding','UTF-8','-d',str(classes),
                        *map(str,inputs)],check=True)
        subprocess.run([args.java,'-cp',str(classes),
                        'org.trillionnium.hepta.background.BackgroundOwnedTaskPolicyHostTest'],check=True)
    finally:
        if temporary is not None:temporary.cleanup()

if __name__=='__main__':main()
