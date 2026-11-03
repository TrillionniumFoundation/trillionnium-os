#!/usr/bin/env python3
"""Build HEPTA49 unsigned with an explicit Android compiler system image.

The captured builder's Pocket4 profile hardcoded an absent historical Soong
output. This driver changes only that dependency selection; Java, aapt2, D8,
resources, manifest and application sources remain the captured versions.
"""
import argparse
import importlib.util
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
REFERENCE=Path("/home/alex/razr-flash-validation-canonical-20261014/staging/rog-r57-count8-source-and-build")
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source",type=Path,default=HERE/"source")
    p.add_argument("--system-modules",type=Path,required=True)
    p.add_argument("--reference-root",type=Path,default=REFERENCE,
                   help="Root containing the pinned inputs/source_3 and inputs/R8_9_3_27 trees")
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    reference=a.reference_root.resolve(strict=True)
    spec=importlib.util.spec_from_file_location("captured_hepta49_builder",HERE/"build_hepta.py")
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    old_profile=mod.profile
    def profile(name,args):
        conf=old_profile(name,args)
        def relocated(value):
            if isinstance(value,Path):
                try:return reference/value.relative_to(REFERENCE)
                except ValueError:return value
            if isinstance(value,str) and value.startswith(str(REFERENCE)+"/"):
                return str(reference)+value[len(str(REFERENCE)):]
            if isinstance(value,list):return [relocated(x) for x in value]
            return value
        conf={k:relocated(v) for k,v in conf.items()}
        conf["system"]=a.system_modules.resolve(strict=True)
        conf["cert"]=conf["key"]=None
        return conf
    mod.profile=profile
    sys.argv=[str(HERE/"build_hepta.py"),"--profile","pocket4","--source",str(a.source),
              "--out",str(a.out)]
    return mod.main()
if __name__=="__main__":raise SystemExit(main())

