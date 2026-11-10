#!/usr/bin/env python3
"""Independent hashlib checks of the real SHA probe, including >2^32 input bits."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe",required=True,type=Path)
    args=parser.parse_args()
    probe=args.probe.resolve(strict=True)
    def invoke(*arguments):
        result=subprocess.run([str(probe),*map(str,arguments)],capture_output=True,timeout=90,check=True)
        return json.loads(result.stdout)
    summary=invoke("--self-test")
    assert summary["all_pass"] and summary["digest_comparisons"]==316
    for vector in summary["pattern_vectors"]:
        data=bytes((i*29+(i>>8)+0x5a)&255 for i in range(vector["bytes"]))
        assert vector["all_equal"] and vector["sha256"]==hashlib.sha256(data).hexdigest()
    with tempfile.TemporaryDirectory() as directory:
        path=Path(directory)/"fixture.bin"
        # Non-repeating over the 64 KiB read boundary, unlike benchmark input.
        data=bytes((i*29+(i>>8)+0x5a)&255 for i in range(1048641))
        path.write_bytes(data)
        expected=hashlib.sha256(data).hexdigest()
        for chunk in (1,63,64,65,4096,65536,1048576):
            for option in ([],["--portable"]):
                report=invoke("--file",path,"--chunk",chunk,*option)
                assert report["sha256"]==expected and report["bytes"]==len(data)
                assert report["held_fd_complete_read"] and report["metadata_unchanged"]
                if option:assert report["hardware_blocks"]==0 and report["backend"]=="portable"
        link=Path(directory)/"link";link.symlink_to(path)
        refused=subprocess.run([str(probe),"--file",str(link)],capture_output=True,timeout=5)
        assert refused.returncode!=0 and not refused.stdout
    period=bytes((i*29+(i>>8)+0x5a)&255 for i in range(65536))
    # Exercise the 64-bit padding length across the 2^32-bit boundary.
    count=536870913
    reference=hashlib.sha256()
    for _ in range(count//len(period)):reference.update(period)
    reference.update(period[:count%len(period)])
    large=invoke("--bench",count,"--portable")
    assert large["sha256"]==reference.hexdigest() and large["bytes"]==count
    root=Path(__file__).resolve().parents[2]
    upstream=(root/"native/worker-upstream.c").read_text()
    header=(root/"native/sha256-dispatch.h").read_text()
    begin=upstream.index("static uint32_t rotr(")
    end=upstream.index("static void sha_init(",begin)
    original=upstream[begin:end].replace("static void sha_block(","static void hepta_sha256_portable_block(")
    assert original in header,"Portable compression differs from the fixed upstream implementation"
    assert hashlib.sha256(upstream.encode()).hexdigest()=="07cd434bea9d1214acef499a69ed204ecef879a6ac05c82f24d062160e2efb3e"
    print(json.dumps({"scope":"host_only","self_test_comparisons":316,
        "independent_pattern_vectors":len(summary["pattern_vectors"]),"file_reads_compared":14,
        "large_length_bytes":count,"upstream_portable_compression_unchanged":True,
        "host_runtime_hwcap_sha2":summary["runtime_hwcap_sha2"],"phone_tested":False,"all_pass":True}))


if __name__=="__main__":main()
