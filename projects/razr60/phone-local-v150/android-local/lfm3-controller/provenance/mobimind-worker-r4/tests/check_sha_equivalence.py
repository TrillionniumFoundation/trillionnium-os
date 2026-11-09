#!/usr/bin/env python3
"""Independent hashlib checks of the real SHA probe, including >2^32 input bits."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import random


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
        rng=random.Random(928103)
        for length in (17,56,127,4097,1048579):
            random_bytes=bytes(rng.getrandbits(8) for _ in range(length));path.write_bytes(random_bytes)
            expected=hashlib.sha256(random_bytes).hexdigest()
            for option in ([],["--portable"]):
                random_report=invoke("--file",path,"--chunk",65536,*option)
                assert random_report["sha256"]==expected and random_report["bytes"]==length
                assert random_report["held_fd_complete_read"] and random_report["metadata_unchanged"]
    period=bytes((i*29+(i>>8)+0x5a)&255 for i in range(65536))
    # Exercise the 64-bit padding length across the 2^32-bit boundary.
    count=536870913
    reference=hashlib.sha256()
    for _ in range(count//len(period)):reference.update(period)
    reference.update(period[:count%len(period)])
    large=invoke("--bench",count,"--portable")
    assert large["sha256"]==reference.hexdigest() and large["bytes"]==count
    root=Path(__file__).resolve().parents[1]
    original=(root/"evidence/code9-sha256-dispatch.h").read_text()
    assert hashlib.sha256(original.encode()).hexdigest()=="b614c97accb36faeda582918cbbbd7acd378285197e2def1557e4e3839379b1a"
    header=(root/"native/sha256-dispatch.hpp").read_text()
    transformed=original.replace("HEPTA_SHA256_DISPATCH_H","HEPTA_SHA256_DISPATCH_HPP")
    transformed=transformed.replace(
        "*s=(Sha256){.h={0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u},\n                .hardware=hepta_sha256_runtime_sha2()};",
        "*s=Sha256{{0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u},\n                0,{0},0,hepta_sha256_runtime_sha2(),0,0};")
    transformed=transformed.replace("const unsigned char *p=data;s->bits+=(uint64_t)n*8u;",
        "const unsigned char *p=static_cast<const unsigned char *>(data);s->bits+=(uint64_t)n*8u;")
    assert header==transformed,"The port changed more than C++ initialization/cast/header guard"
    r3=(root/"evidence/r3-sha_utf8.hpp").read_text()
    assert hashlib.sha256(r3.encode()).hexdigest()=="83a8099330d01d24d1a00d36b9a178a332a1087800a544e924f5dde2e90def88"
    begin=r3.index("static uint32_t rotr(");end=r3.index("static void sha_init(",begin)
    portable=r3[begin:end].replace("static void sha_block(","static void hepta_sha256_portable_block(")
    assert portable in header,"Portable compression changed from r3"
    utf8=r3[r3.index("static bool utf8("):]
    assert (root/"native/sha_utf8.hpp").read_text()==(r3[:r3.index('typedef struct')]+'#include "sha256-dispatch.hpp"\n\n'+utf8)
    print(json.dumps({"scope":"host_only","self_test_comparisons":316,
        "independent_pattern_vectors":len(summary["pattern_vectors"]),"file_reads_compared":24,"random_vectors":5,
        "large_length_bytes":count,"r3_portable_compression_unchanged":True,"code9_arm_dispatch_algorithm_unchanged":True,
        "host_runtime_hwcap_sha2":summary["runtime_hwcap_sha2"],"phone_tested":False,"all_pass":True}))


if __name__=="__main__":main()
