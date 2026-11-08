#!/usr/bin/env python3
"""Bounded, read-only inventory of this pinned v4/LZ4-legacy init_boot backup.

This is not a boot-image repacker or signer. It extracts only ordinary evidence
files into a new host directory, preserving the complete original cpio bytes.
All later repacking must use the independently pinned official magiskboot.
"""
from __future__ import annotations
import argparse
import ctypes
import ctypes.util
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import struct


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def aligned(value, size):
    return (value + size - 1) // size * size


def lz4_legacy(raw):
    require(raw[:4] == bytes.fromhex("02214c18"), "only observed LZ4 legacy format is supported")
    library = ctypes.util.find_library("lz4")
    require(library is not None, "host liblz4 missing")
    lib = ctypes.CDLL(library)
    lib.LZ4_decompress_safe.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
    lib.LZ4_decompress_safe.restype = ctypes.c_int
    offset, result, blocks = 4, bytearray(), []
    while offset < len(raw):
        require(offset + 4 <= len(raw), "truncated LZ4 block header")
        count, = struct.unpack_from("<I", raw, offset)
        offset += 4
        require(0 < count <= 9 * 1024 * 1024 and offset + count <= len(raw), "invalid LZ4 block extent")
        source = ctypes.create_string_buffer(raw[offset:offset + count])
        target = ctypes.create_string_buffer(8 * 1024 * 1024)
        decoded = lib.LZ4_decompress_safe(source, target, count, len(target))
        require(0 < decoded <= len(target) and len(result) + decoded <= 64 * 1024 * 1024,
                "LZ4 decompression failed or exceeds bound")
        result.extend(target.raw[:decoded]); offset += count
        blocks.append({"compressed_bytes": count, "decompressed_bytes": decoded})
    return bytes(result), {"host_library": library, "blocks": blocks}


def cpio_inventory(raw):
    offset, entries, names, payloads = 0, [], set(), {}
    while True:
        start = offset
        require(offset + 110 <= len(raw) and raw[offset:offset + 6] in (b"070701", b"070702"),
                "unsupported or truncated cpio header")
        values = []
        for pos in range(offset + 6, offset + 110, 8):
            field = raw[pos:pos + 8]
            require(all(c in b"0123456789abcdefABCDEF" for c in field), "nonhex cpio header")
            values.append(int(field, 16))
        ino, mode, uid, gid, nlink, mtime, size, devmajor, devminor, rdevmajor, rdevminor, namesize, check = values
        require(0 < namesize <= 4096 and offset + 110 + namesize <= len(raw), "cpio name bound")
        name_raw = raw[offset + 110:offset + 110 + namesize]
        require(name_raw[-1:] == b"\0" and b"\0" not in name_raw[:-1], "invalid cpio name")
        name = name_raw[:-1].decode("utf-8", errors="strict")
        data_offset = aligned(offset + 110 + namesize, 4)
        require(data_offset + size <= len(raw), "cpio data extent invalid")
        payload = raw[data_offset:data_offset + size]
        offset = aligned(data_offset + size, 4)
        require(offset <= len(raw), "cpio padded extent invalid")
        if name == "TRAILER!!!":
            require(size == 0 and not any(raw[offset:]), "nonzero bytes after cpio trailer")
            return entries, payloads, {"trailer_offset": start, "trailing_zero_bytes": len(raw) - offset}
        require(name not in names and not name.startswith("/") and ".." not in PurePosixPath(name).parts
                and "\n" not in name and "\r" not in name, "unsafe or duplicate cpio member")
        names.add(name)
        if raw[start:start + 6] == b"070702":
            require((sum(payload) & 0xffffffff) == check, "cpio payload checksum differs")
        entry = {"name": name, "ino": ino, "mode": mode, "uid": uid, "gid": gid, "nlink": nlink,
                 "mtime": mtime, "bytes": size, "devmajor": devmajor, "devminor": devminor,
                 "rdevmajor": rdevmajor, "rdevminor": rdevminor, "header_check": check,
                 "record_offset": start, "record_bytes": offset - start, "data_offset": data_offset,
                 "record_sha256": sha(raw[start:offset]), "sha256": sha(payload)}
        if stat.S_ISLNK(mode):
            entry["symlink_target"] = payload.decode("utf-8", errors="strict")
        entries.append(entry); payloads[name] = payload
        require(len(entries) <= 10000, "cpio member count exceeds bound")


def inspect(raw):
    require(4096 <= len(raw) <= 128 * 1024 * 1024 and raw[:8] == b"ANDROID!", "boot image bound/magic differs")
    kernel, ramdisk, os_version, header_size = struct.unpack_from("<IIII", raw, 8)
    version, = struct.unpack_from("<I", raw, 40)
    signature_size, = struct.unpack_from("<I", raw, 1580)
    require(version == 4 and header_size == 1584 and kernel == 0 and signature_size == 0,
            "not the observed unsigned v4 init_boot layout")
    require(0 < ramdisk <= 64 * 1024 * 1024 and 4096 + ramdisk <= len(raw) - 64, "ramdisk extent invalid")
    require(raw[-64:-60] == b"AVBf", "observed AVB footer missing")
    major, minor, original_size, vbmeta_offset, vbmeta_size = struct.unpack_from(">IIQQQ", raw, len(raw) - 60)
    require(major == 1 and minor == 0 and aligned(4096 + ramdisk, 4096) <= original_size
            and original_size <= vbmeta_offset < len(raw) - 64
            and 256 <= vbmeta_size <= 1024 * 1024 and vbmeta_offset + vbmeta_size <= len(raw) - 64
            and raw[vbmeta_offset:vbmeta_offset + 4] == b"AVB0", "AVB metadata bounds differ")
    cpio, compression = lz4_legacy(raw[4096:4096 + ramdisk])
    entries, payloads, trailer = cpio_inventory(cpio)
    report = {"schema": "hepta.init-boot-readonly-inventory.v1", "input_bytes": len(raw), "input_sha256": sha(raw),
              "header": {"version": version, "header_size": header_size, "kernel_bytes": kernel,
                         "ramdisk_bytes": ramdisk, "os_version": os_version, "signature_size": signature_size,
                         "header_page_sha256": sha(raw[:4096])},
              "compression": compression, "cpio_bytes": len(cpio), "cpio_sha256": sha(cpio),
              "cpio_trailer": trailer, "members": entries,
              "avb": {"footer_sha256": sha(raw[-64:]), "original_image_size": original_size,
                      "vbmeta_offset": vbmeta_offset, "vbmeta_bytes": vbmeta_size,
                      "vbmeta_sha256": sha(raw[vbmeta_offset:vbmeta_offset + vbmeta_size])},
              "repacked": False, "partition_written": False}
    return report, cpio, payloads


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    raw = args.image.read_bytes()
    require(sha(raw) == args.expected_sha256, "original image hash differs")
    report, cpio, payloads = inspect(raw)
    args.out.mkdir(mode=0o700, parents=False, exist_ok=False)
    write_new(args.out / "original-ramdisk.cpio", cpio)
    rc = []
    for entry in report["members"]:
        if stat.S_ISREG(entry["mode"]) and entry["name"].endswith(".rc"):
            filename = entry["sha256"][:16] + "-" + PurePosixPath(entry["name"]).name
            write_new(args.out / filename, payloads[entry["name"]])
            rc.append({"member": entry["name"], "evidence_file": filename, "sha256": entry["sha256"]})
    report["rc_evidence"] = rc
    result = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    write_new(args.out / "INVENTORY.json", result)
    require(sha(args.image.read_bytes()) == args.expected_sha256, "input changed during read-only inventory")
    print(json.dumps({"inventory": str(args.out / "INVENTORY.json"), "sha256": sha(result),
                      "members": len(report["members"]), "rc_members": rc, "repacked": False}))


if __name__ == "__main__":
    main()
