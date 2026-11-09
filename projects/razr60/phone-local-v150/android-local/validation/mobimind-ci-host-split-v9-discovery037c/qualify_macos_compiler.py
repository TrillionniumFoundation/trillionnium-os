#!/usr/bin/env python3
"""Read-only hashes of exact Mach-O compiler bytes and code-signature ranges."""
import argparse, hashlib, json, pathlib, platform, struct, subprocess, sys

ORIGINAL_SHA = 'ff1800041e683dd1c51ce470a291669a67d6cdee1258c409db33c4124dd175f6'
SDKMANAGER_SHA = '9f980ecd6dd9e20641589dfd653b2cccbc3f09808f0809387e9673747285a3b3'
OUTSIDE_SHA = '60fb4530371a6b738056db82f1a5896bf3b36fd19abe5f8c4be3e9e712052975'
SOURCE_PROPERTIES_SHA = '84bef2c605bb263571c299f1eef3307ff58f741710f8cce514cb525b28567f41'
SIGNATURE_RANGES = [[88718416, 89429808], [172069296, 172733264]]

def require(value, reason):
    if value is not True:
        raise ValueError(reason)

def check_identity(report):
    require(report.get('platform') == 'Darwin', 'actual macOS compiler observation required')
    require(report.get('source_properties_sha256') == SOURCE_PROPERTIES_SHA, 'actual r28b properties changed')
    value = report.get('macho', {})
    require(value.get('schema') == 'hepta.compiler-macho-readonly.v1' and value.get('binary_modified') is False,
            'read-only Mach-O report required')
    require(type(value.get('bytes')) is int and value['bytes'] == 172733264 and
            value.get('sha256') in {ORIGINAL_SHA, SDKMANAGER_SHA}, 'unrecognized compiler container')
    require(json.dumps(value.get('signature_ranges')) == json.dumps(SIGNATURE_RANGES), 'signature range layout changed')
    require(value.get('outside_code_signatures_sha256') == OUTSIDE_SHA, 'compiler bytes outside signature ranges differ')
    slices = value.get('slices')
    require(type(slices) is list and len(slices) == 2 and
            {x.get('cpu') for x in slices if type(x) is dict} == {16777223, 16777228}, 'architecture set changed')
    require(report.get('compiler_identity_overridden') is False, 'compiler identity must remain unchanged')

def inspect(path):
    p = pathlib.Path(path)
    data = p.read_bytes()
    def need(value, reason):
        if not value:
            raise ValueError(reason)
    sha = lambda value: hashlib.sha256(value).hexdigest()
    need(len(data) > 48 and struct.unpack_from('>I', data)[0] == 0xcafebabe, 'expected fat Mach-O')
    count = struct.unpack_from('>I', data, 4)[0]
    need(count == 2, 'expected exactly two architecture slices')
    slices, exclusions = [], []
    for index in range(count):
        cpu, subtype, base, length, align = struct.unpack_from('>IIIII', data, 8 + index * 20)
        need(base >= 48 and length >= 32 and base + length <= len(data), 'slice bounds')
        header = struct.unpack_from('<IiiIIIII', data, base)
        need(header[0] == 0xfeedfacf and header[1] == cpu and 0 < header[4] < 4096, '64-bit architecture header')
        cursor, end = base + 32, base + 32 + header[5]
        need(end <= base + length, 'load command bounds')
        signatures, sections = [], []
        for _ in range(header[4]):
            need(cursor + 8 <= end, 'load command header bounds')
            cmd, size = struct.unpack_from('<II', data, cursor)
            need(size >= 8 and cursor + size <= end, 'load command size')
            if cmd == 0x1d:
                need(size == 16, 'code signature command length')
                offset, size_bytes = struct.unpack_from('<II', data, cursor + 8)
                need(offset >= header[5] + 32 and size_bytes > 0 and offset + size_bytes <= length, 'signature bounds')
                signatures.append({'offset': offset, 'bytes': size_bytes, 'sha256': sha(data[base+offset:base+offset+size_bytes])})
                exclusions.append((base + offset, base + offset + size_bytes))
            if cmd == 0x19:
                need(size >= 72, 'segment length')
                nsects = struct.unpack_from('<I', data, cursor + 64)[0]
                need(72 + nsects * 80 == size, 'section table size')
                for number in range(nsects):
                    at = cursor + 72 + number * 80
                    section = data[at:at+16].split(b'\0', 1)[0].decode('ascii')
                    segment = data[at+16:at+32].split(b'\0', 1)[0].decode('ascii')
                    size_bytes = struct.unpack_from('<Q', data, at + 40)[0]
                    offset = struct.unpack_from('<I', data, at + 48)[0]
                    flags = struct.unpack_from('<I', data, at + 64)[0]
                    record = {'segment': segment, 'section': section, 'offset': offset, 'bytes': size_bytes, 'flags': flags}
                    if offset and size_bytes:
                        need(offset + size_bytes <= length, 'section payload bounds')
                        record['sha256'] = sha(data[base+offset:base+offset+size_bytes])
                    sections.append(record)
            cursor += size
        need(cursor == end and len(signatures) == 1, 'exact load command table/signature')
        slices.append({'cpu': cpu, 'subtype': subtype, 'offset': base, 'bytes': length, 'align': align,
                       'slice_sha256': sha(data[base:base+length]), 'signatures': signatures, 'sections': sections})
    need({x['cpu'] for x in slices} == {0x1000007, 0x100000c}, 'architecture set')
    h, previous = hashlib.sha256(), 0
    for begin, end in sorted(exclusions):
        need(previous <= begin < end <= len(data), 'signature ranges overlap')
        h.update(data[previous:begin]); previous = end
    h.update(data[previous:])
    return {'schema': 'hepta.compiler-macho-readonly.v1', 'path': str(p), 'resolved_path': str(p.resolve()),
            'bytes': len(data), 'sha256': sha(data), 'signature_ranges': sorted(exclusions),
            'outside_code_signatures_sha256': h.hexdigest(), 'slices': slices, 'binary_modified': False}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ndk', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    clang = args.ndk / 'toolchains/llvm/prebuilt/darwin-x86_64/bin/clang'
    properties = (args.ndk / 'source.properties').read_bytes()
    report = {'schema': 'hepta.compiler-container-qualification.v1', 'platform': platform.system(),
              'machine': platform.machine(), 'source_properties': properties.decode('utf-8'),
              'source_properties_sha256': hashlib.sha256(properties).hexdigest(),
              'macho': inspect(clang), 'compiler_identity_overridden': False,
              'binary_rewritten': False, 'original_container_byte_identical': False,
              'compiler_bytes_outside_signatures_identical': False, 'qualified': False}
    result = subprocess.run([str(clang), '--version'], capture_output=True, text=True, timeout=30)
    report['actual_version'] = {'exit_code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}
    error = None
    try:
        require(result.returncode == 0, 'compiler version command failed')
        check_identity(report)
        report['original_container_byte_identical'] = report['macho']['sha256'] == ORIGINAL_SHA
        report['compiler_bytes_outside_signatures_identical'] = True
        report['qualified'] = True
    except Exception as failure:
        error = type(failure).__name__ + ': ' + str(failure)
    report['error'] = error
    encoded = json.dumps(report, indent=2, sort_keys=True) + '\n'
    with args.output.open('x') as stream:
        stream.write(encoded)
    print(encoded, flush=True)
    return 0 if report['qualified'] else 2

if __name__ == '__main__':
    raise SystemExit(main())
