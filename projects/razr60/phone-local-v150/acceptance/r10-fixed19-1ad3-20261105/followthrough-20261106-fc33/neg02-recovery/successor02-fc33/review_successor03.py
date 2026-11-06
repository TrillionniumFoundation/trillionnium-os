import ast,base64,hashlib,json,lzma,pathlib,shlex
r=pathlib.Path(__file__).parent
sha=lambda b:hashlib.sha256(b).hexdigest()
loaded=[]
for fn in ('OLD-PHONE-REQUEST.json','PHONE-REQUEST.json'):
    req=json.loads((r/fn).read_bytes()); argv=shlex.split(req['command']); tree=ast.parse(argv[-1])
    values=[ast.literal_eval(n.args[0]) for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='b85decode']
    assert len(values)==1
    encoded=values[0]; xz=base64.b85decode(encoded); d=lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=16777216)
    raw=d.decompress(xz,max_length=1048577); assert d.eof and not d.unused_data
    wrapper,payload=raw.split(b'\0',1); obj=json.loads(payload)
    text=argv[-1]
    expected={repr(encoded):"'COMPRESSED_PAYLOAD'",str(len(xz)):'COMPRESSED_LENGTH',repr(sha(xz)):"'COMPRESSED_HASH'",str(len(raw)+1):'DECODE_BOUND',str(len(raw)):'DECODE_LENGTH',repr(sha(raw)):"'DECODE_HASH'",str(len(payload)):'PAYLOAD_LENGTH',repr(sha(payload)):"'PAYLOAD_HASH'"}
    for old,new in expected.items():
        assert text.count(old)==1,(fn,new,text.count(old));text=text.replace(old,new,1)
    argv[-1]=text;normalized=dict(req,command=argv)
    loaded.append((req,normalized,xz,raw,wrapper,payload,obj))
a,b=loaded
assert a[1]==b[1] and a[4]==b[4] and len(b[4])==255
assert a[6]['capture_source']==b[6]['capture_source']
assert sha(b[6]['capture_source'].encode())=='e6f1562d9e887137958eaeecb8aec647c4601ac4796c33656a7aaf58985daa34'
for item,sourcefile in ((a,'OLD-SOURCE.original.py'),(b,'SOURCE.original.py')):assert item[6]['source'].encode()==(r/sourcefile).read_bytes()
def source_norm(s):
    t=ast.parse(s);lines=s.splitlines(keepends=True)
    for n in t.body:
        if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in ('PRESERVATION','HOST_VERIFICATION','TARGETS'):
            assert n.lineno==n.end_lineno
            lines[n.lineno-1]=n.targets[0].id+' = REVIEWED_BINDING\n'
    return ''.join(lines)
assert source_norm(a[6]['source'])==source_norm(b[6]['source'])
ab=json.loads(a[6]['binding']);bb=json.loads(b[6]['binding'])
assert set(ab)==set(bb)
changed={k for k in ab if ab[k]!=bb[k]};assert changed=={'preservation_manifest','owned_targets_raw','source','host_verification'}
at=json.loads(ab['owned_targets_raw']);bt=json.loads(bb['owned_targets_raw'])
assert at['sender_xml_parent']['metadata'][7:]==[1793963850235883232]*2
assert bt['sender_xml_parent']['metadata'][7:]==[1793970183899880816]*2
inverse=json.loads(bb['owned_targets_raw']);inverse['sender_xml_parent']['metadata'][7:]=at['sender_xml_parent']['metadata'][7:];inverse['preservation_manifest']=at['preservation_manifest'];assert inverse==at
assert bb['source']['bytes']==len(b[6]['source'].encode()) and bb['source']['sha256']==sha(b[6]['source'].encode())
service=b'shell,v2,raw:/debug_ramdisk/su -c '+shlex.quote(b[0]['command']).encode()+b'\0'
assert len(service)==65214 and sha(service)=='f259e6dfff87ed4f31c0a48bc5df27e7d1e38bbd4d42d51a9cb72030c8b62a8c'
proof={'schema':'hepta.root.successor03.offline-review.v1','source_bytes':len(b[6]['source'].encode()),'source_sha256':sha(b[6]['source'].encode()),'only_three_source_bindings_changed':True,'target_inverse_exact':True,'capture_scope_nonce_lease_audit_paths_and_limits_unchanged':True,'launcher_except_measured_compression_bindings_exact':True,'xz_bytes':len(b[2]),'xz_sha256':sha(b[2]),'service_bytes_with_nul':len(service),'service_sha256':sha(service),'service_limit':65535,'service_headroom':65535-len(service),'phone_dispatches_in_this_review':0,'whole_neg02_pass':False}
(r/'ROOT-SUCCESSOR03-OFFLINE-REVIEW.json').write_text(json.dumps(proof,sort_keys=True,indent=2)+'\n');print(json.dumps(proof,sort_keys=True))
