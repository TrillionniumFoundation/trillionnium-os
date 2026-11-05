"""Exact, reversible source increment; imported only by local review tooling."""

def upgrade_stage_codec(final, edits, *, literal, replace_once, fill, need):
    pname = 'prepare_live_runtime_properties.py'
    vname = 'policy_runtime_properties_verifier.py'
    old_final = literal(final[pname], 'STAGE_FINAL')
    need(literal(final[vname], 'STAGE_FINAL') == old_final,
         'prepare and verifier original stage-final programs differ')
    before = "    env=encoded({k:base64.b64encode(v).decode('ascii') for k,v in sorted(files.items())})\n"
    after = ("    text_files={k:v.decode('utf-8',errors='strict') for k,v in sorted(files.items())}\n"
             "    need(all(text_files[k].encode('utf-8',errors='strict')==v for k,v in files.items()),\n"
             "        'strict UTF-8 staged originals must round-trip byte exactly')\n"
             "    env=encoded(text_files)\n")
    final[pname] = replace_once(final[pname], before, after, edits[pname])
    before = "    stage={'schema':'hepta.runtime-properties-r10.code-stage-intent.v1','binding_sha256':binding_sha,\n"
    after = before + "        'envelope_encoding':'strict-utf8-json-v1',\n"
    final[pname] = replace_once(final[pname], before, after, edits[pname])
    before = ("value=json.loads(raw,object_pairs_hook=pairs)\n"
              "need(set(value)==set(STAGE['files']),'exact reviewed staged file set')\n"
              "files={k:base64.b64decode(v,validate=True) for k,v in value.items()}\n")
    after = ("need(STAGE.get('envelope_encoding')=='strict-utf8-json-v1','exact stage envelope encoding')\n"
             "value=json.loads(raw.decode('utf-8',errors='strict'),object_pairs_hook=pairs)\n"
             "need(type(value) is dict and all(type(v) is str for v in value.values())\n"
             " and set(value)==set(STAGE['files']),'exact reviewed UTF-8 staged file set')\n"
             "files={k:v.encode('utf-8',errors='strict') for k,v in value.items()}\n")
    final[pname] = replace_once(final[pname], before, after, edits[pname])
    new_final = literal(final[pname], 'STAGE_FINAL')
    final[vname] = fill(final[vname], 'STAGE_FINAL', new_final, edits[vname], expected=old_final)
    before = "    stage_raw=files['STAGE-INTENT.original.json'];stage=strict(stage_raw);complete=strict(files['STAGE-COMPLETE.original.json'])\n"
    after = before + "    need(stage.get('envelope_encoding')=='strict-utf8-json-v1','exact stage envelope encoding')\n"
    final[vname] = replace_once(final[vname], before, after, edits[vname])
    before = "    bytes_match(plain,stage['plain']);envelope=strict(plain)\n"
    after = "    bytes_match(plain,stage['plain']);plain.decode('utf-8',errors='strict');envelope=strict(plain)\n"
    final[vname] = replace_once(final[vname], before, after, edits[vname])
    before = "    need(set(envelope)==set(stage['files'])==expected_names and complete['files']==stage['files'],\n"
    after = ("    need(type(envelope) is dict and all(type(value) is str for value in envelope.values())\n"
             "        and set(envelope)==set(stage['files'])==expected_names and complete['files']==stage['files'],\n")
    final[vname] = replace_once(final[vname], before, after, edits[vname])
    before = "        raw=base64.b64decode(value,validate=True);bytes_match(raw,stage['files'][name])\n"
    after = "        raw=value.encode('utf-8',errors='strict');bytes_match(raw,stage['files'][name])\n"
    final[vname] = replace_once(final[vname], before, after, edits[vname])
    need(literal(final[pname], 'STAGE_FINAL') == literal(final[vname], 'STAGE_FINAL'),
         'new prepare and verifier stage-final programs differ')
    for name in ('STAGE_BASE', 'STAGE_PART'):
        need(literal(final[pname], name) == literal(final[vname], name),
             'unchanged stage prefix/part verifier program differs')
