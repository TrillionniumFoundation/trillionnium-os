"""Unadopted retained R7/R8/R9 selection in the actual current consumers.

V4 current/source-parent integration is the immutable source-construction base.
New retained reader and adapter envelopes carry actual v2-derived code identity;
the old failed results and old adapter descriptor remain historical data only.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import json
import sys
import types

FROZEN_CURRENT = {'bytes': 259866, 'sha256': 'f9a19df8a2a1d8b6a09a8c75eec118f4304ad1db5f40fc005fd7d59fb02837b7'}
V4_CONSTRUCTOR = {'bytes': 23887, 'sha256': 'ce3661cb3726b159da2e85dea6c4a4fc1aaeb8f04ebddcb9ff36061e0b39ec5e'}
V4_LOADER = {'bytes': 1024, 'sha256': '5ad647e31d520cb9f473faaa4ef81cd45f1b8d4635569eb19cbb5a9ef62ffffe'}
V4_DERIVED_CURRENT = {'bytes': 258924, 'sha256': '5b7ca9884a448518e572f1e8c5f9438389f01ea315aa41ae89f5729ccc58a3e9'}
V3_CONSTRUCTOR = {'bytes': 19589, 'sha256': '8f1eeb66110127ee295d356b3f365ea209969c689c6a80bfdb0ad1520658fd42'}
V3_LOADER = {'bytes': 1023, 'sha256': '845404b6ea78bd209c4cdf05d6c87453bda9ded4d46d6d42c6bd83757527a5ca'}
V2_SELECTOR = {'bytes': 11956, 'sha256': 'de7dc784654dec65f0e6d2d7fd81918caf9c3c634d152295c1fb7928cf04a5c2'}
V2_LOADER = {'bytes': 1407, 'sha256': '4aa4fb101dca5f4532c70ec071231b036df6e63940d08d6613305be6cb699b82'}
ORIGINAL_ADAPTER = {'bytes': 23623, 'sha256': 'eaf52438100706edb6734efea64299f6ff1b414485c2c353c9172f7c6f670857'}
COMMON = {'bytes': 19138, 'sha256': '1e2d8f90b683312891bdd9ddf46a5b73a589469cc5e4b036acd038374a908cab'}
READER_METHODS = {
    'r7-reader': ('verify_retained_preaccept_archive', 'validate_private_preservation'),
    'r8-reader': ('verify_retained_staged_archive', 'validate_private_preservation'),
    'r9-reader': ('verify_retained_transport_archive', 'validate_private_preservation', 'validate_absence_observations'),
}
READER_DATA = {'r7-reader': ('FIXTURE',), 'r8-reader': ('FIXTURE',),
               'r9-reader': ('MANIFEST_SCHEMA', 'ARCHIVE', 'RAW_ARCHIVE', 'RESULT_STATE')}
ADAPTER_METHODS = ('verify', 'source_parent_inventory', 'current_binding', 'preserve',
                   'validate_absence', 'validate_observation', 'validate_manifest')
METHODS = ('source_parent_boundary_from_original', 'source_parent_closed_boundary_originals',
           'require_failed_ancestor_tail', 'boundary_from_original', 'closed_boundary_originals', 'inventory_value',
           'retained_preaccept', 'retained_failed_staged', 'retained_failed_transport',
           'effective_current_prior_inventory', 'reviewed_historical_source_parent_inventory')


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def pin(raw):
    need(type(raw) is bytes, 'exact immutable source bytes required')
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')) + '\n').encode()


def module(raw, name):
    result = types.ModuleType(name)
    result.__file__ = '<' + name + ':sha256=' + pin(raw)['sha256'] + '>'
    exec(compile(raw, result.__file__, 'exec'), result.__dict__)
    return result


def function_source(raw, name, *, class_name=None):
    text = raw.decode('utf-8', 'strict'); nodes = ast.parse(text).body
    if class_name is not None:
        classes = [n for n in nodes if isinstance(n, ast.ClassDef) and n.name == class_name]
        need(len(classes) == 1, 'one exact source class: ' + class_name); nodes = classes[0].body
    functions = [n for n in nodes if isinstance(n, ast.FunctionDef) and n.name == name]
    need(len(functions) == 1, 'one exact source function: ' + name); node = functions[0]
    return ''.join(text.splitlines(keepends=True)[node.lineno - 1:node.end_lineno]).encode()


def transformed(original, changes):
    current = original
    normalized = []
    for site, old, new in changes:
        old = old.encode() if isinstance(old, str) else old
        new = new.encode() if isinstance(new, str) else new
        need(current.count(old) == 1 and new not in current, 'one exact retained-consumer site: ' + site)
        current = current.replace(old, new, 1); normalized.append((site, old, new))
    reverse = current
    for site, old, new in reversed(normalized):
        need(reverse.count(new) == 1, 'unique retained-consumer inverse site: ' + site)
        reverse = reverse.replace(new, old, 1)
    need(reverse == original, 'retained-consumer inverse recovers all original bytes')
    compile(current, '<UNADOPTED-retained-consumer-construction>', 'exec')
    return current, {'source_origin': pin(original), 'derived_source': pin(current),
        'whole_byte_inverse_verified': True,
        'replacements': [{'site': site, 'original': pin(old), 'derived': pin(new)} for site, old, new in normalized]}


def derive_adapter(original):
    need(pin(original) == ORIGINAL_ADAPTER, 'exact frozen historical runtime adapter source')
    need(original.count(b'adapter_source') == 7, 'seven exact historical adapter descriptor references')
    renamed = original.replace(b'adapter_source', b'historical_adapter_source')
    old_reader = function_source(renamed, 'reader', class_name='Adapter')
    new_reader = b'''    def reader(self):
        raw=self.read_pinned(self.proof['reader'])
        self.C.need(len(raw)<=128*1024,'unchanged external reader source bound')
        return __UNADOPTED_retained_reader_factory__('r9-reader',raw)
'''
    return transformed(original, [
        ('separate-historical-adapter-data-descriptor', original, renamed),
        ('select-actual-derived-r9-after-original-pin', old_reader, new_reader),
        ('consume-derived-r9-verification-result',
         "        v=r.verify_retained_transport_archive(p['archive'],read_pinned=self.read_pinned)\n",
         "        v=__UNADOPTED_consume_retained_call__(r,'r9-reader','verify_retained_transport_archive',\n"
         "            p['archive'],read_pinned=self.read_pinned)\n"),
        ('consume-derived-r9-preservation-result',
         "        return self.reader().validate_private_preservation(v,inventory,inventory_reader=self.inventory_reader)\n",
         "        return __UNADOPTED_consume_retained_call__(self.reader(),'r9-reader',\n"
         "            'validate_private_preservation',v,inventory,inventory_reader=self.inventory_reader)\n"),
        ('consume-derived-r9-absence-validation-result',
         "        return self.reader().validate_absence_observations(observations,expected_boot_id=v['boot_id'])\n",
         "        return __UNADOPTED_consume_retained_call__(self.reader(),'r9-reader',\n"
         "            'validate_absence_observations',observations,expected_boot_id=v['boot_id'])\n"),
    ])


NEW_CURRENT_HELPERS = b'''

def consume_retained_reader_call(reader, kind, method, *args, **kwargs):
    consume = globals().get('__UNADOPTED_consume_retained_call__')
    C.need(callable(consume), 'bound retained reader envelope consumer required')
    return consume(reader, kind, method, *args, **kwargs)


def consume_retained_adapter_call(adapter, method, *args, **kwargs):
    consume = globals().get('__UNADOPTED_consume_adapter_call__')
    C.need(callable(consume), 'bound current adapter envelope consumer required')
    return consume(adapter, method, *args, **kwargs)


def reviewed_historical_source_parent_inventory(raw, inventory_raw, closure_raw, *, original_descriptor):
    # New explicit combined read-only entry. No stage, live observation or probe.
    boundary, inventory, closure = source_parent_closed_boundary_originals(
        raw, inventory_raw, closure_raw, original_descriptor=original_descriptor)
    branches = non_native_sidebranches()
    return effective_current_prior_inventory(boundary, inventory, branches)
'''


def derive_current(v4_source):
    need(pin(v4_source) == V4_DERIVED_CURRENT, 'exact sealed v4 current-consumer construction base')
    old_factory = ("    mod=types.ModuleType('fixed_runtime_retained_transport_adapter')\n"
                   "    mod.__file__=row['path'];exec(compile(raw,mod.__file__,'exec'),mod.__dict__)\n"
                   "    return mod.Adapter(common=C,expected_inputs_sha256=RETAINED_FAILED_TRANSPORT_INPUTS_SHA256,\n"
                   "        adapter_source=row,prior={\n")
    new_factory = ("    factory=globals().get('__UNADOPTED_retained_adapter_factory__')\n"
                   "    C.need(callable(factory),'bound new retained adapter factory required')\n"
                   "    return factory(original_source=raw,common=C,expected_inputs_sha256=RETAINED_FAILED_TRANSPORT_INPUTS_SHA256,\n"
                   "        historical_adapter_source=row,prior={\n")
    changes = [
        ('select-standalone-r7-after-exact-embedded-source-pin',
         "    reader = types.ModuleType('r8_exact_retained_preaccept_reader')\n"
         "    reader.__file__ = '<pinned retained R7 preaccept reader>'\n"
         "    exec(compile(raw, reader.__file__, 'exec'), reader.__dict__)\n"
         "    return reader\n",
         "    return __UNADOPTED_retained_reader_factory__('r7-reader',raw)\n"),
        ('select-standalone-r8-after-exact-external-source-pin',
         "    module=types.ModuleType('fixed_failed_staged_r8');module.__file__=RETAINED_FAILED_STAGED_READER['path']\n"
         "    exec(compile(source,module.__file__,'exec'),module.__dict__)\n"
         "    return module\n",
         "    return __UNADOPTED_retained_reader_factory__('r8-reader',source)\n"),
        ('consume-r7-host-proof-result',
         "    verified = reader.verify_retained_preaccept_archive(RETAINED_PREACCEPT_HOST, read_pinned=host_read)\n",
         "    verified = consume_retained_reader_call(reader,'r7-reader','verify_retained_preaccept_archive',\n"
         "        RETAINED_PREACCEPT_HOST,read_pinned=host_read)\n"),
        ('consume-r7-current-proof-result',
         "    verified = reader.verify_retained_preaccept_archive(\n"
         "        RETAINED_PREACCEPT_PHONE, read_pinned=retained_preaccept_read_pinned)\n",
         "    verified = consume_retained_reader_call(reader,'r7-reader','verify_retained_preaccept_archive',\n"
         "        RETAINED_PREACCEPT_PHONE,read_pinned=retained_preaccept_read_pinned)\n"),
        ('consume-r7-current-preservation-result',
         "    return retained_preaccept_reader().validate_private_preservation(\n"
         "        retained, inventory, inventory_reader=inventory_value)\n",
         "    return consume_retained_reader_call(retained_preaccept_reader(),'r7-reader',\n"
         "        'validate_private_preservation',retained,inventory,inventory_reader=inventory_value)\n"),
        ('consume-r8-current-proof-result',
         "    verified=reader.verify_retained_staged_archive(RETAINED_FAILED_STAGED_PHONE,read_pinned=retained_failed_staged_read_pinned)\n",
         "    verified=consume_retained_reader_call(reader,'r8-reader','verify_retained_staged_archive',\n"
         "        RETAINED_FAILED_STAGED_PHONE,read_pinned=retained_failed_staged_read_pinned)\n"),
        ('consume-r8-current-preservation-result',
         "    return retained_failed_staged_reader().validate_private_preservation(retained,inventory,inventory_reader=inventory_value)\n",
         "    return consume_retained_reader_call(retained_failed_staged_reader(),'r8-reader',\n"
         "        'validate_private_preservation',retained,inventory,inventory_reader=inventory_value)\n"),
        ('select-new-adapter-after-exact-frozen-adapter-pin', old_factory, new_factory),
        ('consume-new-adapter-effective-inventory',
         "        return retained_failed_transport_adapter().source_parent_inventory(retained_r7,retained_r8)\n",
         "        return consume_retained_adapter_call(retained_failed_transport_adapter(),\n"
         "            'source_parent_inventory',retained_r7,retained_r8)\n"),
        ('consume-new-adapter-complete-verification',
         "    return retained_failed_transport_adapter().verify()\n",
         "    return consume_retained_adapter_call(retained_failed_transport_adapter(),'verify')\n"),
        ('consume-new-adapter-current-binding',
         "    return retained_failed_transport_adapter().current_binding(value,retained_failed_transport_value=retained_failed_transport_value)\n",
         "    return consume_retained_adapter_call(retained_failed_transport_adapter(),'current_binding',value,\n"
         "        retained_failed_transport_value=retained_failed_transport_value)\n"),
        ('consume-new-adapter-preservation',
         "    return retained_failed_transport_adapter().preserve(inventory,retained_failed_transport_value=retained_failed_transport_value)\n",
         "    return consume_retained_adapter_call(retained_failed_transport_adapter(),'preserve',inventory,\n"
         "        retained_failed_transport_value=retained_failed_transport_value)\n"),
        ('consume-new-adapter-absence-validation',
         "    return retained_failed_transport_adapter().validate_absence(observations,retained_failed_transport_value=retained_failed_transport_value)\n",
         "    return consume_retained_adapter_call(retained_failed_transport_adapter(),'validate_absence',observations,\n"
         "        retained_failed_transport_value=retained_failed_transport_value)\n"),
        ('consume-new-adapter-observation-validation',
         "    return retained_failed_transport_adapter().validate_observation(value,retained_failed_transport_value=retained_failed_transport_value)\n",
         "    return consume_retained_adapter_call(retained_failed_transport_adapter(),'validate_observation',value,\n"
         "        retained_failed_transport_value=retained_failed_transport_value)\n"),
        ('consume-new-adapter-manifest-validation',
         "    retained_failed_transport_adapter().validate_manifest(manifest)\n",
         "    consume_retained_adapter_call(retained_failed_transport_adapter(),'validate_manifest',manifest)\n"),
    ]
    current, receipt = transformed(v4_source, changes)
    need(current.endswith(b'\n') and NEW_CURRENT_HELPERS not in current, 'explicit once-only new current helper block')
    derived = current + NEW_CURRENT_HELPERS
    need(derived[:-len(NEW_CURRENT_HELPERS)] == current, 'exact inverse appended current helpers')
    compile(derived, '<UNADOPTED-complete-retained-current-consumer>', 'exec')
    receipt['before_helper_append'] = pin(current); receipt['appended_helpers'] = pin(NEW_CURRENT_HELPERS)
    receipt['derived_source'] = pin(derived)
    for name in ('reviewed_source_parent_records', '_source_parent_original', 'exact_descriptor', 'current_context',
                 'boundary_from_original', 'closed_boundary_originals', 'source_parent_boundary_from_original',
                 'source_parent_closed_boundary_originals', 'require_failed_ancestor_tail', 'inventory_value'):
        need(function_source(derived,name) == function_source(v4_source,name), 'sealed v4 selected guard remains exact: ' + name)
    return derived, receipt


def result_envelope(kind, method, value, provenance):
    return {'schema': 'hepta.UNADOPTED.retained-current-result.v1', 'producer_kind': kind,
            'method': method, 'historical_result': value, 'execution_provenance': provenance,
            'historical_result_is_old_execution_attestation': False, 'production_adopted': False,
            'runtime_admission': False, 'current_native_case_credit': 0, 'whole_stage_budget_verified': False}


def decode_result(envelope, *, kind, method, expected_provenance):
    need(type(envelope) is dict and set(envelope) == {'schema', 'producer_kind', 'method', 'historical_result',
        'execution_provenance', 'historical_result_is_old_execution_attestation', 'production_adopted',
        'runtime_admission', 'current_native_case_credit', 'whole_stage_budget_verified'},
        'exact new retained result envelope required')
    need(envelope['schema'] == 'hepta.UNADOPTED.retained-current-result.v1'
         and envelope['producer_kind'] == kind and envelope['method'] == method,
         'retained result producer kind, method or schema differs')
    need(envelope['historical_result_is_old_execution_attestation'] is False
         and envelope['production_adopted'] is False and envelope['runtime_admission'] is False
         and type(envelope['current_native_case_credit']) is int and envelope['current_native_case_credit'] == 0
         and envelope['whole_stage_budget_verified'] is False,
         'retained result cannot promote history, adoption, admission, budget or current credit')
    need(type(envelope['execution_provenance']) is dict
         and encoded(envelope['execution_provenance']) == encoded(expected_provenance),
         'retained result must bind the actual same in-process producer execution provenance')
    result = envelope['historical_result']
    if method.startswith('verify') or method in ('current_binding','validate_observation','validate_manifest'):
        need(type(result) is dict, 'retained verification data projection must remain an object')
    elif method in ('validate_private_preservation','preserve'):
        need(result is True, 'retained preservation data projection must preserve True')
    elif method == 'source_parent_inventory':
        need(type(result) is tuple and len(result) == 3 and type(result[0]) is dict
             and type(result[1]) is dict and type(result[2]) is str,
             'retained source-parent inventory data must preserve the complete original tuple')
    return result


class RetainedReader:
    __slots__ = ('_kind', '_selected', '_selector', '_constructor_identity')
    def __init__(self, kind, selected, selector, constructor_identity):
        object.__setattr__(self,'_kind',kind); object.__setattr__(self,'_selected',selected)
        object.__setattr__(self,'_selector',selector); object.__setattr__(self,'_constructor_identity',encoded(constructor_identity))
    def __setattr__(self,name,value):
        raise AttributeError('retained derived reader facade is immutable')
    def provenance(self):
        value=self._selected
        return {'schema':'hepta.UNADOPTED.retained-reader-execution.v1','kind':self._kind,
            'constructor_source':json.loads(self._constructor_identity),'selector_source':dict(V2_SELECTOR),
            'selector_loader_source':dict(V2_LOADER),'historical_reader_data_source':dict(value.__reference_source_identity__),
            'actual_derived_reader_source':dict(value.__derived_implementation_identity__),
            'module_name':value.__name__,'module_file':value.__file__,
            'construction_receipt':self._selector.receipt(),'fresh_derived_module_globals':True,
            'historical_source_bytes_changed':False,'historical_result_is_old_execution_attestation':False,
            'validation_result_cache':False,'live_observation_cache':False,'production_adopted':False,
            'runtime_admission':False,'current_native_case_credit':0,'whole_stage_budget_verified':False}
    def __getattr__(self,name):
        if name in READER_DATA[self._kind]:
            return copy.deepcopy(getattr(self._selected,name))
        if self._kind=='r7-reader' and name=='original_descriptor':
            return self._selected.original_descriptor
        if name not in READER_METHODS[self._kind]:
            raise AttributeError(name)
        def invoke(*args,**kwargs):
            value=getattr(self._selected,name)(*args,**kwargs)
            return result_envelope(self._kind,name,value,self.provenance())
        return invoke


class RetainedAdapter:
    __slots__ = ('_selected','_provenance')
    def __init__(self, selected, provenance):
        object.__setattr__(self,'_selected',selected); object.__setattr__(self,'_provenance',encoded(provenance))
    def __setattr__(self,name,value):
        raise AttributeError('retained derived adapter facade is immutable')
    def provenance(self):
        return json.loads(self._provenance)
    def __getattr__(self,name):
        if name in ('proof','binding'):
            return copy.deepcopy(getattr(self._selected,name))
        if name in ('read_pinned','host_reader','reader'):
            return getattr(self._selected,name)
        if name not in ADAPTER_METHODS:
            raise AttributeError(name)
        def invoke(*args,**kwargs):
            result=getattr(self._selected,name)(*args,**kwargs)
            return result_envelope('r9-runtime-adapter',name,result,self.provenance())
        return invoke


def consume_reader_call(reader, kind, method, *args, **kwargs):
    need(type(reader) is RetainedReader and reader._kind == kind and method in READER_METHODS[kind],
         'actual bound retained reader type, kind and method required')
    envelope=getattr(reader,method)(*args,**kwargs)
    return decode_result(envelope,kind=kind,method=method,expected_provenance=reader.provenance())


def consume_adapter_call(adapter, method, *args, **kwargs):
    need(type(adapter) is RetainedAdapter and method in ADAPTER_METHODS,
         'actual bound new retained adapter type and method required')
    envelope=getattr(adapter,method)(*args,**kwargs)
    return decode_result(envelope,kind='r9-runtime-adapter',method=method,expected_provenance=adapter.provenance())


class CurrentConsumer:
    __slots__ = ('_methods','_provenance')
    def __init__(self, methods, provenance):
        need(set(methods)==set(METHODS) and all(callable(v) for v in methods.values()),'exact current combined consumer entries')
        object.__setattr__(self,'_methods',types.MappingProxyType(dict(methods)))
        object.__setattr__(self,'_provenance',encoded(provenance))
    def __setattr__(self,name,value):
        raise AttributeError('complete current retained consumer is immutable')
    def provenance(self):
        return json.loads(self._provenance)
    def __getattr__(self,name):
        if name not in self._methods:
            raise AttributeError(name)
        def invoke(*args,**kwargs):
            result=self._methods[name](*args,**kwargs)
            return result_envelope('current-retained-consumer',name,result,self.provenance())
        return invoke


def construct(*, current_source, historical_sources, historical_adapter_source,
              v4_constructor_source, v4_loader_source, v3_constructor_source, v3_loader_source,
              v2_selector_source, v2_loader_source, inventory_function, scope_function,
              read_stage_original, read_retained_original, implementation_source):
    need(type(implementation_source) is bytes and implementation_source==globals().get('__constructor_loaded_source__'),
         'declared v5 constructor must equal actual bound compiled source bytes')
    for raw,expected,name in ((current_source,FROZEN_CURRENT,'frozen current'),
        (historical_adapter_source,ORIGINAL_ADAPTER,'historical adapter'),
        (v4_constructor_source,V4_CONSTRUCTOR,'v4 constructor'),(v4_loader_source,V4_LOADER,'v4 loader'),
        (v3_constructor_source,V3_CONSTRUCTOR,'v3 constructor'),(v3_loader_source,V3_LOADER,'v3 loader'),
        (v2_selector_source,V2_SELECTOR,'v2 selector'),(v2_loader_source,V2_LOADER,'v2 loader')):
        need(pin(raw)==expected,'exact independent source dependency: '+name)
    need(type(historical_sources) is dict and callable(read_stage_original) and callable(read_retained_original),
         'explicit exact source bytes and original providers required')
    sources=dict(historical_sources); identity=pin(implementation_source)
    v4=module(v4_loader_source,'UNADOPTED_v5_exact_v4_loader').load_bound(v4_constructor_source,v4_constructor_source)
    v4_current,v4_transformation=v4.derive_source(current_source,inventory_function)
    selected_current,current_transformation=derive_current(v4_current); current_pin=pin(selected_current)
    selected_adapter,adapter_transformation=derive_adapter(historical_adapter_source); adapter_pin=pin(selected_adapter)
    v3=module(v3_loader_source,'UNADOPTED_v5_exact_v3_loader').load_bound(v3_constructor_source,v3_constructor_source)
    v2loader=module(v2_loader_source,'UNADOPTED_v5_exact_v2_loader')
    def fresh_source_parent():
        return v3.construct(sources=dict(sources),inventory_function=inventory_function,
                            read_pinned=read_stage_original,implementation_source=v3_constructor_source)
    expected_v3_provenance=encoded(fresh_source_parent().provenance())
    def fresh_retained(kind,original):
        need(kind in READER_METHODS,'fixed retained reader kind')
        selector=v2loader.make_selector(selector_source=v2_selector_source,implementation_source=v2_selector_source,
                                       inventory_function=inventory_function,scope_function=scope_function)
        selected={'r7-reader':selector.r7_reader,'r8-reader':selector.r8_reader,'r9-reader':selector.r9_reader}[kind](original)
        reader=RetainedReader(kind,selected,selector,identity)
        return reader
    def fresh_adapter(*,original_source,common,expected_inputs_sha256,historical_adapter_source,
                      prior,old_read_pinned,inventory_reader,supplied):
        need(pin(original_source)==ORIGINAL_ADAPTER,'same actual historical adapter bytes after current read gate')
        raw,transformation=derive_adapter(original_source)
        need(pin(raw)==adapter_pin and transformation==adapter_transformation,'same exact newly derived adapter source')
        selected=types.ModuleType('UNADOPTED_retained_adapter_'+adapter_pin['sha256'][:16])
        selected.__file__='<UNADOPTED-derived-retained-adapter:'+adapter_pin['sha256']+'>'
        selected.__UNADOPTED_retained_reader_factory__=fresh_retained
        selected.__UNADOPTED_consume_retained_call__=consume_reader_call
        exec(compile(raw,selected.__file__,'exec'),selected.__dict__)
        adapter=selected.Adapter(common=common,expected_inputs_sha256=expected_inputs_sha256,
            historical_adapter_source=historical_adapter_source,prior=prior,old_read_pinned=old_read_pinned,
            inventory_reader=inventory_reader,supplied=supplied)
        return RetainedAdapter(adapter,{'schema':'hepta.UNADOPTED.current-retained-adapter-execution.v1',
            'constructor_source':identity,'historical_adapter_data_source':dict(ORIGINAL_ADAPTER),
            'historical_adapter_data_descriptor':copy.deepcopy(historical_adapter_source),
            'actual_derived_adapter_source':dict(adapter_pin),'module_name':selected.__name__,'module_file':selected.__file__,
            'actual_current_consumer_source':dict(current_pin),'selected_v2_source':dict(V2_SELECTOR),
            'fresh_derived_module_globals':True,'original_adapter_bytes_changed':False,
            'old_adapter_descriptor_is_execution_attestation':False,'validation_result_cache':False,
            'runtime_admission':False,'production_adopted':False,'current_native_case_credit':0,
            'whole_stage_budget_verified':False})
    saved_path=sys.path[:];saved_dwb=sys.dont_write_bytecode
    present='component_common' in sys.modules;saved=sys.modules.get('component_common')
    try:
        need(pin(sources['source/component_common.py'])==COMMON,'exact original common for new current module')
        sys.dont_write_bytecode=True
        common=types.ModuleType('component_common');common.__file__='<exact-common:'+COMMON['sha256']+'>'
        common.__reviewed_source_sha256__=COMMON['sha256'];sys.modules['component_common']=common
        exec(compile(sources['source/component_common.py'],common.__file__,'exec'),common.__dict__)
        selected=types.ModuleType('UNADOPTED_complete_retained_current_'+current_pin['sha256'][:16])
        selected.__file__='<UNADOPTED-complete-retained-current:'+current_pin['sha256']+'>'
        selected.__frozen_current_data_source__=current_source
        selected.__derived_consumer_source__=selected_current
        selected.__derived_consumer_source_descriptor__=current_pin
        selected.__reviewed_package_sources__=dict(sources,**{'source/late_boundary.py':selected_current})
        selected.__UNADOPTED_source_parent_reader_factory__=fresh_source_parent
        selected.__UNADOPTED_source_parent_expected_provenance__=expected_v3_provenance
        selected.__retained_stage_read_pinned__=read_stage_original
        selected.__retained_preaccept_read_pinned__=read_retained_original
        selected.__retained_failed_staged_read_pinned__=read_retained_original
        selected.__retained_failed_transport_read_pinned__=read_retained_original
        selected.__retained_failed_transport_adapter_read_pinned__=read_retained_original
        selected.__UNADOPTED_retained_reader_factory__=fresh_retained
        selected.__UNADOPTED_retained_adapter_factory__=fresh_adapter
        selected.__UNADOPTED_consume_retained_call__=consume_reader_call
        selected.__UNADOPTED_consume_adapter_call__=consume_adapter_call
        exec(compile(selected_current,selected.__file__,'exec'),selected.__dict__)
        need(selected.C is common and '__reviewed_source_sha256__' not in selected.__dict__
             and selected.consumer_execution_source_sha256()==current_pin['sha256']
             and selected.consumer_frozen_data_source_sha256()==FROZEN_CURRENT['sha256'],
             'new combined current execution and frozen publisher data identities remain distinct')
        disabled=('main','publish','verify_current','chain_originals','retired_originals','current_inventory',
                  'verify_current_package','fresh_retained_failed_transport_absence','retained_failed_transport_external_originals')
        for name in disabled:
            selected.__dict__.pop(name,None)
        for name in METHODS:
            need(getattr(selected,name).__globals__ is selected.__dict__,'fresh combined current method globals: '+name)
        provenance={'schema':'hepta.UNADOPTED.complete-retained-current-consumer.v5',
            'constructor_source':identity,'historical_frozen_current_data_source':dict(FROZEN_CURRENT),
            'intermediate_v4_source_construction':dict(V4_DERIVED_CURRENT),
            'actual_current_execution_source':current_pin,'actual_adapter_execution_source':adapter_pin,
            'v4_constructor_source':dict(V4_CONSTRUCTOR),'v4_bound_loader_source':dict(V4_LOADER),
            'v3_constructor_source':dict(V3_CONSTRUCTOR),'v3_bound_loader_source':dict(V3_LOADER),
            'v2_selector_source':dict(V2_SELECTOR),'v2_bound_loader_source':dict(V2_LOADER),
            'source_parent_provenance':json.loads(expected_v3_provenance),'common_source':dict(COMMON),
            'v4_transformation':v4_transformation,'current_transformation':current_transformation,
            'adapter_transformation':adapter_transformation,'methods':list(METHODS),'disabled_entries':list(disabled),
            'module_name':selected.__name__,'module_file':selected.__file__,'fresh_derived_module_globals':True,
            'historical_source_bytes_changed':False,'old_execution_receipts_reused':False,
            'standalone_r7_r8_and_nested_r9_r8_r7_selected':True,
            'current_inventory_and_complete_source_parent_selected':True,
            'retained_producer_envelopes_consumed_by_actual_current_guards':True,
            'validation_result_cache':False,'live_observation_cache':False,
            'input_provider_implementation_attested':False,'runtime_admission':False,'production_adopted':False,
            'current_native_case_credit':0,'complete_production_IO_metering_verified':False,
            'whole_stage_budget_verified':False,'new_current_prefix_qualification_verified':False}
        return CurrentConsumer({name:getattr(selected,name) for name in METHODS},provenance)
    finally:
        sys.path[:]=saved_path;sys.dont_write_bytecode=saved_dwb
        if present:sys.modules['component_common']=saved
        else:sys.modules.pop('component_common',None)
