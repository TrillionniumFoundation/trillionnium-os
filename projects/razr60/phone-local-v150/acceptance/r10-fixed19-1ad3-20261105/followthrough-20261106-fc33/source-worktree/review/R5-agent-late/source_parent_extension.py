def reviewed_source_parent_records():
    """The exact closed prefix from the preceding source tuple, newest first."""
    C.need(type(SOURCE_PARENT_RECORDS) is tuple and len(SOURCE_PARENT_RECORDS) == SOURCE_PARENT_COUNT
           and 1 <= SOURCE_PARENT_COUNT <= 2,
           'only the explicitly reviewed preceding source prefix is admitted')
    rows = C.strict(C.encoded(list(SOURCE_PARENT_RECORDS)))
    expected_keys = {'boundary', 'inventory', 'closure', 'closed_previous', 'label', 'home',
        'case_id', 'nonce', 'scope', 'roots', 'private_roots', 'prior_boundary',
        'component_qualified', 'native_status', 'actual_native_calls', 'owner_request_sha256',
        'closure_source_sha256'}
    seen_nonce = set(); seen_scope = set(); seen_homes = set()
    for index, row in enumerate(rows):
        C.need(type(row) is dict and set(row) == expected_keys,
               'source-parent record fields differ from the actual published record')
        C.need(type(row['nonce']) is str and re.fullmatch('[0-9a-f]{32}', row['nonce'])
               and type(row['label']) is str and re.fullmatch('[a-zA-Z0-9_.-]+', row['label'])
               and row['case_id'] in ('NEG-01', 'NEG-02'), 'exact source-parent identity required')
        C.scope(row['scope'])
        key = tuple(row['scope'][name] for name in C.SCOPE)
        C.need(row['nonce'] not in seen_nonce and key not in seen_scope
               and row['home'] not in seen_homes, 'source-parent identities repeat')
        seen_nonce.add(row['nonce']); seen_scope.add(key); seen_homes.add(row['home'])
        home = C.BASE/'native-guard-r10-r1'/row['label']
        expected_roots = [str(C.ANDROID/'data/trillionnium/owner-open/state/phone-local-v150'
                              /'native-guard-r10-r1'/row['label']/'executor'),
                          str(home), str(C.ANDROID/'data/local/tmp'/('hepta-native-guard-'+row['nonce']))]
        C.need(row['home'] == str(home) and row['private_roots'] == expected_roots
               and type(row['roots']) is list and len(row['roots']) == len(set(row['roots']))
               and set(expected_roots) <= set(row['roots'])
               and len(row['roots']) == RETAINED_BASE_ROOT_COUNT + 3*(SOURCE_PARENT_COUNT-index),
               'source-parent cumulative roots differ from its actual three-root growth')
        for kind, name in (('boundary', row['nonce']+'.json'),
                           ('inventory', row['nonce']+'/AFTER-INVENTORY.original.json'),
                           ('closure', row['nonce']+'/CLOSURE.original.json')):
            exact_descriptor(row[kind], expected_path=ROOT/name)
        expected_prior = (rows[index+1]['boundary'] if index+1 < len(rows)
                          else reviewed_v3_runtime_diagnostic_ancestor()['boundary'])
        C.need(row['prior_boundary'] == expected_prior,
               'source-parent prefix must retain the exact preceding full original descriptor')
        cp = row['closed_previous']
        C.need(type(cp) is dict and set(cp) == {'path', 'bytes', 'sha256'}
               and type(cp['bytes']) is int and 0 < cp['bytes'] <= 65536
               and type(cp['path']) is str and Path(cp['path']).is_absolute()
               and str(Path(cp['path'])) == cp['path'] and '..' not in Path(cp['path']).parts
               and type(cp['sha256']) is str and C.HASH.fullmatch(cp['sha256']),
               'exact prior host publication input pin required')
        C.need(type(row['component_qualified']) is bool
               and row['native_status'] in ('completed', 'provider_failed', 'cancelled')
               and type(row['actual_native_calls']) is int and 0 <= row['actual_native_calls'] <= 2
               and (not row['component_qualified'] or
                    (row['native_status'] == 'completed' and row['actual_native_calls'] == 2))
               and row['closure_source_sha256'] == SOURCE_PARENT_CLOSURE_SHA256
               and type(row['owner_request_sha256']) is str
               and C.HASH.fullmatch(row['owner_request_sha256']),
               'source-parent outcome or closure source was reinterpreted')
    C.need(len(seen_homes) == SOURCE_PARENT_HOME_COUNT
           and len(rows[0]['roots']) == SOURCE_PARENT_INVENTORY_ROOT_COUNT
           and SOURCE_PARENT_INVENTORY_ROOT_COUNT == RETAINED_BASE_ROOT_COUNT+3*SOURCE_PARENT_HOME_COUNT,
           'actual preceding source homes and inventory resource accounting differ')
    return rows


def source_parent_private_roots():
    return [root for row in reviewed_source_parent_records() for root in row['private_roots']]


def source_parent_homes():
    return sorted(row['home'] for row in reviewed_source_parent_records())


def is_source_parent_ancestor(value):
    if type(value) is not dict:
        return False
    pin = C.descriptor(C.encoded(value))
    return any(pin == {key:row['boundary'][key] for key in ('bytes', 'sha256')}
               for row in reviewed_source_parent_records())


def _source_parent_original(raw, original_descriptor):
    C.need(type(raw) is bytes, 'source-parent classification requires original bytes')
    pin = C.descriptor(raw)
    for row in reviewed_source_parent_records():
        if pin == {key:row['boundary'][key] for key in ('bytes', 'sha256')}:
            C.need(original_descriptor == row['boundary'],
                   'source-parent bytes require their exact path and all nine metadata integers')
            return row
    return None


_SOURCE_PARENT_READER_METHODS = ('boundary_from_original', 'closed_boundary_originals',
                                 'require_failed_ancestor_tail')


class SourceParentReader:
    """Only original R4 pure entrypoints, with their own original module globals."""
    __slots__ = ('_methods', '_provenance')

    def __init__(self, methods, provenance):
        from types import MappingProxyType
        C.need(set(methods) == set(_SOURCE_PARENT_READER_METHODS)
               and all(callable(method) for method in methods.values()),
               'the three exact source-parent reader methods are required')
        object.__setattr__(self, '_methods', MappingProxyType(dict(methods)))
        object.__setattr__(self, '_provenance', C.encoded(provenance))

    def __getattr__(self, name):
        try:
            return self._methods[name]
        except KeyError:
            raise AttributeError(name) from None

    def __setattr__(self, name, value):
        raise AttributeError('source-parent reader is immutable')

    def provenance(self):
        return C.strict(self._provenance)


def source_parent_reader():
    """Load byte-exact old sources; never bind old publisher identity to new code."""
    import types
    package = Path(__file__).parent.parent
    supplied = globals().get('__reviewed_package_sources__')
    C.need(supplied is None or type(supplied) is dict,
           'reviewed source-parent package overlay must be an explicit byte map')
    sources = {}
    for name, descriptor in SOURCE_PARENT_READER_DEPENDENCIES.items():
        raw = (C.read(package/name, 16*1024*1024, private=False) if supplied is None
               else supplied.get(name))
        C.need(type(raw) is bytes and C.descriptor(raw) == descriptor,
               'exact original source-parent reader dependency differs: '+name)
        sources[name] = raw
    old_raw = sources[SOURCE_PARENT_REFERENCE]
    # All nested readers consult this old source slot for code provenance.
    # A new source/late_boundary.py must never be visible through this overlay.
    overlay = dict(sources)
    overlay['source/late_boundary.py'] = old_raw
    present = 'component_common' in sys.modules
    saved = sys.modules.get('component_common')
    old_path = sys.path[:]; old_dwb = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        common = types.ModuleType('component_common')
        common.__file__ = str(package/'source/component_common.py')
        common.__reviewed_source_sha256__ = SOURCE_PARENT_COMMON_SHA256
        sys.modules['component_common'] = common
        exec(compile(sources['source/component_common.py'], common.__file__, 'exec'), common.__dict__)
        old = types.ModuleType('reviewed_source_parent_late_boundary_r4')
        old.__file__ = str(package/SOURCE_PARENT_REFERENCE)
        old.__reviewed_source_sha256__ = SOURCE_PARENT_READER_SHA256
        old.__reviewed_package_sources__ = overlay
        callback = globals().get('__retained_stage_read_pinned__')
        if callback is not None:
            C.need(callable(callback), 'explicit retained original callback must be callable')
            old.__retained_stage_read_pinned__ = callback
        exec(compile(old_raw, old.__file__, 'exec'), old.__dict__)
        C.need(old.C is common
               and old.reviewed_source_sha256() == SOURCE_PARENT_READER_SHA256
               and old.REVIEWED_CURRENT_COMBINATION_SHA256 == SOURCE_PARENT_COMBINATION_SHA256
               and old.REVIEWED_CURRENT_POLICY_SHA256 == SOURCE_PARENT_POLICY_SHA256
               and old.REVIEWED_CURRENT_POLICY_ADOPTION_SHA256 == SOURCE_PARENT_POLICY_ADOPTION_SHA256
               and old.MAX_CHAIN == 11
               and old.REVIEWED_RETAINED_STAGE_BINDING == REVIEWED_RETAINED_STAGE_BINDING,
               'source-parent original module globals or published identity changed')
        for name in _SOURCE_PARENT_READER_METHODS:
            C.need(getattr(old, name).__globals__ is old.__dict__,
                   'source-parent method lost its original module globals')
        C.need(old.__reviewed_package_sources__['source/late_boundary.py'] == old_raw
               and C.descriptor(old_raw) == {'bytes': SOURCE_PARENT_READER_BYTES,
                                            'sha256': SOURCE_PARENT_READER_SHA256},
               'source-parent self-source overlay differs')
        for name in ('main', 'publish', 'verify_current'):
            old.__dict__.pop(name, None)
        provenance = {'schema': 'hepta.native-guard.exact-source-parent-reader.v1',
            'source': {'bytes': SOURCE_PARENT_READER_BYTES, 'sha256': SOURCE_PARENT_READER_SHA256},
            'common': {'bytes': 19138, 'sha256': SOURCE_PARENT_COMMON_SHA256},
            'combination_sha256': SOURCE_PARENT_COMBINATION_SHA256,
            'package_sha256': SOURCE_PARENT_PACKAGE_SHA256,
            'original_module_globals': True, 'old_source_slot_overlay': True,
            'historical_reader_functions_changed': False,
            'historical_publisher_identity_changed': False,
            'validation_result_cache': False, 'current_tuple_credit': False,
            'methods': list(_SOURCE_PARENT_READER_METHODS)}
        return SourceParentReader({name:getattr(old, name) for name in _SOURCE_PARENT_READER_METHODS},
                                  provenance)
    finally:
        sys.path[:] = old_path; sys.dont_write_bytecode = old_dwb
        if present:
            sys.modules['component_common'] = saved
        else:
            sys.modules.pop('component_common', None)


def source_parent_boundary_from_original(raw, *, original_descriptor):
    record = _source_parent_original(raw, original_descriptor)
    C.need(record is not None, 'only an exact explicitly reviewed source-parent original is admitted')
    value = source_parent_reader().boundary_from_original(raw, original_descriptor=original_descriptor,
        combination_sha256=SOURCE_PARENT_COMBINATION_SHA256, package_sha256=SOURCE_PARENT_PACKAGE_SHA256)
    for key in ('inventory', 'closure', 'case_id', 'nonce', 'scope', 'roots', 'prior_boundary',
                'component_qualified', 'native_status', 'actual_native_calls', 'owner_request_sha256'):
        C.need(value[key] == record[key], 'source-parent original field differs: '+key)
    C.need(value['publisher_source_sha256'] == SOURCE_PARENT_READER_SHA256
           and value['package_sha256'] == SOURCE_PARENT_PACKAGE_SHA256
           and value['combination_sha256'] == SOURCE_PARENT_COMBINATION_SHA256
           and value['retained_stage_parent_profiles']['allowed_new_homes'] ==
               sorted(row['home'] for row in reviewed_source_parent_records()
                      if row['home'] in value['roots']),
           'source-parent source tuple or actual home accounting changed')
    return value


def source_parent_closed_boundary_originals(raw, inventory_raw, closure_raw, *, original_descriptor):
    value = source_parent_boundary_from_original(raw, original_descriptor=original_descriptor)
    checked, inventory, closure = source_parent_reader().closed_boundary_originals(
        raw, inventory_raw, closure_raw, original_descriptor=original_descriptor,
        combination_sha256=SOURCE_PARENT_COMBINATION_SHA256, package_sha256=SOURCE_PARENT_PACKAGE_SHA256)
    C.need(checked == value and closure.get('closure_source_sha256') == SOURCE_PARENT_CLOSURE_SHA256,
           'source-parent closed result or original closure source changed')
    C.need(inventory['roots'] == value['roots'], 'source-parent complete roots changed')
    return checked, inventory, closure


def manifest_source_parent_binding():
    """Exact manifest fields derived from the actual retained source prefix."""
    rows = reviewed_source_parent_records()
    return {'runtime_file_count': 38,
        'source_parent_reader': {'path': SOURCE_PARENT_REFERENCE, 'bytes': SOURCE_PARENT_READER_BYTES,
                                 'sha256': SOURCE_PARENT_READER_SHA256},
        'source_parent_records': rows,
        'source_parent_combination_sha256': SOURCE_PARENT_COMBINATION_SHA256,
        'source_parent_package_sha256': SOURCE_PARENT_PACKAGE_SHA256,
        'source_parent_native_boundary_count': SOURCE_PARENT_COUNT,
        'source_parent_home_count': SOURCE_PARENT_HOME_COUNT,
        'source_parent_private_roots': source_parent_private_roots(),
        'historical_failed_native_boundary_count': HISTORICAL_FAILED_BOUNDARY_COUNT,
        'historical_native_boundary_count': HISTORICAL_FAILED_BOUNDARY_COUNT+SOURCE_PARENT_COUNT,
        'source_parent_qualification_is_current_tuple_credit': False,
        'component_role_cap': COMPONENT_ROLE_CAP, 'native_chain_cap': MAX_CHAIN,
        'fixture_root_cap': MAX_FIXTURE_ROOTS,
        'maximum_new_current_case_prefix': MAX_NEW_CURRENT_CASE_PREFIX,
        'current_complete_inventory_root_count': SOURCE_PARENT_INVENTORY_ROOT_COUNT,
        'maximum_complete_inventory_roots_after_two_final_NEG_cases': MAX_CURRENT_INVENTORY_ROOTS}
