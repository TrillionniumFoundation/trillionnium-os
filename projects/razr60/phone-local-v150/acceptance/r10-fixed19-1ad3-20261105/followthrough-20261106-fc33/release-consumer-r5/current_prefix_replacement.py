def current_closed_lease_roots(boundary, inventory, closure, late, *,
                               read_pinned, combination_descriptor):
    """Derive only this closed case's three roots from its original lease bytes.

    The enclosing reader has already validated the complete inventory and the
    independent closure. Its file entry supplies the exact phone descriptor;
    the existing original-copy callback supplies bytes, never a live read.
    """
    path = closure.get('lease_source_path')
    need(type(path) is str, 'current closure omitted its original lease path')
    lease_path = Path(path)
    need(lease_path.is_absolute() and str(lease_path) == path
         and '..' not in lease_path.parts and lease_path.name == 'LEASE.json'
         and lease_path.parent.parent == Path(BASE)/'native-guard-r10-r1',
         'current lease left the exact component home namespace')
    entry = inventory['entries'].get(path)
    need(type(entry) is dict and set(entry) == {'kind', 'metadata', 'bytes', 'sha256'}
         and entry['kind'] == 'file' and type(entry['bytes']) is int
         and 0 < entry['bytes'] <= 262144,
         'current complete inventory omitted the bounded original lease file')
    row = {'path': path, **{key: entry[key] for key in ('bytes', 'sha256', 'metadata')}}
    late.exact_descriptor(row, expected_path=lease_path)
    raw = read_pinned(row)
    need(type(raw) is bytes and descriptor(raw) == {key: row[key] for key in ('bytes', 'sha256')}
         and row['sha256'] == closure.get('lease_sha256'),
         'current lease original differs from the complete inventory or closure')
    lease = strict(raw)
    need(type(lease) is dict and set(lease) == {'schema', 'label', 'boot_id', 'case_id',
        'nonce', 'owner_request_sha256', 'selected_session_id', 'selected_profile_id',
        'expires_unix_ms', 'combination', 'retirement', 'prior_boundary',
        'android_journal', 'package_sha256'}
        and lease['schema'] == 'hepta.native-guard.lease.v1'
        and type(lease['label']) is str
        and re.fullmatch('[a-z0-9][a-z0-9-]{5,55}', lease['label']),
        'current original lease schema or label differs')
    home = Path(BASE)/'native-guard-r10-r1'/lease['label']
    journal = ANDROID_BASE+'/native-guard-r10-r1/'+lease['label']+'/executor'
    need(lease_path == home/'LEASE.json' and lease['android_journal'] == journal
         and type(lease['expires_unix_ms']) is int and lease['expires_unix_ms'] > 0,
         'current original lease home, journal or historical expiry differs')
    for key in ('boot_id', 'nonce', 'case_id', 'owner_request_sha256', 'package_sha256',
                'retirement', 'prior_boundary'):
        need(encode(lease[key]) == encode(boundary[key]) == encode(closure[key]),
             'current original lease/closed binding differs: '+key)
    for key in ('session_id', 'profile_id'):
        need(encode(lease['selected_'+key]) == encode(boundary['scope'][key])
             == encode(closure['scope'][key]),
             'current original lease selected scope differs: '+key)
    need(type(lease['combination']) is dict and set(lease['combination']) == {'bytes', 'sha256'}
         and type(lease['combination']['bytes']) is int
         and encode(lease['combination']) == encode(combination_descriptor)
         and lease['combination']['sha256'] == CURRENT_COMBINATION_SHA,
         'current original lease does not bind the actual complete current combination')
    return ['/proc/1/root'+journal, str(home),
            '/proc/1/root/data/local/tmp/hepta-native-guard-'+lease['nonce']]


def validate_final_component_prefix(chain, late, retained, *, read_pinned,
                                    combination_descriptor):
    records = late.reviewed_source_parent_records()
    need(type(CURRENT_COMPONENT_CHAIN_LENGTH) is int
         and CURRENT_COMPONENT_CHAIN_LENGTH == late.MAX_CHAIN
         == late.HISTORICAL_FAILED_BOUNDARY_COUNT+len(records)+late.MAX_NEW_CURRENT_CASE_PREFIX
         and late.HISTORICAL_FAILED_BOUNDARY_COUNT == 9
         and late.MAX_NEW_CURRENT_CASE_PREFIX == 2
         and type(COMPONENT_ROLE_BUDGET) is int
         and COMPONENT_ROLE_BUDGET == late.COMPONENT_ROLE_CAP
         == 3*(CURRENT_COMPONENT_CHAIN_LENGTH+2)
         and len(chain) == CURRENT_COMPONENT_CHAIN_LENGTH,
         'production release requires two new current cases, exact source parents and nine fixed failed ancestors')
    prefix = chain[:2]
    need([row[0]['case_id'] for row in prefix] == ['NEG-02', 'NEG-01'],
         'closed current cases must be supplied latest-first after actual new NEG01 then NEG02')
    parents = chain[2:2+len(records)]
    for (boundary, inventory, closure), record in zip(parents, records):
        need(late.is_source_parent_ancestor(boundary)
             and record['boundary']['path'] == str(late.ROOT/(boundary['nonce']+'.json'))
             and encode(boundary['inventory']) == encode(record['inventory'])
             and encode(boundary['closure']) == encode(record['closure'])
             and boundary['roots'] == inventory['roots'],
             'only exact preceding-source originals may occupy the source-parent prefix')
    need(all(row[0]['component_qualified'] is False and row[0]['native_status'] == 'provider_failed'
             for row in chain[2+len(records):]),
         'fixed historical failures do not provide new component qualification')
    roots = list(parents[0][1]['roots'])
    need(len(roots) == late.SOURCE_PARENT_INVENTORY_ROOT_COUNT,
         'new current prefix must begin at the complete actual source-parent inventory')
    for boundary, inventory, closure in reversed(prefix):
        need(boundary['schema'] == late.SCHEMA and boundary['package_sha256'] == PACKAGE_SHA
             and boundary['combination_sha256'] == CURRENT_COMBINATION_SHA
             and not late.is_source_parent_ancestor(boundary)
             and boundary['component_qualified'] is True and boundary['native_status'] == 'completed'
             and closure['component_qualified'] is True and closure['native_status'] == 'completed'
             and type(closure['unknown_effects']) is int and closure['unknown_effects'] == 0,
             'both exact new current NEG component cases must actually qualify')
        late.current_retained_stage_binding(boundary); late.current_retained_stage_binding(closure)
        late.preserve_retained_unstarted_stage(inventory, retained=retained)
        late.validate_retained_stage_parent_profiles(retained, closure['retained_stage_parent_profiles'], inventory)
        added = current_closed_lease_roots(boundary, inventory, closure, late,
            read_pinned=read_pinned, combination_descriptor=combination_descriptor)
        need(len(added) == len(set(added)) == 3 and not (set(added) & set(roots)),
             'new current case reuses a retained private root')
        roots = roots+added
        need(boundary['roots'] == inventory['roots'] == roots
             and boundary['retained_stage_parent_profiles'] == closure['retained_stage_parent_profiles'],
             'current final inventory must preserve exact ordered baseline roots and add only its three lease-bound roots')
    need(len(roots) == late.MAX_CURRENT_INVENTORY_ROOTS,
         'two new current closures must match the reviewed complete inventory budget')
