def require_failed_ancestor_tail(values):
    """New prefix, exact old source prefix, then all nine original failed bytes."""
    records = reviewed_source_parent_records()
    retained_count = HISTORICAL_FAILED_BOUNDARY_COUNT+len(records)
    C.need(type(values) is list and retained_count <= len(values) <= MAX_CHAIN,
           'all exact source-parent originals and the original nine failures are required')
    current_count = len(values)-retained_count
    C.need(0 <= current_count <= MAX_NEW_CURRENT_CASE_PREFIX,
           'only two newly closed cases belong to the new source tuple')
    history = values[current_count:]
    old = source_parent_reader()
    for value, record in zip(history[:len(records)], records):
        raw = C.encoded(value)
        C.need(C.descriptor(raw) == {k:record['boundary'][k] for k in ('bytes','sha256')},
               'source-parent prefix was omitted, reordered, altered or duplicated')
        checked = old.boundary_from_original(raw, original_descriptor=record['boundary'],
            combination_sha256=SOURCE_PARENT_COMBINATION_SHA256, package_sha256=SOURCE_PARENT_PACKAGE_SHA256)
        C.need(checked == value, 'source-parent original reader changed its result')
    # The unchanged old function checks the old current prefix and all nine
    # exact historical canonical boundary bytes, full predecessor IDs and counts.
    old.require_failed_ancestor_tail(history)
    seen_nonce = set(); seen_scope = set(); current_package = None
    for index, value in enumerate(values):
        key = tuple(value['scope'][name] for name in C.SCOPE)
        C.need(value['nonce'] not in seen_nonce and key not in seen_scope,
               'closed boundary repeats a nonce or native scope across source tuples')
        seen_nonce.add(value['nonce']); seen_scope.add(key)
        if index < current_count:
            if current_package is None:
                current_package = value['package_sha256']
            C.need(value['package_sha256'] == current_package,
                   'new component prefix changes its source-package generation')
            boundary_value(value, combination_sha256=REVIEWED_CURRENT_COMBINATION_SHA256,
                           package_sha256=current_package)
            following = values[index+1]; prior = value['prior_boundary']
            C.need(prior is not None
                   and prior['path'] == str(ROOT/(following['nonce']+'.json'))
                   and {k:prior[k] for k in ('bytes','sha256')} == C.descriptor(C.encoded(following)),
                   'new source component prefix is not a complete continuous original chain')
            if index == current_count-1:
                C.need(prior == records[0]['boundary'],
                       'new source prefix must point to the exact actual source-parent head')
