def verify_closed_components(epoch, proc, mode):
    """Read-only final admission of closed component generations and endpoints.

    Called only after the original native-view/boot verifier has returned its
    verified epoch. A new boot does not reuse old numeric identities as evidence.
    The abstract r6 socket is checked at startup, before this release creates
    its own sidecar. Port 18080 remains absent until provider exec admission.
    """
    import time
    reviewed_component_package_sha256 = '990c726a1fff139761494cc19cf091deb269201f27ea947dda4a5833e3a72f2a'
    require(isinstance(reviewed_component_package_sha256, str)
            and SHA.fullmatch(reviewed_component_package_sha256) is not None,
            'current_component_runtime_not_frozen')
    require(mode in ('startup', 'admission'), 'component_activation_mode')
    raw = private_read(PAYLOAD / 'closed-component-activation.json', 65536)
    value = strict_json(raw)
    require(set(value) == {'schema', 'retirement_boot_id', 'component_boundary_sha256',
                           'component_package_sha256', 'role_generations'}
            and value['schema'] == 'hepta.module-r10-r1.closed-component-activation.v1'
            and value['retirement_boot_id'] == epoch['original_boot_id']
            and SHA.fullmatch(value['component_boundary_sha256']) is not None
            and value['component_package_sha256'] == reviewed_component_package_sha256,
            'closed_component_activation_binding')
    roles = value['role_generations']
    require(isinstance(roles, list) and 3 <= len(roles) <= 42
            and len({tuple(row) for row in roles}) == len(roles)
            and all(isinstance(row, list) and len(row) == 4
                    and all(type(n) is int and n > 1 for n in row)
                    and row[:3] == [row[0]] * 3 for row in roles),
            'closed_component_generation_inventory')
    same_boot = epoch['current_boot_id'] == epoch['original_boot_id']
    ids = {row[0] for row in roles}; expected = {tuple(row) for row in roles}
    inspected = 0; deadline = time.monotonic() + 2.0
    for _ in range(2):
        names = proc.pids()
        require(0 < len(names) <= 4096 and 1 in names and len(set(names)) == len(names),
                'component_activation_complete_proc_inventory')
        for pid in names:
            require(time.monotonic() < deadline, 'component_activation_census_timeout')
            row = proc.row(pid)
            if row is None:
                continue
            inspected += 1
            if same_boot:
                identity = (row['pid'], row['pgrp'], row['session'], row['start_ticks'])
                require(identity not in expected
                        and row['pgrp'] not in ids and row['session'] not in ids,
                        'closed_component_generation_or_owned_group_present')
    for path in ('/proc/net/tcp', '/proc/net/tcp6'):
        rows = proc.read(path, 1024 * 1024).splitlines()
        require(rows, 'component_activation_tcp_header_missing')
        for line in rows[1:]:
            fields = line.split()
            require(len(fields) >= 10 and b':' in fields[1], 'component_activation_tcp_row')
            port = fields[1].rsplit(b':', 1)[1]
            require(re.fullmatch(b'[0-9A-Fa-f]{4}', port) is not None,
                    'component_activation_tcp_port')
            require(not (int(port, 16) == 18080 and fields[3] == b'0A'),
                    'component_activation_18080_listener_present')
    if mode == 'startup':
        rows = proc.read('/proc/net/unix', 1024 * 1024).splitlines()
        require(rows, 'component_activation_unix_header_missing')
        for line in rows[1:]:
            fields = line.split()
            require(len(fields) >= 7, 'component_activation_unix_row')
            require(len(fields) == 7 or fields[7] != b'@hepta_phone_executor_v150_r6',
                    'component_activation_retired_r6_endpoint_present')
    require(proc.boot() == epoch['current_boot_id'], 'component_activation_boot_changed')
    return {'schema': 'hepta.module-r10-r1.component-activation-observation.v1',
        'component_boundary_sha256': value['component_boundary_sha256'],
        'role_generation_count': len(roles), 'numeric_generation_filter_applied': same_boot,
        'complete_proc_censuses': 2, 'process_rows_read': inspected,
        'port_18080_listener_absent': True,
        'r6_endpoint_absence_checked_before_new_sidecar': mode == 'startup',
        'policy_writes': 0, 'signals_sent': 0, 'task_submissions': 0}
