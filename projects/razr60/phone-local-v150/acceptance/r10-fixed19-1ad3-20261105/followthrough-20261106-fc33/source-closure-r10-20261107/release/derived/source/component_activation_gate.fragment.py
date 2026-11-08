def verify_closed_components(epoch, proc, mode):
    """Read-only final admission of closed component generations and endpoints.

    Called only after the original native-view/boot verifier has returned its
    verified epoch. A new boot does not reuse old numeric identities as evidence.
    The abstract r6 socket is checked at startup, before this release creates
    its own sidecar. Port 18080 remains absent until provider exec admission.
    """
    import time
    reviewed_component_package_sha256 = '94e945e55f4cda2c9d2c4bd473f6fdb8ec6eca425610db4fd59af1814f5fca02'
    require(isinstance(reviewed_component_package_sha256, str)
            and SHA.fullmatch(reviewed_component_package_sha256) is not None,
            'current_component_runtime_not_frozen')
    require(mode in ('startup', 'admission'), 'component_activation_mode')
    raw = private_read(PAYLOAD / 'closed-component-activation.json', 65536)
    value = strict_json(raw)
    require(set(value) == {'schema', 'retirement_boot_id', 'component_boundary_sha256',
                           'component_package_sha256', 'role_generations', 'retained_preaccept_binding', 'retained_preaccept_role_generations', 'retained_failed_staged_binding', 'retained_failed_staged_role_generations', 'retained_failed_transport_binding', 'retained_failed_transport_role_generations'}
            and value['schema'] == 'hepta.module-r10-r1.closed-component-activation.v4'
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
    native_role_generation_count = len(roles)
    retained_binding = {'boot_id': 'f8019f83-20a7-4f18-bea1-51c980621e4d', 'combination': {'bytes': 4695, 'sha256': '7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411'}, 'component_qualified': False, 'component_role_identities': {'sidecar': [14026, 14026, 14026, 39106597], 'supervisor': [12513, 12513, 12513, 39102689]}, 'evidence_archive': {'archive': {'bytes': 3000200, 'sha256': '4010779b9a3810dc7d0d51072dc76dd52be2327301b857df2b04ddb004a5edca'}, 'raw_archive': {'bytes': 11427840, 'sha256': 'a50abed2fea44393468bd058c9c97d72330e9bf0b98e36aa196f0a0d05affcdd'}}, 'inventory': {'bytes': 1378036, 'sha256': 'dfdadedaded0eced586cc680f39d8ab58c336db2d25d75daf7460fc32ae74f7f'}, 'label': 'root-r10-neg01-fc33-r7-bound01', 'lease': {'bytes': 2506, 'sha256': '03f1d2a383384e74743e3331adf39a50bdd8e3d4c9a8d4e618bd8b6012557a5c'}, 'native_case_credit': 0, 'nonce': '4808fbf1e81fd1542e7ffb60d7f57ca6', 'original_native_predecessor': {'bytes': 29342, 'metadata': [65086, 154717, 33152, 0, 0, 1, 29342, 1793954246107886895, 1793954246107886895], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/ac03e3864c1798742c472957b06ca843.json', 'sha256': '39b3702f8472148ae209a9a1043e1dd0623dd92d1210e8310d84b72f89390047'}, 'package': {'bytes': 61701, 'sha256': '643d4e17475293532aa02489194c01175d263f54d8a5979ae96ff802d4f5150a'}, 'private_roots': ['/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-r7-bound01', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-r7-bound01/executor', '/proc/1/root/data/local/tmp/hepta-native-guard-4808fbf1e81fd1542e7ffb60d7f57ca6'], 'schema': 'hepta.r7.retained-preaccept-binding.v1'}
    retained = value['retained_preaccept_role_generations']
    require(value['retained_preaccept_binding'] == retained_binding
            and retained_binding['native_case_credit'] == 0
            and retained_binding['component_qualified'] is False
            and isinstance(retained, list) and len(retained) == 2
            and retained == [retained_binding['component_role_identities'][name]
                             for name in sorted(retained_binding['component_role_identities'])]
            and all(isinstance(row, list) and len(row) == 4
                    and all(type(n) is int and n > 1 for n in row)
                    and row[:3] == [row[0]] * 3 for row in retained),
            'exact_separately_retained_preaccept_generations')
    retained_staged_binding = {'absent_fixture_path': '/proc/1/root/data/local/tmp/hepta-native-guard-aa06c3b8d035dcd0c0047105f620b3bf', 'boot_id': 'f8019f83-20a7-4f18-bea1-51c980621e4d', 'combination': {'bytes': 4695, 'sha256': '7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411'}, 'component_qualified': False, 'component_role_identities': {}, 'evidence_archive': {'archive': {'bytes': 2066079, 'sha256': 'd66d286bfb7890e0b32358326b669ac4a47d5f4ba43c524bc3f129f5bf631e93'}, 'raw_archive': {'bytes': 6389760, 'sha256': '2f0e98f48f0f1449cf1fe588ffe6b5a30f69f252fae67e5fd1682a25b713a213'}}, 'fixture_is_inventory_root': False, 'global_unknown_effect_count': None, 'inventory': {'bytes': 1403291, 'sha256': '2008db913728ff0c3836cb6edb361e37f427d7663f2832163fe93b2adb18f432'}, 'label': 'root-r10-neg01-fc33-r8-bound01', 'lease': {'bytes': 2506, 'sha256': 'f05ee53a7609972c18f6bab2263008a4c3de3b49b12b8654df94790b25c30a44'}, 'native_case_credit': 0, 'native_terminal': None, 'nonce': 'aa06c3b8d035dcd0c0047105f620b3bf', 'original_native_predecessor': {'bytes': 29342, 'metadata': [65086, 154717, 33152, 0, 0, 1, 29342, 1793954246107886895, 1793954246107886895], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/ac03e3864c1798742c472957b06ca843.json', 'sha256': '39b3702f8472148ae209a9a1043e1dd0623dd92d1210e8310d84b72f89390047'}, 'original_nonce_consumed': True, 'original_remote_cleanup_boolean': False, 'original_root_namespace_anchor': {'bytes': 12992, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-fc33-r8-bound01/ROOT-FAILURE.json', 'sha256': 'ab8c85f7d403c6427931db66acfecb12137143cf3b78573a654346584dab7a31'}, 'package': {'bytes': 65655, 'sha256': '654f8b0ad50a4d930d7beff9421b5e9f988ecb74b55badc70cec9efeaa63130c'}, 'private_roots': ['/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-r8-bound01', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-r8-bound01/executor'], 'retained_preaccept_binding': {'boot_id': 'f8019f83-20a7-4f18-bea1-51c980621e4d', 'combination': {'bytes': 4695, 'sha256': '7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411'}, 'component_qualified': False, 'component_role_identities': {'sidecar': [14026, 14026, 14026, 39106597], 'supervisor': [12513, 12513, 12513, 39102689]}, 'evidence_archive': {'archive': {'bytes': 3000200, 'sha256': '4010779b9a3810dc7d0d51072dc76dd52be2327301b857df2b04ddb004a5edca'}, 'raw_archive': {'bytes': 11427840, 'sha256': 'a50abed2fea44393468bd058c9c97d72330e9bf0b98e36aa196f0a0d05affcdd'}}, 'inventory': {'bytes': 1378036, 'sha256': 'dfdadedaded0eced586cc680f39d8ab58c336db2d25d75daf7460fc32ae74f7f'}, 'label': 'root-r10-neg01-fc33-r7-bound01', 'lease': {'bytes': 2506, 'sha256': '03f1d2a383384e74743e3331adf39a50bdd8e3d4c9a8d4e618bd8b6012557a5c'}, 'native_case_credit': 0, 'nonce': '4808fbf1e81fd1542e7ffb60d7f57ca6', 'original_native_predecessor': {'bytes': 29342, 'metadata': [65086, 154717, 33152, 0, 0, 1, 29342, 1793954246107886895, 1793954246107886895], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/ac03e3864c1798742c472957b06ca843.json', 'sha256': '39b3702f8472148ae209a9a1043e1dd0623dd92d1210e8310d84b72f89390047'}, 'package': {'bytes': 61701, 'sha256': '643d4e17475293532aa02489194c01175d263f54d8a5979ae96ff802d4f5150a'}, 'private_roots': ['/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-r7-bound01', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-r7-bound01/executor', '/proc/1/root/data/local/tmp/hepta-native-guard-4808fbf1e81fd1542e7ffb60d7f57ca6'], 'schema': 'hepta.r7.retained-preaccept-binding.v1'}, 'schema': 'hepta.r8.retained-staged-failure-binding.v1', 'standalone_execution_authorized': False}
    require(value['retained_failed_staged_binding'] == retained_staged_binding
            and value['retained_failed_staged_role_generations'] == []
            and retained_staged_binding['retained_preaccept_binding'] == retained_binding
            and retained_staged_binding['component_role_identities'] == {}
            and retained_staged_binding['native_case_credit'] == 0
            and retained_staged_binding['native_terminal'] is None
            and retained_staged_binding['global_unknown_effect_count'] is None
            and retained_staged_binding['component_qualified'] is False
            and retained_staged_binding['standalone_execution_authorized'] is False,
            'exact_retained_staged_originals_have_zero_role_generations_and_no_native_credit')
    retained_transport_binding = {'baseline_device_shell_wire_dispatched': None, 'boot_id': 'f8019f83-20a7-4f18-bea1-51c980621e4d', 'business_qualified': False, 'combination': {'bytes': 4695, 'sha256': '7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411'}, 'component_qualified': False, 'component_role_identities': {}, 'current_kernel_ESRCH_asserted': False, 'evidence_archive': {'archive': {'bytes': 2174339, 'sha256': '18da9626e5ae687adb4087b5a5484d9d2a8dc8885fdaabfd57b829ec02d20fd3'}, 'raw_archive': {'bytes': 3788800, 'sha256': 'ca76e0854be12cb004bef057df668374b851c0a2a90604f1ae7c8ea422b368d6'}}, 'first_launch_receipt_gap': True, 'first_push_scope_only': True, 'global_unknown_effect_count': None, 'historical_failed_listener_identity': None, 'historical_failed_route_callsite': None, 'inventory': {'bytes': 1403290, 'sha256': 'bb8cfb6dd2f108046e8296956e514f7b3eec0ea5aaac5794ad86c70174478609'}, 'label': 'root-r10-neg01-fc33-r9-bound01', 'lease': {'bytes': 2506, 'sha256': 'c56261e8a905de9a3e12d81d16c2a9fb15e90103a4fc0324d6f93c74ec5a6c17'}, 'native_case_credit': 0, 'native_terminal': None, 'new_nonce_authorized': False, 'nonce': '299483481a678cbd589aeba54ed8b68f', 'original_native_predecessor': {'bytes': 29342, 'metadata': [65086, 154717, 33152, 0, 0, 1, 29342, 1793954246107886895, 1793954246107886895], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/ac03e3864c1798742c472957b06ca843.json', 'sha256': '39b3702f8472148ae209a9a1043e1dd0623dd92d1210e8310d84b72f89390047'}, 'original_nonce_consumed': True, 'original_retried_launch': False, 'original_root_namespace_anchor': {'bytes': 3274, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-fc33-r9-bound01/ROOT-FAILURE.json', 'sha256': '29b5b67cc99280b36c3250d87aaf3ecfeec8a19a79d22e715338447bd6095763'}, 'original_start_reused': True, 'original_wrapper_status': 'failed_or_unknown_no_retry', 'package': {'bytes': 73225, 'sha256': 'bcabd6171f84738300b1a1e1bbac5263356339f9d9c5e9ee3079db16ca820734'}, 'private_roots': [], 'remote_cleanup_proven': False, 'replay_authorized': False, 'retained_failed_staged_binding': {'absent_fixture_path': '/proc/1/root/data/local/tmp/hepta-native-guard-aa06c3b8d035dcd0c0047105f620b3bf', 'boot_id': 'f8019f83-20a7-4f18-bea1-51c980621e4d', 'combination': {'bytes': 4695, 'sha256': '7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411'}, 'component_qualified': False, 'component_role_identities': {}, 'evidence_archive': {'archive': {'bytes': 2066079, 'sha256': 'd66d286bfb7890e0b32358326b669ac4a47d5f4ba43c524bc3f129f5bf631e93'}, 'raw_archive': {'bytes': 6389760, 'sha256': '2f0e98f48f0f1449cf1fe588ffe6b5a30f69f252fae67e5fd1682a25b713a213'}}, 'fixture_is_inventory_root': False, 'global_unknown_effect_count': None, 'inventory': {'bytes': 1403291, 'sha256': '2008db913728ff0c3836cb6edb361e37f427d7663f2832163fe93b2adb18f432'}, 'label': 'root-r10-neg01-fc33-r8-bound01', 'lease': {'bytes': 2506, 'sha256': 'f05ee53a7609972c18f6bab2263008a4c3de3b49b12b8654df94790b25c30a44'}, 'native_case_credit': 0, 'native_terminal': None, 'nonce': 'aa06c3b8d035dcd0c0047105f620b3bf', 'original_native_predecessor': {'bytes': 29342, 'metadata': [65086, 154717, 33152, 0, 0, 1, 29342, 1793954246107886895, 1793954246107886895], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/ac03e3864c1798742c472957b06ca843.json', 'sha256': '39b3702f8472148ae209a9a1043e1dd0623dd92d1210e8310d84b72f89390047'}, 'original_nonce_consumed': True, 'original_remote_cleanup_boolean': False, 'original_root_namespace_anchor': {'bytes': 12992, 'path': '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-root-chains-r10-r1/root-r10-neg01-fc33-r8-bound01/ROOT-FAILURE.json', 'sha256': 'ab8c85f7d403c6427931db66acfecb12137143cf3b78573a654346584dab7a31'}, 'package': {'bytes': 65655, 'sha256': '654f8b0ad50a4d930d7beff9421b5e9f988ecb74b55badc70cec9efeaa63130c'}, 'private_roots': ['/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-r8-bound01', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-r8-bound01/executor'], 'retained_preaccept_binding': {'boot_id': 'f8019f83-20a7-4f18-bea1-51c980621e4d', 'combination': {'bytes': 4695, 'sha256': '7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411'}, 'component_qualified': False, 'component_role_identities': {'sidecar': [14026, 14026, 14026, 39106597], 'supervisor': [12513, 12513, 12513, 39102689]}, 'evidence_archive': {'archive': {'bytes': 3000200, 'sha256': '4010779b9a3810dc7d0d51072dc76dd52be2327301b857df2b04ddb004a5edca'}, 'raw_archive': {'bytes': 11427840, 'sha256': 'a50abed2fea44393468bd058c9c97d72330e9bf0b98e36aa196f0a0d05affcdd'}}, 'inventory': {'bytes': 1378036, 'sha256': 'dfdadedaded0eced586cc680f39d8ab58c336db2d25d75daf7460fc32ae74f7f'}, 'label': 'root-r10-neg01-fc33-r7-bound01', 'lease': {'bytes': 2506, 'sha256': '03f1d2a383384e74743e3331adf39a50bdd8e3d4c9a8d4e618bd8b6012557a5c'}, 'native_case_credit': 0, 'nonce': '4808fbf1e81fd1542e7ffb60d7f57ca6', 'original_native_predecessor': {'bytes': 29342, 'metadata': [65086, 154717, 33152, 0, 0, 1, 29342, 1793954246107886895, 1793954246107886895], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/ac03e3864c1798742c472957b06ca843.json', 'sha256': '39b3702f8472148ae209a9a1043e1dd0623dd92d1210e8310d84b72f89390047'}, 'package': {'bytes': 61701, 'sha256': '643d4e17475293532aa02489194c01175d263f54d8a5979ae96ff802d4f5150a'}, 'private_roots': ['/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-r7-bound01', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-r7-bound01/executor', '/proc/1/root/data/local/tmp/hepta-native-guard-4808fbf1e81fd1542e7ffb60d7f57ca6'], 'schema': 'hepta.r7.retained-preaccept-binding.v1'}, 'schema': 'hepta.r8.retained-staged-failure-binding.v1', 'standalone_execution_authorized': False}, 'retained_preaccept_binding': {'boot_id': 'f8019f83-20a7-4f18-bea1-51c980621e4d', 'combination': {'bytes': 4695, 'sha256': '7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411'}, 'component_qualified': False, 'component_role_identities': {'sidecar': [14026, 14026, 14026, 39106597], 'supervisor': [12513, 12513, 12513, 39102689]}, 'evidence_archive': {'archive': {'bytes': 3000200, 'sha256': '4010779b9a3810dc7d0d51072dc76dd52be2327301b857df2b04ddb004a5edca'}, 'raw_archive': {'bytes': 11427840, 'sha256': 'a50abed2fea44393468bd058c9c97d72330e9bf0b98e36aa196f0a0d05affcdd'}}, 'inventory': {'bytes': 1378036, 'sha256': 'dfdadedaded0eced586cc680f39d8ab58c336db2d25d75daf7460fc32ae74f7f'}, 'label': 'root-r10-neg01-fc33-r7-bound01', 'lease': {'bytes': 2506, 'sha256': '03f1d2a383384e74743e3331adf39a50bdd8e3d4c9a8d4e618bd8b6012557a5c'}, 'native_case_credit': 0, 'nonce': '4808fbf1e81fd1542e7ffb60d7f57ca6', 'original_native_predecessor': {'bytes': 29342, 'metadata': [65086, 154717, 33152, 0, 0, 1, 29342, 1793954246107886895, 1793954246107886895], 'path': '/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-boundaries-r10-r1/ac03e3864c1798742c472957b06ca843.json', 'sha256': '39b3702f8472148ae209a9a1043e1dd0623dd92d1210e8310d84b72f89390047'}, 'package': {'bytes': 61701, 'sha256': '643d4e17475293532aa02489194c01175d263f54d8a5979ae96ff802d4f5150a'}, 'private_roots': ['/var/lib/trillionnium/owner-open/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-r7-bound01', '/proc/1/root/data/trillionnium/owner-open/state/phone-local-v150/native-guard-r10-r1/root-r10-neg01-fc33-r7-bound01/executor', '/proc/1/root/data/local/tmp/hepta-native-guard-4808fbf1e81fd1542e7ffb60d7f57ca6'], 'schema': 'hepta.r7.retained-preaccept-binding.v1'}, 'same_boot_complete_scope_original': {'bytes': 11658275, 'sha256': '7323e266eed8e2e0413f4a04e4368b703953103c214a569a0fe175bcc76b2ddd'}, 'schema': 'hepta.r9.retained-transport-failure-binding.v1', 'standalone_execution_authorized': False}
    require(value['retained_failed_transport_binding'] == retained_transport_binding
            and value['retained_failed_transport_role_generations'] == []
            and retained_transport_binding['retained_failed_staged_binding'] == retained_staged_binding
            and retained_transport_binding['private_roots'] == []
            and retained_transport_binding['component_role_identities'] == {}
            and retained_transport_binding['first_launch_receipt_gap'] is True
            and retained_transport_binding['original_start_reused'] is True
            and retained_transport_binding['native_case_credit'] == 0
            and retained_transport_binding['native_terminal'] is None
            and retained_transport_binding['global_unknown_effect_count'] is None
            and retained_transport_binding['baseline_device_shell_wire_dispatched'] is None
            and retained_transport_binding['remote_cleanup_proven'] is False
            and retained_transport_binding['standalone_execution_authorized'] is False,
            'exact_retained_transport_originals_preserve_unknowns_without_new_role_generations')
    roles = roles + retained
    require(len(roles) <= 44 and len({tuple(row) for row in roles}) == len(roles),
            'native_and_separately_retained_generations_must_be_distinct')
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
        'role_generation_count': len(roles), 'native_role_generation_count': native_role_generation_count,
        'retained_preaccept_generation_count': len(retained), 'retained_preaccept_native_case_credit': 0,
        'retained_failed_staged_generation_count': 0, 'retained_failed_staged_native_case_credit': 0,
        'retained_failed_transport_generation_count': 0, 'retained_failed_transport_native_case_credit': 0,
        'numeric_generation_filter_applied': same_boot,
        'complete_proc_censuses': 2, 'process_rows_read': inspected,
        'port_18080_listener_absent': True,
        'r6_endpoint_absence_checked_before_new_sidecar': mode == 'startup',
        'policy_writes': 0, 'signals_sent': 0, 'task_submissions': 0}
