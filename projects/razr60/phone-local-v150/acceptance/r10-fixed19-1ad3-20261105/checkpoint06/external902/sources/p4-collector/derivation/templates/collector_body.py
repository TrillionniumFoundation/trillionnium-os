def verify_fixed_scope(files):
    material = {name: row for name, row in files.items()
                if name.startswith('material-originals/')}
    expected = {'material-originals/' + name for name in MATERIAL_FILES}
    need(set(material) == expected, 'complete P4 material tree differs from original Mac material tree')
    for name, pin in MATERIAL_FILES.items():
        row = material['material-originals/' + name]
        need(row['descriptor'] == pin, 'original material byte pin differs: ' + name)
    for name, pin in ADDITIONAL_FIXED_FILES.items():
        need(files[name]['descriptor'] == pin, 'fixed sibling input/plan original differs')
    terminal = files['setup-fixture-originals/HOST-TERMINAL.json']
    need(terminal['descriptor'] == SETUP_TERMINAL, 'fixed setup fixture terminal differs')
    need(strict(terminal['raw'])['state'] == 'OWNED_ROOT_FIXTURE_CHILD_JOINED',
         'fixed original setup terminal state differs')
    sender_names = {name[len('sender-originals/'):] for name in files
                    if name.startswith('sender-originals/')}
    required = {'SEND.once.json', 'SEND.MONOTONIC-INTENT.json',
                'SEND.MONOTONIC-WINDOW.json', 'SEND-NATIVE-LATENCY.json'}
    need(required <= sender_names, 'original native sender records incomplete')
    branch = sender_names & {'SEND.result.json', 'SEND.unknown.json'}
    need(len(branch) == 1, 'exactly one retained native send result branch required')
    lease = strict(material['material-originals/tree/LEASE.json']['raw'])
    contract = strict(material['material-originals/tree/sender-contract.json']['raw'])
    need(lease['label'] == contract['label'] == LABEL
         and lease['nonce'] == contract['nonce'] == NONCE
         and lease['case_id'] == contract['case_id'] == 'NEG-01'
         and lease['package_sha256'] == contract['package_sha256'] == RUNTIME_MANIFEST_SHA,
         'fixed material lease and sender contract identities differ')
    return {'scope': 'Original byte identities and closed file sets only',
        'material_reference': MAC_MATERIAL_REFERENCE,
        'material_regular_files': len(material),
        'material_whole_closed_set_matches_original_host_material': True,
        'fixed_sibling_originals': ADDITIONAL_FIXED_FILES,
        'setup_original_terminal': SETUP_TERMINAL,
        'sender_regular_files': len(sender_names),
        'sender_named_records_present': sorted(name for name in sender_names if name.startswith('SEND')),
        'sender_result_branch': sorted(branch)[0],
        'sender_native_result_independently_qualified_here': False,
        'original_mac_sender_pid': 54589,
        'original_mac_parent_joined': False,
        'original_mac_stdout_eof': False, 'original_mac_stderr_eof': False,
        'later_records_retrofit_original_parent_join_or_EOF': False,
        'native_process_cleanup_verified_here': False,
        'boundary_publication_verified_here': False}


def main():
    started = time.monotonic()
    start_unix_ns = time.time_ns()
    handles = {}
    parent_fd = out_fd = None
    out_identity = None
    try:
        need(type(COLLECTOR_SOURCE) is bytes and len(COLLECTOR_SOURCE) <= 65536,
             'exact controller-retained collector source required')
        need(OUT.parent == P4_BASE and all(Path(path).is_absolute() for path in FIXED_TREES.values()),
             'fixed independent P4 paths required')
        files, directories = collect_tree(started, handles)
        scope_proof = verify_fixed_scope(files)
        before_write = recheck_tree(files, directories, handles, started)
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for name, row in sorted(files.items()):
                member = tarfile.TarInfo(str(relative(name)))
                member.size = len(row['raw'])
                member.mode = 0o600
                member.uid = member.gid = 0
                member.mtime = 0
                archive.addfile(member, io.BytesIO(row['raw']))
        tar_raw = buffer.getvalue()
        need(len(tar_raw) <= MAX_BYTES + 4 * 1024 * 1024, 'archive framing budget exceeded')
        packed = lzma.compress(tar_raw, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64, preset=6)
        need(lzma.decompress(packed) == tar_raw, 'lossless original archive differs')
        check_time(started)
        parent_fd, parent_identity = open_directory(P4_BASE)
        need(not os.path.lexists(OUT), 'new independent evidence directory required; no retry or overwrite')
        os.mkdir(OUT.name, mode=0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
        out_fd, out_identity = open_directory(OUT, parent_fd, OUT.name)
        need(out_identity[3] == os.geteuid() and stat.S_IMODE(out_identity[2]) == 0o700,
             'new private evidence directory required')
        collector_row = put_new(out_fd, OUT / 'COLLECTOR.original.py', COLLECTOR_SOURCE)
        archive_row = put_new(out_fd, OUT / 'EXTERNAL902-P4-ORIGINALS.tar.xz', packed)
        counts = {prefix: sum(name.startswith(prefix + '/') for name in files)
                  for prefix in FIXED_TREES}
        total_bytes = sum(len(row['raw']) for row in files.values())
        manifest = {'schema': 'hepta.root.external902-p4-originals-manifest.v1',
            'state': 'EXACT_THREE_P4_TREES_AND_PINNED_SIBLING_ORIGINALS_READ_ONLY_BYTE_COPY',
            'label': LABEL, 'nonce': NONCE, 'complete_source_roots': FIXED_TREES,
            'additional_fixed_files': ADDITIONAL_FIXED_FILES,
            'started_unix_ns': start_unix_ns, 'first_full_recheck': before_write,
            'files': [{**row['descriptor'], 'archive_member': name, 'metadata': row['metadata']}
                      for name, row in sorted(files.items())],
            'directories': [row for _, row in sorted(directories.items())],
            'complete_tree_file_counts': counts, 'fixed_sibling_file_count': len(ADDITIONAL_FIXED_FILES),
            'total_original_files': len(files), 'observed_directories': len(directories),
            'total_original_file_bytes': total_bytes,
            'archive': archive_row, 'tar_plaintext': {'bytes': len(tar_raw), 'sha256': sha(tar_raw)},
            'archive_regular_members': len(files), 'collector_source': collector_row,
            'original_scope_checks': scope_proof,
            'same_instant_as_failure': False, 'atomic_filesystem_snapshot': False,
            'observation_scope': 'Later three complete P4 trees plus eight individually fixed sibling files, full9/bytes/child-name bookends',
            'mac_actor_py_in_this_archive': False,
            'originals_modified': False, 'phone_calls': 0, 'subprocesses': 0, 'network_calls': 0,
            'signals_sent': 0, 'process_census_performed': False,
            'case_pass': False, 'component_qualified': False, 'business_qualified': False}
        manifest_row = put_new(out_fd, OUT / 'ORIGINALS-MANIFEST.json', enc(manifest))
        after_copy = recheck_tree(files, directories, handles, started)
        check_directory(P4_BASE, parent_fd, parent_identity, full=False)
        check_directory(OUT, out_fd, out_identity, full=False)
        result = {'schema': 'hepta.root.external902-p4-originals-collection.v1',
            'state': 'EXTERNAL902_THREE_P4_TREES_AND_PINNED_SIBLING_ORIGINALS_ARCHIVED',
            'label': LABEL, 'nonce': NONCE, 'out': str(OUT),
            'complete_source_roots': FIXED_TREES, 'additional_fixed_files': ADDITIONAL_FIXED_FILES,
            'archive': archive_row, 'manifest': manifest_row, 'collector_source': collector_row,
            'complete_tree_file_counts': counts, 'fixed_sibling_file_count': len(ADDITIONAL_FIXED_FILES),
            'total_original_files': len(files), 'observed_directories': len(directories),
            'total_original_file_bytes': total_bytes,
            'after_copy_full_recheck': after_copy,
            'original_mac_sender_pid': 54589,
            'original_sender_join_or_EOF_retrofitted': False,
            'native_cleanup_or_boundary_publication_verified_here': False,
            'mac_actor_py_in_this_archive': False,
            'same_instant_as_failure': False, 'atomic_filesystem_snapshot': False,
            'originals_modified': False, 'phone_calls': 0, 'subprocesses': 0, 'network_calls': 0,
            'signals_sent': 0, 'process_census_performed': False,
            'case_pass': False, 'component_qualified': False, 'business_qualified': False,
            'automatic_retry': False, 'filesystem_or_compression_hard_deadline': False}
        result_row = put_new(out_fd, OUT / 'RESULT.json', enc(result))
        final_check = recheck_tree(files, directories, handles, started)
        check_directory(P4_BASE, parent_fd, parent_identity, full=False)
        check_directory(OUT, out_fd, out_identity, full=False)
        need(sorted(os.listdir(out_fd)) == ['COLLECTOR.original.py', 'EXTERNAL902-P4-ORIGINALS.tar.xz',
            'ORIGINALS-MANIFEST.json', 'RESULT.json'], 'new evidence output inventory differs')
        print(enc({'state': result['state'], 'result': result_row, 'archive': archive_row,
            'manifest': manifest_row, 'complete_tree_file_counts': counts,
            'fixed_sibling_file_count': len(ADDITIONAL_FIXED_FILES),
            'total_original_files': len(files), 'total_original_file_bytes': total_bytes,
            'last_full_recheck': final_check, 'original_unjoined_sender_pid': 54589,
            'original_sender_join_or_EOF_retrofitted': False, 'case_pass': False,
            'phone_calls': 0, 'subprocesses': 0, 'network_calls': 0,
            'same_instant_as_failure': False, 'atomic_filesystem_snapshot': False}).decode(), end='')
        return 0
    except BaseException as error:
        if out_fd is not None:
            try:
                put_new(out_fd, OUT / 'FAILED-OR-UNKNOWN.json', enc({
                    'state': 'EVIDENCE_COLLECTION_FAILED_OR_UNKNOWN_RETAIN_EXISTING_OUTPUTS',
                    'error_type': type(error).__name__, 'detail': str(error)[:2000],
                    'out': str(OUT), 'case_pass': False, 'automatic_retry': False,
                    'originals_modified': False, 'phone_calls': 0, 'subprocesses': 0,
                    'network_calls': 0, 'signals_sent': 0}))
            except BaseException:
                pass
        raise
    finally:
        if out_fd is not None:
            os.close(out_fd)
        if parent_fd is not None:
            os.close(parent_fd)
        for _, fd, _ in handles.values():
            os.close(fd)


if __name__ == '__main__':
    raise SystemExit(main())
