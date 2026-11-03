"""Real temporary-filesystem rename window and strict negative boundaries.

No CLI/model, daemon, socket, phone, SSH or live evidence mutation occurs.
"""
from pathlib import Path
import errno, json, os, sys, tempfile
from unittest.mock import patch

BASE=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(BASE/'source'))
from daily_provider import evidence_item_size, expected_evidence_temporary, raise_evidence_scan_error

def rejects(function, exception=Exception):
    try:function()
    except exception:return True
    raise AssertionError('unexpected missing/nonregular evidence was accepted')

def main():
    checks={}
    with tempfile.TemporaryDirectory(prefix='hepta-capacity-race-') as temporary:
        root=Path(temporary)/'evidence';root.mkdir()
        run=root/('20261103-101005-'+'a'*32);run.mkdir()
        source=run/'codex-07.spawn-intent.json.new'
        payload=b'{"fixture":"actual atomic rename window"}\n';source.write_bytes(payload)
        assert evidence_item_size(source,root)==len(payload)
        checks['present_expected_temporary_is_counted']=True
        # Reproduce the exact ordering from the real incident: enumerate the
        # temporary, then atomic-rename it before the scan calls its lstat.
        enumerated=list(run.iterdir());assert enumerated==[source]
        canonical=source.with_name('codex-07.spawn-intent.json')
        os.replace(source,canonical)
        assert evidence_item_size(enumerated[0],root) is None
        assert evidence_item_size(canonical,root)==len(payload) and canonical.read_bytes()==payload
        checks['real_enumerate_then_atomic_replace_missing_new_is_tolerated']=True
        checks['canonical_rename_destination_still_counted_and_unchanged']=True
        existing=run/'unrecognized.json.new';existing.write_bytes(b'exists')
        assert evidence_item_size(existing,root)==6
        checks['present_other_regular_file_still_counts']=True
        known_names=['codex-01.spawn-intent.json.new','codex-01.spawned.json.new',
            'codex-01.joined.json.new','codex-02.images.json.new','codex-02.model-failure.json.new',
            'terminal.json.new','business-outcome.json.new','task-contract.json.new',
            'dispatch-001.json.new','result-'+'b'*64+'.json.new','semantic-'+'c'*64+'.json.new',
            'capture-'+'d'*32+'.json.new','connection-ended.json.'+'e'*32+'.new',
            'cleanup-failure.json.'+'f'*32+'.new']
        assert all(expected_evidence_temporary(run/name,root) for name in known_names)
        checks['only_current_atomic_writer_temporary_grammars_recognized']=True
        for name in ['missing.json','codex-06.spawn-intent.json','image-'+'a'*32+'.jpg',
                     'unknown.json.new','codex-07.answer.json.new','codex-7.spawn-intent.json.new',
                     'terminal.json.new.extra']:
            checks['missing_'+name+'_raises']=rejects(lambda name=name:evidence_item_size(run/name,root),FileNotFoundError)
        claims=root/'claims';claims.mkdir()
        checks['missing_claim_record_not_ignored']=rejects(lambda:evidence_item_size(claims/('a'*64),root),FileNotFoundError)
        checks['temporary_spelling_outside_run_not_ignored']=rejects(lambda:evidence_item_size(root/'terminal.json.new',root),FileNotFoundError)
        unknown=root/'not-a-run';unknown.mkdir()
        checks['unknown_run_directory_not_ignored']=rejects(lambda:evidence_item_size(unknown/'terminal.json.new',root),FileNotFoundError)
        missing_parent=root/('20261103-101006-'+'b'*32)
        checks['missing_parent_not_misread_as_completed_rename']=rejects(lambda:evidence_item_size(missing_parent/'terminal.json.new',root),FileNotFoundError)
        symlink=run/'codex-02.spawned.json.new';symlink.symlink_to(canonical)
        checks['existing_temporary_symlink_rejected']=rejects(lambda:evidence_item_size(symlink,root),RuntimeError)
        dangling=run/'codex-03.spawned.json.new';dangling.symlink_to(run/'absent-target')
        checks['dangling_temporary_symlink_rejected']=rejects(lambda:evidence_item_size(dangling,root),RuntimeError)
        linked_parent=root/('20261103-101007-'+'c'*32);linked_parent.symlink_to(run,target_is_directory=True)
        checks['temporary_with_symlink_parent_rejected']=rejects(lambda:evidence_item_size(linked_parent/'terminal.json.new',root),RuntimeError)
        directory=run/'codex-04.spawned.json.new';directory.mkdir()
        checks['temporary_directory_rejected']=rejects(lambda:evidence_item_size(directory,root),RuntimeError)
        for name, error in [('permission',PermissionError(errno.EACCES,'fixture')),
                            ('io',OSError(errno.EIO,'fixture')),
                            ('not_directory',NotADirectoryError(errno.ENOTDIR,'fixture'))]:
            with patch.object(Path,'lstat',side_effect=error):
                checks[name+'_lstat_error_propagates']=rejects(lambda:evidence_item_size(source,root),type(error))
        checks['real_os_walk_missing_root_error_propagates']=rejects(
            lambda:list(os.walk(root/'missing-evidence',followlinks=False,onerror=raise_evidence_scan_error)),FileNotFoundError)
        with patch('os.scandir',side_effect=PermissionError(errno.EACCES,'fixture')):
            checks['os_walk_scandir_permission_error_not_suppressed']=rejects(
                lambda:list(os.walk(root,followlinks=False,onerror=raise_evidence_scan_error)),PermissionError)
    assert all(checks.values())
    return {'checks':checks,'checks_passed':len(checks),
        'real_race_sequence':'actual file enumeration -> os.replace -> lstat of enumerated expected.new',
        'unknown_missing_canonical_or_IO_error_is_not_swallowed':True,
        'live_evidence_claims_or_services_mutated':False,'model_or_phone_actions':0}

if __name__=='__main__':print(json.dumps(main(),ensure_ascii=False,indent=2))

