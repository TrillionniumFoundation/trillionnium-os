"""One fixed parent expectation projection, derived from retained raw originals.

The original TARGETS_RAW remains the historical ownership authority. This pure
function changes no file or owned-directory descriptor and grants no authority
over the foreign four transport files or the two retained audit records.
"""

def derive_reconciled_targets(original, reconciliation):
    require(C.encoded(original)==TARGETS_RAW and C.sha(TARGETS_RAW)==TARGETS_SHA
        and len(TARGETS_RAW)==183176 and TARGETS_SHA=='0aad40b0feac77b963547d90b27ed49eb260d3a2c14fd9a9dbfe4a61550597d1',
        'unchanged exact historical target authority')
    require(C.encoded(reconciliation)==RECONCILIATION_RAW and C.sha(RECONCILIATION_RAW)==RECONCILIATION_SHA
        and len(RECONCILIATION_RAW)==72764 and RECONCILIATION_SHA=='3f07757cf054f697e2a81ad1ce0752c6e1aa5ca6a7b09488cb122363b76b038a',
        'one exact independently verified observation original')
    require(reconciliation['schema']=='hepta.fc33.final05.parent-observation-host-verification.v1'
        and reconciliation['state']=='COMPLETE_FINITE_OBSERVATION_PRIVATELY_PRESERVED_NO_CLOSURE'
        and reconciliation['host_validation_error'] is None and reconciliation['phone_rc']==0,
        'complete finite observation, no inferred recovery')
    require(reconciliation['actual_result']['bytes']==195248
        and reconciliation['actual_result']['sha256']=='d0d2726adb89a6e29c6ed054972c4ef9131402a521cdfdfdf1196284dcd0c0e4'
        and reconciliation['actual_request']['bytes']==28145
        and reconciliation['actual_request']['sha256']=='e7afd47d4f41b18fe5745de2c2c32eabb8d771b54f7354fd64e89ed54fa45fbf',
        'exact one completed read-only observer')
    for key in ('scope_closure','cleanup_authorized','business_qualified','component_qualified','private_bodies_in_public_report'):
        require(reconciliation[key] is False,'observation carries no extra authority')
    checks=reconciliation['checks']
    require(checks['all15_existing_lock_groups_held_through_two_windows'] is True
        and checks['exact_resource_baseline_restored'] is True
        and checks['current_parent_and_fixture_profile_coherent'] is True
        and checks['all97_current_originals_proven'] is False
        and checks['old44_full_files_refreshed'] is False
        and checks['known_role_liveness_refreshed'] is False,
        'exact observation scope remains limited')
    current=checks['five_complete_current_parent_profiles'];old=original['surviving_parents']
    require(len(current)==len(old)==5 and [r['path'] for r in current]==[r['path'] for r in old],
        'same exact five parent aliases only')
    gnu_removed={'root-r10-neg01-74ec-final05.stage.py','root-r10-neg01-74ec-final05.tar.gz'}
    gnu_added={'root-r10-neg01-74ec-final05.SECONDARY4-CLEANUP-INTENT-74ec02.json',
               'root-r10-neg01-74ec-final05.SECONDARY4-CLEANUP-RESULT-74ec02.json'}
    android_removed={'hepta-native-guard-root-r10-neg01-74ec-final05.stage.py',
                     'hepta-native-guard-root-r10-neg01-74ec-final05.tar.gz'}
    exact_delta=[(set(),set()),(set(),set()),(gnu_removed,gnu_added),(android_removed,set()),(set(),set())]
    for index,(before,after,(removed,added)) in enumerate(zip(old,current,exact_delta)):
        require(set(after)=={'path','metadata','names','selinux_raw_b64'},'complete current parent schema')
        bounded_metadata(before['metadata']);bounded_metadata(after['metadata'])
        require(before['metadata'][:7]==after['metadata'][:7]
            and before['selinux_raw_b64']==after['selinux_raw_b64'],
            'parent device/inode/type/owner/nlink/size/label unchanged')
        require(set(before['names'])-set(after['names'])==removed
            and set(after['names'])-set(before['names'])==added
            and after['names']==sorted(set(after['names'])),
            'only exactly observed finite foreign parent member delta')
        if index<2:require(before==after,'shared scope parent aliases unchanged')
    require({k:v for k,v in current[0].items() if k!='path'}=={k:v for k,v in current[1].items() if k!='path'},
        'current shared aliases one complete profile')
    expected_xml={r['path']:r for r in original['files'] if r['path'].startswith('/proc/1/root/data/local/tmp/hepta-natural-root-r10-neg02-a1055-final05-v150-')}
    observed_xml=checks['eleven_xml_originals']
    require(len(expected_xml)==len(observed_xml)==11 and checks['eleven_xml_total_bytes']==223418,
        'same eleven privately retained sender XML originals')
    for row in observed_xml:
        require(row['kind']=='file' and {k:row[k] for k in ('path','bytes','sha256','metadata','selinux_raw_b64')}==expected_xml[row['path']],
            'XML original full9/hash/label/size unchanged')
    audits=checks['two_foreign_audit_originals']
    require(len(audits)==2 and {Path(r['original']['path']).name for r in audits}==gnu_added
        and all(r['body_retained_privately'] is True and r['claims_not_accepted_as_cleanup_proof'] is True for r in audits),
        'two exact foreign audit originals retained only')
    fixture=str(C.FIXTURE);absence=checks['fixture_absence'];parent=current[-1]
    require(absence['path']==fixture and absence['kind']=='absent' and absence['absence']=='ENOENT'
        and absence['no_effect_inferred'] is False and Path(fixture).name not in parent['names']
        and absence['parent_metadata']==parent['metadata']
        and absence['parent_selinux_raw_b64']==parent['selinux_raw_b64'],
        'fresh held/reopened fixture absence uses same complete current parent')
    result=C.strict(C.encoded(original));result['surviving_parents']=C.strict(C.encoded(current))
    # These are expectation projections, never altered historical observations.
    # Retain each old observed_monotonic_ns verbatim; stable_tree_projection
    # intentionally excludes that informational timestamp from equality.
    for row in (result['prior_fixture_absence'],result['prior_private_tree']['entries'][fixture]):
        require(row['path']==fixture and row['kind']=='absent' and row['absence']=='ENOENT'
            and row['no_effect_inferred'] is False and row['parent_metadata'][:7]==parent['metadata'][:7]
            and row['parent_selinux_raw_b64']==parent['selinux_raw_b64'],'one original absent fixture parent identity')
        row['parent_metadata']=list(parent['metadata']);row['parent_selinux_raw_b64']=parent['selinux_raw_b64']
    # Complete reverse projection proves the scope did not grow and no file,
    # private directory, prior-home alias, preservation or sender pin changed.
    reverse=C.strict(C.encoded(result));reverse['surviving_parents']=original['surviving_parents']
    reverse['prior_fixture_absence']=original['prior_fixture_absence']
    reverse['prior_private_tree']['entries'][fixture]=original['prior_private_tree']['entries'][fixture]
    require(C.encoded(reverse)==TARGETS_RAW and result['files']==original['files']
        and result['directories']==original['directories'] and len(result['files'])==97 and len(result['directories'])==10,
        'exact original97/10 ownership retained by complete inverse')
    for row in (result['prior_fixture_absence'],result['prior_private_tree']['entries'][fixture]):
        require(row['parent_metadata']==result['surviving_parents'][-1]['metadata']
            and row['parent_selinux_raw_b64']==result['surviving_parents'][-1]['selinux_raw_b64'],
            'derived expectations cannot mix two profiles of the same parent')
    return result
