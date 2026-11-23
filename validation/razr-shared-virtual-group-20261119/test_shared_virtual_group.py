#!/usr/bin/env python3
"""Test the actual host consumers with synthetic DMS/PMS and helper receipts.

This script performs no phone operations and creates no app qualification.
It accepts the package root containing personal/src and ctrip/src. It deliberately
does not import either family's runtime, phone entrypoint, or binding loader.
"""

import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import types

sys.dont_write_bytecode = True


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixture_displays():
    return {
        0: dict(group=0, kind='INTERNAL', state='OFF', enabled=True, unique='physical-main'),
        1: dict(group=1, kind='INTERNAL', state='OFF', enabled=True, unique='physical-cover'),
        40: dict(group=2, kind='VIRTUAL', state='ON', enabled=True, unique='fixture-owned'),
        41: dict(group=2, kind='VIRTUAL', state='OFF', enabled=False, unique='fixture-peer'),
    }


def fixture_raw(displays, *, power_changes=None):
    """A synthetic complete dump, including the disabled peer and both physicals."""
    members = {}
    logical = []
    for display_id, d in sorted(displays.items()):
        group = d['group']
        members.setdefault(group, []).append(display_id)
        info = ('DisplayInfo{fixture, displayId ' + str(display_id)
                + ', displayGroupId ' + str(group) + ', type ' + d['kind']
                + ', uniqueId "' + d['unique'] + '", state ' + d['state']
                + ', committedState ' + d['state'] + ', fixture}')
        logical.extend(['  Display ' + str(display_id) + ':',
                        '    mDisplayId=' + str(display_id),
                        '    mDisplayGroupId=' + str(group),
                        '    mIsEnabled=' + str(d['enabled']).lower(),
                        '    mBaseDisplayInfo=' + info])
    grouped = []
    power = []
    for group, ids in sorted(members.items()):
        grouped.extend(['  Group ' + str(group) + ':', '    Size=' + str(len(ids)),
                        '    mDisplays=['])
        for display_id in ids:
            grouped.extend(['    mDisplayId=' + str(display_id),
                            '    mDisplayGroupId=' + str(group)])
        grouped.append('    ]')
        grouped.extend('    Display ' + str(display_id) + ' fixture' for display_id in ids)
        values = dict(wakefulness='Awake' if group == 2 else 'Asleep',
                      last=100, no_lights=90, summary='0x20' if group == 2 else '0x0')
        values.update((power_changes or {}).get(group, {}))
        power.extend(['  displayGroupId=' + str(group),
                      '    wakefulness=' + values['wakefulness'],
                      '    lastUserActivityTime=' + str(values['last']) + ' (fixture)',
                      '    lastUserActivityTimeNoChangeLights=' + str(values['no_lights']) + ' (fixture)',
                      '    mWakeLockSummary=' + values['summary']])
    dms = '\n'.join(['DISPLAY MANAGER (dumpsys display)', 'LogicalDisplayMapper:',
                     '  Logical Displays: size=' + str(len(displays))] + logical
                    + ['  Display Groups: size=' + str(len(members))] + grouped
                    + ['  DeviceStateToLayoutMap:', ''])
    pms = '\n'.join(['POWER MANAGER (dumpsys power)', 'Display Group User Activity:']
                    + power + ['Suspend Blockers:', ''])
    return dms, pms


def fixture_lease(members):
    return dict(schema='hepta.owned-display-screen-power-lease.v1', display_id=40,
                display_group_id=2, display_unique_id='fixture-owned', group_members=members,
                wake_lock_level=10, wake_lock_tag='HeptaOuterDisplay:fixture-generation:40',
                wake_lock_held=True, display_state=2, wake_up_called=False,
                on_after_release=False, default_display_fallback=False,
                acquired_elapsed_ms=100, requested_timeout_ms=1000, deadline_elapsed_ms=1100)


def exercise(family, package):
    root = package / family / 'src'
    outer = load(family + '_outer', root / 'outer_session.py')
    power = load(family + '_power', root / 'reference' / 'physical_power.py')
    outer.attach(types.SimpleNamespace(need=require))
    passed = []

    def check(name, action):
        action()
        passed.append(family + ':' + name)

    def reject(name, action, message=None):
        try:
            action()
        except (RuntimeError, ValueError) as exc:
            require(message is None or message in str(exc), name + ': wrong rejection: ' + str(exc))
            passed.append(family + ':' + name)
            return
        raise AssertionError(name + ': unsafe input accepted')

    def same(actual, expected):
        require(actual == expected, 'unexpected value: ' + repr(actual))

    bound = dict(display_id=40, display_group_id=2, generation='fixture-generation',
                 bound_display_readback={'display_unique_id': 'fixture-owned'})
    def validate(receipt, state=None):
        return outer.screen_power_valid(receipt, state or bound)

    check('old-single-virtual-group-remains-accepted', lambda: validate(fixture_lease([40])))
    check('actual-shared-members-retained', lambda: same(validate(fixture_lease([40, 41]))['group_members'], [40, 41]))
    frozen = copy.deepcopy(bound)
    frozen['bound_screen_power_lease'] = fixture_lease([40])
    check('peer-arrival-keeps-original-token-and-deadline', lambda: validate(fixture_lease([40, 41]), frozen))
    frozen['bound_screen_power_lease'] = fixture_lease([40, 41])
    check('peer-departure-keeps-original-token-and-deadline', lambda: validate(fixture_lease([40]), frozen))
    check('membership-order-does-not-change-ownership', lambda: validate(fixture_lease([41, 40]), frozen))
    for name, members in (
        ('missing', None), ('empty', []), ('own-absent', [41]), ('duplicate', [40, 41, 41]),
        ('physical-main', [40, 0]), ('physical-cover', [40, 1]), ('negative', [40, -1]),
        ('boolean', [40, True]), ('float', [40, 41.0]), ('string-id', [40, '41']),
        ('tuple', (40, 41)), ('too-large', list(range(2, 4099))),
    ):
        reject('helper-members-' + name, lambda m=members: validate(fixture_lease(m)),
               'actual virtual display group membership unavailable')
    for key, value in (
        ('display_id', 41), ('display_group_id', 3), ('display_unique_id', 'replacement'),
        ('wake_lock_level', 26), ('wake_lock_tag', 'foreign-token'), ('wake_lock_held', False),
        ('display_state', 1), ('wake_up_called', True), ('on_after_release', True),
        ('default_display_fallback', True), ('acquired_elapsed_ms', 101),
        ('requested_timeout_ms', 999), ('deadline_elapsed_ms', 1101),
    ):
        value_receipt = fixture_lease([40, 41]); value_receipt[key] = value
        reject('original-scope-refusal-' + key, lambda r=value_receipt: validate(r, frozen))
    reject('missing-receipt-refused', lambda: validate(None))
    check('new-helper-byte-pin', lambda: same(outer.DEX_SHA,
        '02173012cd6c8825966a4a103848d4a33f4888c0ecf89e864fb8bb0bdf584ee2'))

    def snapshot(displays=None, **kwargs):
        return power.parse_snapshot(*fixture_raw(displays if displays is not None else fixture_displays(), **kwargs))

    initial = snapshot()
    own_only = fixture_displays(); del own_only[41]
    peer_only = fixture_displays(); del peer_only[40]
    physical_only = fixture_displays(); del physical_only[40]; del physical_only[41]
    check('parsed-full-census-includes-disabled-peer', lambda: same(initial['displays'][41]['enabled'], False))
    check('power-fence-reports-real-members', lambda: same(power.isolated_target(initial, 40)['group_members'], [40, 41]))
    check('power-fence-single-virtual-still-valid', lambda: same(power.isolated_target(snapshot(own_only), 40)['group_members'], [40]))

    def compare(before, after, after_state='present', awake=True):
        return power.compare_physical(before, after, 40, target_after=after_state,
                                      require_target_awake=awake)

    check('create-own-in-existing-virtual-peer-group', lambda: compare(snapshot(peer_only), initial))
    check('peer-joins-without-touching-physical-displays', lambda: compare(snapshot(own_only), initial))
    check('peer-leaves-without-touching-physical-displays', lambda: compare(initial, snapshot(own_only)))
    check('own-release-leaves-peer-present', lambda: same(
        compare(initial, snapshot(peer_only), 'absent', False)['target_after'], None))
    check('last-own-release-may-remove-empty-group', lambda: compare(snapshot(own_only), snapshot(physical_only), 'absent', False))
    check('peer-power-lifecycle-is-not-physical-ownership', lambda: compare(initial, snapshot(
        power_changes={2: {'summary': '0x0', 'last': 500}})))
    check('power-report-grants-no-ownership-or-input', lambda: same(
        compare(initial, initial)['display_ownership_or_input_authority'], False))
    for physical in (0, 1):
        bad = fixture_displays(); bad[physical]['group'] = 2
        reject('physical-' + str(physical) + '-shares-target-group',
               lambda b=bad: power.isolated_target(snapshot(b), 40), 'TARGET_PHYSICAL_GROUP')
        bad = fixture_displays(); bad[physical]['state'] = 'ON'
        reject('physical-' + str(physical) + '-state-changed',
               lambda b=bad: compare(initial, snapshot(b)), 'PHYSICAL_POWER_CHANGED')
        reject('physical-' + str(physical) + '-activity-changed', lambda p=physical: compare(initial,
               snapshot(power_changes={p: {'last': 101}})), 'PHYSICAL_POWER_CHANGED')
        reject('physical-' + str(physical) + '-is-not-owned-input',
               lambda p=physical: power.isolated_target(initial, p), 'TARGET_PHYSICAL_OR_INVALID')
    for kind in ('INTERNAL', 'EXTERNAL', 'WIFI', 'UNKNOWN'):
        bad = fixture_displays(); bad[41]['kind'] = kind
        reject('disabled-nonvirtual-peer-' + kind,
               lambda b=bad: power.isolated_target(snapshot(b), 40), 'TARGET_GROUP_NOT_VIRTUAL')
    bad = fixture_displays(); bad[40]['unique'] = 'reused-numeric-id'
    reject('own-numeric-id-reuse-refused', lambda: compare(initial, snapshot(bad)), 'TARGET_IDENTITY_CHANGED')
    moved = fixture_displays(); moved[40]['group'] = 3
    reject('own-group-change-refused', lambda: compare(initial, snapshot(moved)), 'TARGET_IDENTITY_CHANGED')
    off = fixture_displays(); off[40]['state'] = 'OFF'
    reject('own-off-cannot-claim-ready', lambda: compare(initial, snapshot(off)), 'TARGET_NOT_AWAKE_AND_ON')
    reject('own-absent-cannot-claim-present', lambda: compare(initial, snapshot(peer_only)), 'TARGET_AFTER_PRESENCE')
    dms, pms = fixture_raw(fixture_displays())
    reject('partial-group-census-refused', lambda: power.parse_snapshot(
        dms.replace('    Size=2', '    Size=1'), pms), 'GROUP_MEMBER_COUNT')
    reject('duplicate-member-census-refused', lambda: power.parse_snapshot(
        dms.replace('    mDisplayId=41\n    mDisplayGroupId=2\n    ]',
                    '    mDisplayId=40\n    mDisplayGroupId=2\n    ]'), pms), 'GROUP_MEMBER_COUNT')
    reject('display-group-inventory-disagreement-refused', lambda: power.parse_snapshot(
        dms.replace('    Display 41 fixture', '    Display 42 fixture'), pms), 'GROUP_MEMBER_SUMMARY_CONFLICT')
    reject('missing-power-group-refused', lambda: power.parse_snapshot(dms, pms.replace(
        '  displayGroupId=2', '  displayGroupId=3')), 'DMS_PMS_GROUP_SET_MISMATCH')
    return passed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    files = [args.package / family / 'src' / rel for family in ('personal', 'ctrip')
             for rel in ('outer_session.py', 'reference/physical_power.py')]
    before = {str(p.relative_to(args.package)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    passed = exercise('personal', args.package) + exercise('ctrip', args.package)
    after = {str(p.relative_to(args.package)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    require(before == after, 'tests altered consumer source')
    require(len(passed) == len(set(passed)), 'duplicate check names')
    for rel in ('outer_session.py', 'reference/physical_power.py'):
        require((args.package / 'personal/src' / rel).read_bytes()
                == (args.package / 'ctrip/src' / rel).read_bytes(), 'family contract drift: ' + rel)
    result = dict(schema='hepta.shared-virtual-group-consumers.host.v1', status='PASS',
                  checks=passed, count=len(passed), source_sha256=after,
                  phone_operations=0, phone_business_qualified=False,
                  fixture_scope='Synthetic helper receipts and full DMS/PMS dumps only.')
    with args.out.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(json.dumps(dict(status='PASS', count=len(passed), phone_operations=0)))


if __name__ == '__main__':
    main()
