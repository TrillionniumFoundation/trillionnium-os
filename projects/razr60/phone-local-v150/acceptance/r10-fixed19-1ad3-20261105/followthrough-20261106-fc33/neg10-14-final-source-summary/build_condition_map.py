"""Index already retained observations; this script executes no production tests."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parent
PATHS = {
    'native': 'references/native-v3/evidence/native-RESULT.original.json',
    'shared': 'references/native-v3/evidence/shared-RESULT.original.json',
    'selected': 'references/native-v3/evidence/selected-guards-RESULT.original.json',
    'owned': 'neg14-owned-capacity01/actual/RUN01/RESULT.json',
}

def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

RESULTS = {key: json.loads((ROOT / path).read_bytes()) for key, path in PATHS.items()}

def select(group, array, names):
    rows = RESULTS[group][array]
    selections = []
    for name in names.split():
        hits = [i for i, row in enumerate(rows) if row.get('name') == name]
        assert len(hits) == 1 and rows[hits[0]]['passed'] is True, (group, array, name)
        selections.append({'pointer': '/' + array + '/' + str(hits[0]), 'name': name})
    return {'result': group, 'path': PATHS[group], **pin((ROOT / PATHS[group]).read_bytes()),
            'selections': selections}

def source(name, symbols):
    return {'name': name, 'symbols': symbols.split()}

OBS = source('phone_observation_tools.py', 'native_bound_call native_streams _native_observation_sha256 PhoneTools.map PhoneTools.prepare')
LOCAL = source('phone_local_tools.py', 'PhoneLocalTools._wire_call PhoneLocalTools.prepare')
ADAPTER = source('provider_codex_host.py', 'CodexAdapter.receive CodexAdapter.emit')
PHONE = source('provider_phone_local.py', 'PhoneLocalAdapter.receive PhoneLocalAdapter.emit')
TASK = source('task_postconditions.py', 'load_contract write_exclusive evaluate terminal_fields')
DAILY = source('daily_phone_local.py', 'expected_evidence_temporary evidence_item_size raise_evidence_scan_error serve main')
CONDITIONS = []

def add(case, suffix, requirement, evidence, sources, observed, limits=(), partial=False):
    CONDITIONS.append({'case_id': case, 'condition_id': case.replace('-', '') + '-' + suffix,
                       'requirement_zh': requirement, 'evidence': evidence, 'source_symbols': sources,
                       'observed': observed, 'limits': list(limits), 'whole_case_closed': False,
                       'state': 'OBSERVED_PARTIAL_HOST_RESOURCE_SCOPE' if partial else 'OBSERVED_PASS_IN_RECORDED_HOST_SCOPE'})

for suffix, name, requirement in [
    ('budget', 'image_budget', '图像预算超限在 dispatch 前拒绝'),
    ('expired', 'image_expired', '过期图像在 dispatch 前拒绝'),
    ('foreign-image', 'image_foreign_image', '非当前图像在 dispatch 前拒绝'),
    ('old-round', 'image_old_round', '旧 round 在 dispatch 前拒绝'),
]:
    add('NEG-10', suffix, requirement, [select('selected', 'cases', name)], [OBS],
        '真实 PhoneTools.map 抛出 ProviderError；mapper 状态不变，零 mapping record、零 input write、零 dispatch。',
        ['图像/round/时钟前提显式 synthetic；没有新截图或本地模型图像输入。'])

add('NEG-11', 'identity', 'native 身份错误必须拒绝', [
    select('native', 'parser_cases', 'all_wrong_target event_wrong_target event_target_object event_target_missing registry_wrong_target registry_missing registry_target_missing registry_wrong_call registry_wrong_tool wrong_call wrong_event_call wrong_event_tool mapped_call_identity_mismatch mapped_target_alias_conflict mapped_target_wrong_type'),
    select('native', 'consumer_chains', 'all_wrong_target event_wrong_target event_target_object event_target_missing'),
    select('native', 'trust_parser_cases', 'trusted_scope_changed_original_digest_rejected missing_scope scope_extra scope_missing_stream scope_float'),
], [OBS, LOCAL, ADAPTER, PHONE], 'expected target、完整 scope 来自真实 map / accepted turn；不从返回值反推 expected。错误 target、call、tool、scope 经真实消费者拒绝。')
add('NEG-11', 'sequence', '序列和生命周期顺序错误必须拒绝', [
    select('native', 'parser_cases', 'wrong_event_sequence boolean_event_sequence output_before_started duplicate_started missing_started'),
    select('native', 'trust_parser_cases', 'outer_sequence_float'),
], [OBS], '严格整数序列与 accepted → started → output* → terminal 顺序；错序列、布尔序列、缺失/重复 started 拒绝。')
add('NEG-11', 'length', '长度、编码与完整流错误必须拒绝', [
    select('native', 'parser_cases', 'output_wrong_count output_float_count output_invalid_base64 noncanonical_base64_pad_bits output_wrong_encoding event_terminal_stdout_float event_terminal_stderr_false full_current_multichunk full_current_unicode_newline'),
], [OBS], '逐块 base64、字节数、累积终态计数与严格类型受校验；多块中文、emoji、换行完整流为正控。')
add('NEG-11', 'terminal', '终态损坏、非法退出组合及缺字段必须拒绝', [
    select('native', 'parser_cases', 'terminal_nonzero_exit terminal_error terminal_exit_bool terminal_exit_float event_terminal_exit_bool event_terminal_exit_float exited_zero_with_signal signal_false signal_missing legacy_minimal_terminal terminal_unknown_field terminal_elapsed_float terminal_elapsed_bool terminal_elapsed_negative terminal_elapsed_overflow terminal_elapsed_missing started_pid_bool started_pid_float started_pid_zero started_pid_negative started_pid_overflow started_pid_missing'),
    select('native', 'consumer_chains', 'exited_zero_with_signal legacy_minimal_terminal started_pid_bool started_pid_float started_pid_missing terminal_elapsed_float'),
], [OBS, LOCAL, ADAPTER], '当前实际 schema 的完整终态、pid、u64 时间字段和 exited 0 / signal None 组合验证；历史 minimal terminal 不被最终 v3 接受。')
add('NEG-11', 'truncation', '截断和同值异类型终态必须拒绝', [
    select('native', 'parser_cases', 'terminal_truncated event_terminal_truncated_zero event_terminal_elapsed_float'),
], [OBS], 'output_truncated 必须精确 False；事件内终态与外层终态逐字段类型一致。')
add('NEG-11', 'hashes', '请求、配置和 observation 哈希损坏必须拒绝', [
    select('native', 'trust_parser_cases', 'wrong_request_sha256 missing_request_sha256 wrong_binding_fingerprint missing_binding_fingerprint wrong_observation_sha256 missing_observation_sha256 registry_terminal_receipt_changed registry_terminal_receipt_missing registry_terminal_receipt_wrong_generation started_pid_changed_without_rehash terminal_elapsed_changed_without_rehash same_length_output_bytes_changed old_turn_request_digest'),
    select('native', 'trust_consumer_chains', 'trust_wrong_request_sha256 trust_missing_request_sha256 trust_wrong_binding_fingerprint trust_missing_binding_fingerprint trust_wrong_observation_sha256 trust_missing_observation_sha256 trust_registry_terminal_receipt_changed trust_same_length_output_bytes_changed'),
    select('native', 'dispatch_binding_cases', 'mapped_base mapped_full wrong_request_claim wrong_binding_claim wrong_config_generation partial_claims changed_argv unknown_field changed_target'),
], [OBS, LOCAL, ADAPTER, PHONE, source('action_ledger.py', 'ActionLedger.reserve')],
    '用可信完整 mapped call、active scope/config 的真实 preimage 重算请求与配置哈希；对完整 observation 与 registry terminal receipt 重算并比较。真实 LedgerPrefix/ActionLedger 保存的完整 wire 与 dispatch frame 相等。',
    ['generation 在 claim_spawn 后分配：验证类型、合法范围及 receipt/digest 一致性，没有先验独立 admission counter 或 MAC；协调重写 generation 与全部未签名哈希不在当前协议可独立鉴别范围。',
     'event record elapsed_ms 检查类型/范围，但实际 producer 的 ObservationDigest 不包含它；terminal.elapsed_ms 在 digest 内且篡改拒绝。'])
add('NEG-11', 'generation-and-schema', 'generation 与事件 schema 损坏必须受控拒绝', [
    select('native', 'trust_parser_cases', 'generation_changed_without_rehash generation_bool generation_float generation_zero generation_negative generation_allocator_exhausted generation_overflow generation_missing allocator_minimum allocator_maximum_allocatable'),
    select('native', 'parser_cases', 'unknown_event_kind_progress unknown_event_kind_queued unknown_event_kind_list unknown_event_kind_object unknown_event_kind_none event_record_unknown_field accepted_unknown_field output_stream_list'),
], [OBS], '当前窄语义 tool 只接受实际 schema 的 accepted / started / output / terminal；未知 kind、错误类型与非法 generation 受控抛出 ProviderError。')

for suffix, names, field, requirement in [
    ('confirmation', 'missing_confirmation invalid_confirmation', 'input', '缺确认或确认无效时明确失败并列缺项'),
    ('public', 'missing_public wrong_public', 'public', '缺公开回执或回执错误时明确失败并列缺项'),
    ('return', 'missing_return wrong_return', 'return', '缺返回或返回错误时明确失败并列缺项'),
]:
    add('NEG-12', suffix, requirement, [select('shared', 'cases', names)], [OBS, ADAPTER, TASK],
        '真实业务降级函数产出 turn.fail；business_verified=False，missing_postconditions 精确为 ' + repr([field]) + '；迟到 terminal 被拒绝且已持久终态不重写。',
        ['owner/native/public 输入显式 synthetic；真实生产消费者与业务 gate 的结果不替代现场业务证明。'])
add('NEG-12', 'coverage', '部分任务不得冒充整项完成', [select('shared', 'cases', 'partial_coverage complete_control')], [ADAPTER, TASK],
    'declared_postconditions_only 即使列出后条件全满足也 turn.fail，明确说明合约仅覆盖局部；entire_request 完整 synthetic 正控可 turn.complete。')
add('NEG-13', 'once', '模板恰好一次绑定', [select('shared', 'cases', 'real_exclusive_binding_race')], [TASK],
    '真实两个 host 线程竞争 O_EXCL：一接受、一拒绝、仅一个 binding 文件；两线程均 join，绑定原件保留。')
add('NEG-13', 'scope', '错误 scope 不消费模板', [select('shared', 'cases', 'real_exclusive_binding_race nonce_missing nonce_duplicate request_digest_mismatch app_scope_owner_mismatch')], [TASK],
    '错误 session/profile 在竞争前均 bindings_after=0；缺/重复 nonce、请求 digest/app owner 错误均零 binding、模板不变、零 dispatch。')
add('NEG-13', 'replay', '旧身份、旧 nonce 不能再次派发', [select('shared', 'cases', 'real_exclusive_binding_race old_identity_real_pipe_admission')], [TASK, ADAPTER],
    '同身份、换 stream、换 task/turn 复用旧 nonce 均拒绝；真实 CodexAdapter.receive 的两次旧身份输入均 mapped_calls=0 / outgoing_frames=0 / native_dispatches=0，原 failed claim 和 binding 未改变。')
add('NEG-14', 'rename', '只接受精确识别的 rename 竞态', [select('selected', 'cases', 'rename_local-01.request.json.new rename_health-outcome.json.new')], [DAILY],
    '两种已识别临时文件经真实 os.replace 后，生产 scanner 仅容忍该消失临时文件，并计数实际 canonical 原件。')
add('NEG-14', 'io', '未知路径或 I/O 错误必须拒绝', [
    select('selected', 'cases', 'missing_canonical unknown_temporary known_temporary_missing_parent symlink_rejected actual_enotdir scanner_eacces_same_exception'),
    select('owned', 'checks', 'real_kernel_EACCES_through_lstat_and_scanner'),
], [DAILY], '缺 canonical、未知临时名、缺父目录、symlink、真实 ENOTDIR 均拒绝；本轮隔离 host 的真实内核 EACCES errno 13 经 evidence_item_size 和 os.walk onerror 传播。',
    ['旧 13 项的 scanner EACCES 是合成异常同对象传播；新增 4 项的 EACCES 才是真实权限失败，两者单列。'])
add('NEG-14', 'capacity', '公开容量阈值首次拒绝零 dispatch、零额外消费并保留旧 claim', [select('owned', 'checks', 'public_daily_logical_capacity_first_boundary_refusal')], [DAILY],
    '实际 daily CLI 使用公开最低 max-evidence-bytes=1073741824；真实逻辑字节总量 939524095 时仍存活，增至 939524096 首次拒绝；原 claim 全字节/full9 不变，零额外 claim / binding / worker / dispatch / connection，锁可重新取得。',
    ['通过自有稀疏文件 st_size 真实耗尽逻辑字节预算；没有填满磁盘，没有触发 ENOSPC，未声称覆盖 200000 文件计数上限。',
     '原 load_local_config / validate_executor 实际执行；client 原字节只读验证但未运行，真实模型和 phone scope 均未消耗。'])
add('NEG-14', 'orphan', '保留孤儿 spawn 凭据时拒绝新工作并保全原件', [select('owned', 'checks', 'public_daily_orphan_spawn_receipt_refusal')], [DAILY],
    '真实 daily CLI 发现明确 synthetic、未 join 的 retained spawn intent 后在 READY 前拒绝；intent 与旧 claim 的全字节/full9 不变，不伪造 join、不新增输入或消费，锁可重新取得。',
    ['没有创建或终止真实模型孤儿 worker；此控制是保留凭据的真实 admission 拒绝。'])
add('NEG-14', 'resources', '资源回到实测基线', [
    select('selected', 'cases', 'fd_thread_child_cpu_and_owned_temp_cleanup'),
    select('owned', 'checks', 'owned_child_groups_files_and_fd_thread_baseline'),
], [DAILY], '原固定 protocol 的 NEG14 是 host_isolated，要求 confirmed worker/child/file-descriptor cleanup 回实测基线。两条实际 daily 路径均零 worker admission；两个自有 daily 子进程实际 wait、pidfd terminal、两组 census 为空且 killpg(0)=ESRCH；外层 namespace 子进程单独 wait，内外 FD/thread 恢复、自有测试树移除。旧纯 host 组另保留 FD/thread/child CPU 基线。',
    ['进程组为本轮新建自有测试组；没有向现有项目、phone、native 或模型角色发送信号。',
     'RSS/整套 installed runtime/真实模型 slot 未测；原 NEG14 未要求这些字段，此处只说明范围，不新增资格门。没有创建真实模型 worker，worker admission 两路均为零。'])

combo_path = 'references/COMBINATION-7969.original.json'
combo_raw = (ROOT / combo_path).read_bytes()
combo = json.loads(combo_raw)
protocol_path = 'references/fixed19.original-protocol.json'
protocol_raw = (ROOT / protocol_path).read_bytes()
assert pin(protocol_raw) == {'bytes': 37318, 'sha256': 'c573959e59fd9fbe7a850d6d2d6d747e3135718493f15de4a8acde850bad93b0'}
protocol = json.loads(protocol_raw)
protocol_neg14 = [row for row in protocol['cases'] if row['id'] == 'NEG-14']
assert len(protocol_neg14) == 1 and protocol_neg14[0]['layer'] == 'host_isolated'
sources = []
for row in combo['production_files']:
    name = Path(row['path']).name
    path = 'references/native-v3/candidate/source/' + name
    raw = (ROOT / path).read_bytes()
    assert pin(raw) == {key: row[key] for key in ('bytes', 'sha256')}
    sources.append({'name': name, 'path': path, **pin(raw)})
value = {
    'schema': 'fc33.neg10-neg14.final15.condition-map.v1',
    'current_combination': {'path': combo_path, **pin(combo_raw)},
    'fixed_protocol': {'path': protocol_path, **pin(protocol_raw)},
    'original_NEG14_definition': protocol_neg14[0],
    'sources': sources, 'source_count': 15, 'conditions': CONDITIONS,
    'actual_BUILD': None, 'installed_tuple': None, 'actual_READY': None,
    'whole_cases_closed': [],
    'unmeasured_scope_not_additional_qualification_gates': {'full_installed_runtime_RSS': None, 'real_model_slot_resource_samples': None},
    'counts_are_original_groups_not_sum': True,
    'current_evidence_groups': {'native': {'parser': 73, 'consumer': 12, 'trust_parser': 40,
                                         'trust_consumer': 11, 'dispatch_binding': 9, 'ledger_binding': 1},
                                'shared': 14, 'selected': 13, 'owned_neg14': 4},
    'common_pending_gates': [
        'Exact current actual sealed BUILD originals verified by the reviewed current release reader',
        'Exact installed/start/READY originals verified by the reviewed current install reader',
    ],
    'generation_trust_boundary_is_not_promoted_to_independent_attestation': True,
}
raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()
target = ROOT / 'CONDITION-MAP.json'
if target.exists():
    assert target.read_bytes() == raw, 'do not overwrite a different published condition map'
else:
    target.write_bytes(raw)
print(json.dumps({'conditions': len(CONDITIONS), 'result': pin(raw)}, sort_keys=True))
