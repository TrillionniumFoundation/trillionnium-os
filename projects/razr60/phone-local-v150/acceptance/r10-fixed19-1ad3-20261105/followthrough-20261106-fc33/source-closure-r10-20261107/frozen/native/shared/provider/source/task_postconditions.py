"""Trusted, request-bound business postconditions; no new wire fields.

The operator may pre-create a private contract for a new semantic turn. Model
text cannot create or relax it. Protocol completion is distinct from verified
business completion. Facts are verified native receipts, never model claims.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from provider_openai_compatible import ProviderError

IDENTITY = ('session_id', 'profile_id', 'task_id', 'turn_id')
SHA = re.compile(r'[0-9a-f]{64}\Z')
ID = re.compile(r'[A-Za-z0-9_-]{1,64}\Z')
PACKAGE = re.compile(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+\Z')
VIEW = re.compile(r'[A-Za-z][A-Za-z0-9_.]*:id/[A-Za-z0-9_]+\Z')
APP_COMPONENT = re.compile(r'[A-Za-z][A-Za-z0-9_.$]*/(?:\.)?[A-Za-z][A-Za-z0-9_.$]*\Z')
TASK_VERSIONS = ('v149.1', 'v150.2', 'v150.3')
APP_SCOPE_SCHEMA = 'hepta.task-app-scope.v1'


def require(ok, reason):
    if not ok:
        raise ProviderError('task contract: ' + reason)


def identity_key(identity):
    return hashlib.sha256(json.dumps([identity[name] for name in IDENTITY],
                                    separators=(',', ':')).encode()).hexdigest()


def request_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()


def app_scope_hash(scope):
    return hashlib.sha256(json.dumps(scope, ensure_ascii=False, sort_keys=True,
                                     separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def validate_app_scope(scope, owner_request_sha256, approved_apps=None):
    """Validate an operator declaration; never infer targets or actions from prose."""
    require(isinstance(owner_request_sha256, str) and SHA.fullmatch(owner_request_sha256),
            'app scope owner request digest differs')
    require(isinstance(scope, dict) and set(scope) == {'schema', 'owner_request_sha256', 'apps'}
            and scope['schema'] == APP_SCOPE_SCHEMA
            and scope['owner_request_sha256'] == owner_request_sha256,
            'app scope schema or exact owner request binding differs')
    require(isinstance(scope['apps'], list) and 1 <= len(scope['apps']) <= 64,
            'app scope requires a nonempty bounded explicit subset')
    seen = set()
    for entry in scope['apps']:
        require(isinstance(entry, dict) and set(entry) == {'alias', 'component'},
                'app scope entry fields differ')
        alias, component = entry['alias'], entry['component']
        require(isinstance(alias, str) and 0 < len(alias.encode()) <= 128 and '\0' not in alias
                and alias not in seen, 'app scope alias malformed or duplicated')
        seen.add(alias)
        require(isinstance(component, str) and 0 < len(component.encode()) <= 512
                and APP_COMPONENT.fullmatch(component)
                and component.split('/')[0] != 'org.trillionnium.owneropen',
                'app scope component malformed or reserved for typed HEPTA return')
        if approved_apps is not None:
            require(isinstance(approved_apps, dict) and alias in approved_apps
                    and isinstance(approved_apps[alias], dict)
                    and approved_apps[alias].get('component') == component,
                    'app scope alias/component tuple differs from approved registry')
    return scope


def resolve_task_apps(contract, owner_request_sha256, approved_apps):
    """One source for decoder and mapper permissions, with explicit legacy modes."""
    require(isinstance(approved_apps, dict) and approved_apps, 'approved app registry absent')
    require(isinstance(owner_request_sha256, str) and SHA.fullmatch(owner_request_sha256),
            'task app scope owner digest absent')
    scope = None
    if contract is None:
        mode = 'legacy_global_registry_no_contract'
    else:
        require(isinstance(contract, dict) and isinstance(contract.get('contract'), dict),
                'trusted contract wrapper differs')
        value = contract['contract']
        require(value.get('schema') in {'hepta.task-contract.' + v for v in TASK_VERSIONS}
                and value.get('request_sha256') == owner_request_sha256,
                'trusted contract app scope request or version differs')
        version = value['schema'].removeprefix('hepta.task-contract.')
        fields = {'schema', 'identity', 'request_sha256', 'postconditions', 'coverage'}
        require(set(value) == fields | ({'app_scope'} if version == 'v150.3' else set()),
                'trusted contract fields differ')
        if value['schema'] == 'hepta.task-contract.v150.3':
            scope = validate_app_scope(value.get('app_scope'), owner_request_sha256, approved_apps)
            mode = 'request_bound_explicit_subset'
        else:
            require('app_scope' not in value, 'legacy contract cannot silently acquire a scope')
            mode = 'legacy_global_registry_' + version
    aliases = [entry['alias'] for entry in scope['apps']] if scope is not None else list(approved_apps)
    # Copy the reviewed tuples. An empty new-version subset never falls back.
    selected = {alias: dict(approved_apps[alias]) for alias in aliases}
    require(selected, 'task app scope resolved to no approved targets')
    evidence = {'schema': 'hepta.resolved-task-app-scope.v1', 'mode': mode,
                'owner_request_sha256': owner_request_sha256,
                'app_scope': json.loads(json.dumps(scope, ensure_ascii=False)) if scope is not None else None,
                'app_scope_sha256': app_scope_hash(scope) if scope is not None else None,
                'apps': [{'alias': alias, 'component': selected[alias]['component']} for alias in sorted(selected)],
                'components_are_launch_entries': True, 'subsequent_navigation_boundary': 'selected_component_packages',
                'typed_hepta_return_is_explicit_exception': True, 'scope_is_not_an_action_plan': True}
    return selected, evidence


def private_directory(directory):
    info = directory.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o700 and directory.resolve() == directory,
            'directory must be private and canonical')


def private_json(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 16384,
                'file identity or size differs')
        raw = os.read(fd, 16385)
        after, named = os.fstat(fd), path.lstat()
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
        require(len(raw) == info.st_size and all(getattr(info, key) == getattr(after, key)
                == getattr(named, key) for key in fields), 'file changed while read')
    finally:
        os.close(fd)
    def unique(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate key')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    require(isinstance(value, dict), 'JSON object required')
    return value, hashlib.sha256(raw).hexdigest()


def validate_conditions(conditions, *, allow_anchor=False):
    require(isinstance(conditions, list) and 1 <= len(conditions) <= 8, 'postcondition count differs')
    seen = set()
    for condition in conditions:
        require(isinstance(condition, dict) and isinstance(condition.get('id'), str)
                and ID.fullmatch(condition['id']) and condition['id'] not in seen, 'condition id differs')
        seen.add(condition['id'])
        kind = condition.get('kind')
        if kind == 'foreground_hepta':
            require(set(condition) == {'id', 'kind'}, 'foreground fields differ')
        elif kind in {'text_readback_exact', 'public_text_exact'}:
            require(set(condition) == {'id', 'kind', 'package', 'view_id', 'utf8_sha256'}
                    and isinstance(condition['package'], str) and PACKAGE.fullmatch(condition['package'])
                    and isinstance(condition['view_id'], str) and VIEW.fullmatch(condition['view_id'])
                    and isinstance(condition['utf8_sha256'], str) and SHA.fullmatch(condition['utf8_sha256']),
                    'text readback fields differ')
        elif kind == 'public_text_anchor_exact' and allow_anchor:
            require(set(condition) == {'id', 'kind', 'package', 'component', 'title_view_id',
                    'anchor_text', 'value_view_id', 'utf8_sha256'}
                    and isinstance(condition['package'], str) and PACKAGE.fullmatch(condition['package'])
                    and isinstance(condition['component'], str)
                    and re.fullmatch(r'[A-Za-z][A-Za-z0-9_.]*/[A-Za-z][A-Za-z0-9_.$]*', condition['component'])
                    and condition['component'].split('/')[0] == condition['package']
                    and all(isinstance(condition[key], str) and VIEW.fullmatch(condition[key])
                            for key in ('title_view_id', 'value_view_id'))
                    and condition['title_view_id'] != condition['value_view_id']
                    and isinstance(condition['anchor_text'], str) and 0 < len(condition['anchor_text'].encode()) <= 256
                    and '\0' not in condition['anchor_text']
                    and isinstance(condition['utf8_sha256'], str) and SHA.fullmatch(condition['utf8_sha256']),
                    'anchored public text fields differ')
        elif kind == 'visual_receipt_matches_challenge':
            require(set(condition) == {'id', 'kind', 'package', 'challenge_view_id', 'receipt_view_id', 'receipt_prefix', 'challenge_prefix'}
                    and isinstance(condition['package'], str) and PACKAGE.fullmatch(condition['package'])
                    and all(isinstance(condition[key], str) and VIEW.fullmatch(condition[key])
                            for key in ('challenge_view_id', 'receipt_view_id'))
                    and condition['challenge_view_id'] != condition['receipt_view_id']
                    and isinstance(condition['receipt_prefix'], str)
                    and 0 < len(condition['receipt_prefix'].encode()) <= 256 and '\0' not in condition['receipt_prefix']
                    and isinstance(condition['challenge_prefix'], str)
                    and 0 < len(condition['challenge_prefix'].encode()) <= 256 and '\0' not in condition['challenge_prefix'],
                    'visual public receipt fields differ')
        else:
            raise ProviderError('task contract: unsupported postcondition')


def write_exclusive(path, value):
    raw = (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    return hashlib.sha256(raw).hexdigest()


def validate_template(value):
    scoped = isinstance(value, dict) and value.get('schema') == 'hepta.task-template.v150.3'
    fields = {'schema', 'expected_scope', 'request_sha256', 'nonce', 'postconditions', 'coverage'}
    require(isinstance(value, dict) and set(value) == fields | ({'app_scope'} if scoped else set())
            and value['schema'] in {'hepta.task-template.' + v for v in TASK_VERSIONS}, 'template schema differs')
    scope = value['expected_scope']
    require(isinstance(scope, dict) and set(scope) == {'session_id', 'profile_id'}
            and all(isinstance(item, str) and 0 < len(item.encode()) <= 256 and '\0' not in item
                    for item in scope.values()), 'template scope differs')
    require(isinstance(value['request_sha256'], str) and SHA.fullmatch(value['request_sha256'])
            and isinstance(value['nonce'], str)
            and re.fullmatch(r'[A-Za-z0-9_-]{16,64}', value['nonce']), 'template request hash or nonce differs')
    require(value['coverage'] in {'entire_request', 'declared_postconditions_only'}, 'template coverage differs')
    validate_conditions(value['postconditions'], allow_anchor=value['schema'] != 'hepta.task-template.v149.1')
    if scoped:
        validate_app_scope(value['app_scope'], value['request_sha256'])


def load_contract(directory, identity, request):
    if directory is None:
        return None
    directory = Path(directory)
    if not directory.exists():
        return None
    private_directory(directory)
    exact = private_json(directory / (identity_key(identity) + '.json'))
    if exact is not None:
        value, source_sha = exact
        scoped = value.get('schema') == 'hepta.task-contract.v150.3'
        fields = {'schema', 'identity', 'request_sha256', 'postconditions', 'coverage'}
        require(set(value) == fields | ({'app_scope'} if scoped else set())
                and value['schema'] in {'hepta.task-contract.' + v for v in TASK_VERSIONS}, 'schema differs')
        require(value['identity'] == {key: identity[key] for key in IDENTITY}
                and value['request_sha256'] == request_hash(request), 'turn or request binding differs')
        validate_conditions(value['postconditions'], allow_anchor=value['schema'] != 'hepta.task-contract.v149.1')
        if scoped:
            validate_app_scope(value['app_scope'], value['request_sha256'])
        require(value['coverage'] in {'entire_request', 'declared_postconditions_only'}, 'contract coverage differs')
        return {'contract': value, 'source_sha256': source_sha, 'binding_kind': 'exact_identity'}
    templates, bindings = directory/'templates', directory/'bindings'
    if not templates.exists():
        return None
    private_directory(templates)
    template = private_json(templates / (request_hash(request) + '.json'))
    if template is None:
        return None
    value, template_sha = template
    validate_template(value)
    require(value['request_sha256'] == request_hash(request) and request.count(value['nonce']) == 1
            and value['expected_scope'] == {key: identity[key] for key in ('session_id', 'profile_id')},
            'template request, nonce or known scope differs')
    private_directory(bindings)
    bound_identity = {key: identity[key] for key in IDENTITY}
    version = value['schema'].removeprefix('hepta.task-template.')
    binding = {'schema': 'hepta.task-template-binding.' + version, 'identity': bound_identity,
               'request_sha256': value['request_sha256'], 'template_sha256': template_sha,
               'nonce': value['nonce'], 'state': 'consumed_no_reuse'}
    if version == 'v150.3':
        binding.update(app_scope=value['app_scope'], app_scope_sha256=app_scope_hash(value['app_scope']))
    try:
        binding_sha = write_exclusive(bindings / (value['request_sha256'] + '.json'), binding)
    except FileExistsError as error:
        raise ProviderError('task contract: one-time request template already consumed; no task dispatch') from error
    contract = {'schema': 'hepta.task-contract.' + version, 'identity': bound_identity,
                'request_sha256': value['request_sha256'], 'postconditions': value['postconditions'], 'coverage': value['coverage']}
    if version == 'v150.3':
        contract['app_scope'] = value['app_scope']
    contract_sha = hashlib.sha256(json.dumps(contract, sort_keys=True, ensure_ascii=False,
                                           separators=(',', ':')).encode()).hexdigest()
    return {'contract': contract, 'source_sha256': contract_sha,
            'binding_kind': 'one_time_request_template', 'template_sha256': template_sha,
            'binding_sha256': binding_sha}


def evaluate(contract, facts, last_result_call_id, model_status, protocol_kind):
    checks = []
    for condition in (contract['contract']['postconditions'] if contract else []):
        if condition['kind'] == 'foreground_hepta':
            candidates = [fact for fact in facts if fact['kind'] == 'foreground_hepta'
                          and fact['call_id'] == last_result_call_id]
        elif condition['kind'] == 'text_readback_exact':
            # Exact readback is a receipt at that point in the task, not an
            # assertion that app state persists after later navigation.
            candidates = [fact for fact in facts if fact['kind'] == 'text_readback_exact'
                          and fact['package'] == condition['package'] and fact['view_id'] == condition['view_id']]
            if candidates:
                candidates = candidates[-1:]
            candidates = [fact for fact in candidates if fact['utf8_sha256'] == condition['utf8_sha256']]
        elif condition['kind'] == 'public_text_exact':
            candidates = []
            for fact in facts:
                if fact['kind'] != 'public_text_observation' or fact['package'] != condition['package']:
                    continue
                for value in fact['values']:
                    if value['view_id'] == condition['view_id']:
                        candidates.append({**fact, 'matched_value': value})
            if candidates:
                candidates = candidates[-1:]
            candidates = [fact for fact in candidates if fact['matched_value']['utf8_sha256'] == condition['utf8_sha256']]
        elif condition['kind'] == 'public_text_anchor_exact':
            candidates = []
            for fact in facts:
                if (fact.get('kind') != 'public_text_anchor_observation'
                        or fact.get('package') != condition['package']
                        or fact.get('component') != condition['component'] or fact.get('display_id') != 0):
                    continue
                value = fact.get('anchor_value', {})
                if (value.get('selector_schema') == 'hepta.public-text-anchor.v150.1'
                        and value.get('relation') == 'same_direct_preference_text_container'
                        and all(value.get(key) == condition[key] for key in
                                ('title_view_id', 'anchor_text', 'value_view_id'))):
                    candidates.append(fact)
            candidates = candidates[-1:]
            candidates = [fact for fact in candidates if fact['anchor_value']['utf8_sha256'] == condition['utf8_sha256']]
        else:
            candidates, last_tap = [], None
            for fact in facts:
                if fact['kind'] == 'visual_tap_executed' and fact['package'] == condition['package']:
                    last_tap = fact
                if fact['kind'] != 'public_text_observation' or fact['package'] != condition['package']:
                    continue
                values = {value['view_id']: value for value in fact['values']}
                if condition['challenge_view_id'] not in values or condition['receipt_view_id'] not in values:
                    continue
                challenge, receipt = values[condition['challenge_view_id']], values[condition['receipt_view_id']]
                # Qualified control-probe format: literal trusted prefix,
                # then exactly one eight-character uppercase hexadecimal code.
                # Never strip whitespace, normalize case, or pick one of many.
                text = challenge['text']
                code = text[len(condition['challenge_prefix']):] if text.startswith(condition['challenge_prefix']) else ''
                matched = bool(last_tap and re.fullmatch(r'[0-9A-F]{8}', code)
                               and receipt['text'] == condition['receipt_prefix'] + code)
                # The latest pair in one public snapshot is authoritative;
                # older good receipts never override a later mismatch.
                candidates = [{**fact, 'matched_challenge': challenge, 'matched_receipt': receipt,
                               'preceding_visual_tap': last_tap}] if matched else []
        checks.append({'id': condition['id'], 'kind': condition['kind'], 'satisfied': bool(candidates),
                       'evidence': candidates[-1] if candidates else None})
    conditions_verified = bool(contract and checks and all(check['satisfied'] for check in checks))
    verified = bool(conditions_verified and contract['contract']['coverage'] == 'entire_request'
                    and model_status == 'completed' and protocol_kind == 'turn.complete')
    status = ('verified' if verified else 'unverified_no_contract' if not contract
              else 'partial' if any(check['satisfied'] for check in checks) else 'unverified')
    version = contract['contract']['schema'].removeprefix('hepta.task-contract.') if contract else 'v149.1'
    require(version in TASK_VERSIONS, 'business outcome contract version differs')
    outcome = {'schema': 'hepta.business-outcome.' + version, 'business_verified': verified,
            'status': status, 'model_reported_status': model_status,
            'requested_protocol_terminal': protocol_kind,
            'coverage': contract['contract']['coverage'] if contract else None,
            'postconditions_verified': conditions_verified,
            'contract_sha256': contract['source_sha256'] if contract else None,
            'postconditions': checks, 'verified_facts': facts,
            'missing_postconditions': [item['id'] for item in checks if not item['satisfied']],
            'native_completed_is_business_success': False}
    if version == 'v150.3':
        scope = validate_app_scope(contract['contract']['app_scope'], contract['contract']['request_sha256'])
        outcome.update(app_scope=scope, app_scope_sha256=app_scope_hash(scope))
    return outcome


def terminal_fields(kind, fields, outcome, has_actions):
    """Return only existing turn.* fields accepted by the native protocol."""
    if kind != 'turn.complete':
        return kind, fields
    model_status = outcome['model_reported_status']
    contract_failed = outcome['contract_sha256'] is not None and not outcome['business_verified']
    if contract_failed or model_status in {'partial', 'failed', 'unknown'}:
        missing = ', '.join(outcome['missing_postconditions']) or (
            '合约只覆盖列出的局部后条件，尚不能确认整项任务' if outcome['coverage'] == 'declared_postconditions_only'
            else '模型报告任务尚未完成或无法确认')
        return 'turn.fail', {'error': '[business_not_verified] 业务未完成或仅部分完成；未验证后条件：'
                            + missing + '。已执行动作不会自动重放。'}
    prefix = ('[业务已按明确后条件验证] ' if outcome['business_verified'] else
              '[业务未独立验证；流程已结束] ' if has_actions else '[无动作；业务未独立验证] ')
    return kind, {'summary': prefix + str(fields.get('summary', ''))}
