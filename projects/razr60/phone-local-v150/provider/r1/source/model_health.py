"""Observed CLI health, separate from transport readiness and task acceptance.

Only original top-level CLI failure events enter this classifier. Tool output,
model prose and phone receipts never update model availability. A failed turn
remains consumed; this module neither retries nor changes account or model.
"""
import datetime
import hashlib
import json
import os
import re
import stat
import threading

from provider_openai_compatible import ProviderError


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


PUBLIC_ERRORS = {
    'usage_limit_exceeded': '模型额度已用尽；本次任务未完成。请在额度恢复后明确发起新任务，已执行动作不会自动重放。',
    'authentication_failed': '模型登录或授权失效；本次任务未完成，需要检查当前已选账号的授权。',
    'rate_limit_exceeded': '模型请求受到速率限制；本次任务未完成，未自动重试。',
    'request_rejected': '模型服务拒绝了请求；本次任务未完成，未切换模型或重试。',
    'transport_unavailable': '模型连接失败；本次任务结果不完整，未自动重试。',
    'model_timeout': '模型请求超时；本次任务结果不完整，已执行动作不会自动重放。',
    'model_budget_exhausted': '本地模型输出预算耗尽；本次任务未完成，未提高预算或重放动作。',
    'unknown_model_failure': '模型请求失败，具体原因未获确认；本次任务未完成，未自动重试。',
}


class ModelFailure(ProviderError):
    def __init__(self, category, event=None):
        if category not in PUBLIC_ERRORS:
            raise ValueError('unknown model failure category')
        self.category = category
        self.event_sha256 = (hashlib.sha256(json.dumps(event, sort_keys=True,
            ensure_ascii=False, separators=(',', ':')).encode()).hexdigest() if event is not None else None)
        super().__init__('[' + category + '] ' + PUBLIC_ERRORS[category])

    def receipt(self):
        return {'category': self.category, 'event_sha256': self.event_sha256,
                'public_error': str(self), 'automatic_retry': False,
                'account_or_model_changed': False, 'business_verified': False}


def cli_failure(event):
    """Classify only two trusted event envelopes, never arbitrary nested text."""
    if not isinstance(event, dict) or event.get('type') not in {'error', 'turn.failed'}:
        raise ValueError('not a top-level CLI failure event')
    error = event.get('error')
    error = error if isinstance(error, dict) else {}
    codes = {str(value).lower() for value in (event.get('code'), error.get('code'),
                                            error.get('type')) if isinstance(value, str)}
    message = event.get('message', error.get('message')) if event.get('type') == 'error' else error.get('message')
    text = message.lower().replace('’', "'") if isinstance(message, str) else ''
    if codes & {'usage_limit_exceeded', 'insufficient_quota', 'quota_exceeded'} or re.search(
            r"\b(?:you've hit your usage limit|usage limit (?:has been )?exceeded|insufficient quota)\b", text):
        category = 'usage_limit_exceeded'
    elif codes & {'authentication_error', 'invalid_api_key', 'unauthorized', 'authentication_failed'} or re.search(
            r'\b(?:authentication (?:failed|error)|invalid api key|not authenticated|login required)\b', text):
        category = 'authentication_failed'
    elif codes & {'rate_limit_exceeded', 'rate_limit_error'} or re.search(r'\brate limit (?:reached|exceeded)\b', text):
        category = 'rate_limit_exceeded'
    elif codes & {'invalid_request_error', 'bad_request', 'request_rejected'}:
        category = 'request_rejected'
    elif codes & {'timeout', 'request_timeout', 'deadline_exceeded'} or re.search(r'\b(?:request timed out|request timeout|deadline exceeded)\b', text):
        category = 'model_timeout'
    elif codes & {'connection_error', 'network_error', 'service_unavailable'} or re.search(
            r'\b(?:connection (?:reset|refused|closed)|network is unreachable|service unavailable)\b', text):
        category = 'transport_unavailable'
    else:
        category = 'unknown_model_failure'
    return ModelFailure(category, event)


class ModelHealth:
    """Persist observations with an in-flight ordering fence.

    A success from a request already in flight when a failure was observed
    cannot clear that failure. Only a later-started successful request can do
    so. No availability prediction or quota probe is performed here.
    """
    SCHEMA = 'hepta.model-health.v149.1'

    def __init__(self, path, model, writer):
        self.path, self.model, self.writer = path, model, writer
        self.lock = threading.Lock()
        self.value = {'schema': self.SCHEMA, 'model': model, 'availability': 'unknown',
                      'reason': 'not_observed', 'issued': 0, 'failure_fence': 0,
                      'last_success': None, 'last_failure': None,
                      'readiness_is_model_health': False, 'automatic_probe_or_retry': False}
        try:
            path.lstat()
            exists = True
        except FileNotFoundError:
            exists = False
        if exists:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 16384):
                    raise ProviderError('model health state identity is invalid')
                raw = os.read(fd, 16385)
                after, named = os.fstat(fd), path.lstat()
                fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
                if len(raw) != info.st_size or any(getattr(info, field) != getattr(after, field)
                        or getattr(info, field) != getattr(named, field) for field in fields):
                    raise ProviderError('model health state changed while read')
            finally:
                os.close(fd)
            value = json.loads(raw)
            if (value.get('schema') != self.SCHEMA or value.get('model') != model
                    or type(value.get('issued')) is not int or value['issued'] < 0
                    or type(value.get('failure_fence')) is not int
                    or not 0 <= value['failure_fence'] <= value['issued']
                    or value.get('availability') not in {'unknown', 'observed_available', 'observed_unavailable'}):
                raise ProviderError('model health state schema differs')
            self.value.update(value)
        self.writer(self.path, self.value)

    def begin(self):
        with self.lock:
            self.value['issued'] += 1
            attempt = {'id': self.value['issued'], 'started_utc': utc()}
            self.writer(self.path, self.value)
            return attempt

    def success(self, attempt):
        with self.lock:
            observation = {**attempt, 'observed_utc': utc()}
            self.value['last_success'] = observation
            if attempt['id'] > self.value['failure_fence']:
                self.value.update(availability='observed_available', reason='successful_structured_decision')
            self.writer(self.path, self.value)

    def failure(self, attempt, error):
        if not isinstance(error, ModelFailure):
            raise ValueError('only a classified model failure updates availability')
        with self.lock:
            self.value['last_failure'] = {**attempt, 'observed_utc': utc(), **error.receipt()}
            self.value['failure_fence'] = self.value['issued']
            protected = self.value['availability'] == 'observed_unavailable' and self.value['reason'] in {
                'usage_limit_exceeded', 'authentication_failed'}
            reason = self.value['reason'] if protected and error.category not in {
                'usage_limit_exceeded', 'authentication_failed'} else error.category
            self.value.update(availability='observed_unavailable', reason=reason)
            self.writer(self.path, self.value)
