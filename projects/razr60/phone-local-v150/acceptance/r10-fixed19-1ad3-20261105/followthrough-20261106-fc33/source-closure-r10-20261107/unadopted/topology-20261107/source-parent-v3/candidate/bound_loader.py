"""Bind the actual constructor bytes before any source-parent construction."""
import hashlib
import types

CONSTRUCTOR_PIN = {'bytes': 19589, 'sha256': '8f1eeb66110127ee295d356b3f365ea209969c689c6a80bfdb0ad1520658fd42'}


def load_bound(actual_source, declared_source):
    if type(actual_source) is not bytes or {
            'bytes': len(actual_source), 'sha256': hashlib.sha256(actual_source).hexdigest()} != CONSTRUCTOR_PIN:
        raise ValueError('exact independently pinned source-parent constructor bytes required')
    if type(declared_source) is not bytes or declared_source != actual_source:
        raise ValueError('declared constructor source differs from actual compiled bytes')
    module = types.ModuleType('UNADOPTED_bound_source_parent_constructor')
    module.__file__ = '<UNADOPTED-bound-source-parent-constructor:' + CONSTRUCTOR_PIN['sha256'] + '>'
    module.__constructor_loaded_source__ = actual_source
    exec(compile(actual_source, module.__file__, 'exec'), module.__dict__)
    return module
