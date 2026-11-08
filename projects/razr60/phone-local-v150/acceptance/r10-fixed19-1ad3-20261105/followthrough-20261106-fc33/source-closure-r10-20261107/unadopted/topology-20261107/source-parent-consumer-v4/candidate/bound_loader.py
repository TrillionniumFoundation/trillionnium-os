"""Bind the actual v4 constructor bytes before any current-consumer construction."""
import hashlib
import types

CONSTRUCTOR_PIN = {'bytes': 23887, 'sha256': 'ce3661cb3726b159da2e85dea6c4a4fc1aaeb8f04ebddcb9ff36061e0b39ec5e'}

def load_bound(actual_source, declared_source):
    if type(actual_source) is not bytes or {
            'bytes': len(actual_source), 'sha256': hashlib.sha256(actual_source).hexdigest()} != CONSTRUCTOR_PIN:
        raise ValueError('exact independently pinned consumer constructor bytes required')
    if type(declared_source) is not bytes or declared_source != actual_source:
        raise ValueError('declared consumer source differs from actual compiled bytes')
    module = types.ModuleType('UNADOPTED_bound_source_parent_consumer_constructor')
    module.__file__ = '<UNADOPTED-bound-consumer-constructor:' + CONSTRUCTOR_PIN['sha256'] + '>'
    module.__constructor_loaded_source__ = actual_source
    exec(compile(actual_source, module.__file__, 'exec'), module.__dict__)
    return module
