"""Independently bind actual v5 constructor bytes before new current selection."""
import hashlib
import types
CONSTRUCTOR_PIN = {'bytes': 31905, 'sha256': '88eec8400731b2131f4361ded2c5e480fa7abfca526a7f9be4463a3e48b25bde'}

def load_bound(actual_source, declared_source):
    if type(actual_source) is not bytes or {
            'bytes': len(actual_source), 'sha256': hashlib.sha256(actual_source).hexdigest()} != CONSTRUCTOR_PIN:
        raise ValueError('exact independently pinned v5 constructor bytes required')
    if type(declared_source) is not bytes or declared_source != actual_source:
        raise ValueError('declared v5 constructor source differs from actual compiled bytes')
    module=types.ModuleType('UNADOPTED_bound_retained_current_constructor')
    module.__file__='<UNADOPTED-bound-v5-constructor:'+CONSTRUCTOR_PIN['sha256']+'>'
    module.__constructor_loaded_source__=actual_source
    exec(compile(actual_source,module.__file__,'exec'),module.__dict__)
    return module
