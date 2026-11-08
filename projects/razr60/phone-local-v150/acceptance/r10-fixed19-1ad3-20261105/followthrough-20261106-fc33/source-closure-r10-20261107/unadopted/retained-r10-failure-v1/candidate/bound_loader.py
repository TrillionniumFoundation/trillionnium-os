"""Load exactly the independently identified retained-failure implementation."""
import hashlib
import types

EXPECTED_BYTES = 35444
EXPECTED_SHA256 = 'bb9809c6767d4822d1ceab7eb82e2d2386eab0af87592cedb971edc07e092901'

def load(source_bytes):
    if type(source_bytes) is not bytes or len(source_bytes) != EXPECTED_BYTES or hashlib.sha256(source_bytes).hexdigest() != EXPECTED_SHA256:
        raise ValueError("exact retained-R10 failure implementation bytes required")
    module = types.ModuleType("hepta_unadopted_retained_r10_" + EXPECTED_SHA256)
    module.__file__ = "UNADOPTED/retained-r10-failure/" + EXPECTED_SHA256 + ".py"
    module.__bound_source_bytes__ = source_bytes
    exec(compile(source_bytes, module.__file__, "exec", dont_inherit=True), module.__dict__)
    return module
