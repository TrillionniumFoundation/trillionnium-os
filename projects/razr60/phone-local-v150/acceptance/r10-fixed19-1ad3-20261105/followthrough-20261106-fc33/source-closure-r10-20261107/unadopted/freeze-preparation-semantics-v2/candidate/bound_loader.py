"""Load the separately identified offline source-freeze semantics."""
import hashlib
import types

EXPECTED_BYTES = 30816
EXPECTED_SHA256 = '7673496d3f29b5f21b312c0b1208a4497426b4f21f4f51bddba3910422b9566d'

def load(source_bytes, declared_source_bytes):
    if type(source_bytes) is not bytes or len(source_bytes) != EXPECTED_BYTES or hashlib.sha256(source_bytes).hexdigest() != EXPECTED_SHA256:
        raise ValueError("exact source-freeze implementation bytes required")
    if type(declared_source_bytes) is not bytes or source_bytes != declared_source_bytes:
        raise ValueError("declared source must equal actual compiled source bytes")
    module = types.ModuleType("UNADOPTED_source_freeze_" + EXPECTED_SHA256)
    module.__bound_source_bytes__ = source_bytes
    exec(compile(source_bytes, "<bound-source-freeze-semantics>", "exec", dont_inherit=True), module.__dict__)
    return module
