"""Exact proof-copy inverse for the reviewed canonical byte reuse only."""
import hashlib
BASE_SHA = "e7f5ba2bf975f5a39ab47909176912ec1e825c32fb51ac778ee6a76e4abcf39d"
CURRENT_SHA = "b3c99f53c94b662ee35ffa26054f22f647fd2744d34edbc67d847afe9a05e651"
REPLACEMENTS = [('this.kind=kind;this.receipt=freezeMap(receipt);binding=map(this.receipt,"binding");validate(this.receipt,kind);\n        byte[] expected=canonicalBytes(this.receipt);', 'this.kind=kind;this.receipt=freezeMap(receipt);binding=map(this.receipt,"binding");\n        byte[] expected=validate(this.receipt,kind);'), ('Map<String,Object> frozen=freezeMap(receipt);validate(frozen,NATIVE_AX);return canonicalBytes(frozen);', 'Map<String,Object> frozen=freezeMap(receipt);return validate(frozen,NATIVE_AX);'), ('Map<String,Object> frozen=freezeMap(receipt);validate(frozen,NATIVE_AX_FORM_HISTORY);return canonicalBytes(frozen);', 'Map<String,Object> frozen=freezeMap(receipt);return validate(frozen,NATIVE_AX_FORM_HISTORY);'), ('Map<String,Object> frozen=freezeMap(receipt);validate(frozen,NATIVE_AX_INPUT_HISTORY);return canonicalBytes(frozen);', 'Map<String,Object> frozen=freezeMap(receipt);return validate(frozen,NATIVE_AX_INPUT_HISTORY);'), ('private static void validate(Map<String,Object> r,String kind){', 'private static byte[] validate(Map<String,Object> r,String kind){'), ('        canonicalBytes(r); // UTF-8, including real Chinese text and JSON escapes, is the byte limit.', '        return canonicalBytes(r); // Reuse these exact UTF-8 bytes; the full byte-limit check remains here.')]
def predecessor(raw):
    digest=hashlib.sha256(raw).hexdigest()
    if digest==BASE_SHA:
        return raw
    if digest!=CURRENT_SHA:
        raise RuntimeError("unreviewed capture source bytes")
    text=raw.decode("utf-8")
    for before,after in REPLACEMENTS:
        if text.count(after)!=1:
            raise RuntimeError("canonical reuse inverse hunk is not unique")
        text=text.replace(after,before,1)
    parent=text.encode("utf-8")
    if hashlib.sha256(parent).hexdigest()!=BASE_SHA:
        raise RuntimeError("complete capture predecessor bytes differ")
    return parent
