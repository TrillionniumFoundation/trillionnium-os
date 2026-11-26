"""Proof-copy mapping of the 46-case explicit-model test to its exact 34-case predecessor.
The current 46-case Java file is always the compiler input; this helper is only
for a historical closed-scope assertion and grants no runtime authority.
"""
import hashlib

CURRENT_BYTES=48955
CURRENT_SHA256="964a1dfa97d9bb582e3937c8d01976e836bdea26d64c7bde77930241bf673993"
PREDECESSOR_BYTES=33714
PREDECESSOR_SHA256="e552be17b5a3275c9c6639ca00ae09fd5c8bb69dd089ab6fd9ecd38e1243bd48"
BLOCK_BYTES=15219
BLOCK_SHA256="9af4600c2a3ddac51d8dfdadde19f679c7b2007bfb467dec7e5676350dadc311"
START=b"\n    private static android.app.AlertDialog textPicker(Env e)throws Exception {\n"
END=b"    public static void main(String[] args)throws Exception {\n"
CURRENT_CALL=b"        try{flightPreferenceCases(Paths.get(args[1]));textPreferenceCases();}\n"
PREVIOUS_CALL=b"        try{flightPreferenceCases(Paths.get(args[1]));}\n"

def predecessor(raw):
    if not isinstance(raw,bytes):
        raise ValueError("complete automatic-target Java test bytes required")
    actual=(len(raw),hashlib.sha256(raw).hexdigest())
    if actual==(PREDECESSOR_BYTES,PREDECESSOR_SHA256):
        return raw
    if actual!=(CURRENT_BYTES,CURRENT_SHA256):
        raise ValueError("reviewed complete 46-case automatic-target test required")
    if raw.count(START)!=1 or raw.count(END)!=1 or raw.count(CURRENT_CALL)!=1:
        raise ValueError("unique complete explicit-model test boundaries required")
    lo=raw.index(START);hi=raw.index(END,lo)
    block=raw[lo:hi]
    if (len(block),hashlib.sha256(block).hexdigest())!=(BLOCK_BYTES,BLOCK_SHA256):
        raise ValueError("complete explicit-model test addition required")
    proof=(raw[:lo]+raw[hi:]).replace(CURRENT_CALL,PREVIOUS_CALL,1)
    if (len(proof),hashlib.sha256(proof).hexdigest())!=(PREDECESSOR_BYTES,PREDECESSOR_SHA256):
        raise ValueError("automatic-target proof must recover every original test byte")
    return proof
