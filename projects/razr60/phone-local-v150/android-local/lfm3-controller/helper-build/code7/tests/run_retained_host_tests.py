#!/usr/bin/env python3
"""Rerun original helper focused87 cases against the supplied helper source.

Pure host only: no APK building, ADB, phone, network or deletion. The56 original
retained files and two original identity fixtures are hash-pinned below. Runtime
src/assets are replaced with supplied current helper bytes. The sole test edit is
one explicit synthetic helper-version literal. The caller's frozen source/build
manifest supplies candidate/version/tool admission; this runner records the full
candidate and selected tool bytes before/after and preserves all original cases.
Android UID/PM/Binder/syscalls/renderer boundaries remain explicit host doubles.
"""
import argparse
import difflib
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import time
import traceback

# Derived from the actually rerun retained77 receipt c9c475aa... (not old pass reuse).
RETAINED = {
  "assets/readonly_dom.js": [
    14579,
    "05bb7c1e4e1929b961c42af1e5c0e01918bf6ff64f153132ca11c7d85873e705"
  ],
  "src/org/trillionnium/hepta/background/FixedIntentTarget.java": [
    2730,
    "f5f3936a8185185cf5f036a74665ee6edfbd5c1f617299dd9cd6edd4bf7b23e2"
  ],
  "src/org/trillionnium/hepta/background/FixedIntentTools.java": [
    4137,
    "c20285039abaf4ad6028ffb18c1b5e755eccb9a13059576817e557177a294947"
  ],
  "src/org/trillionnium/hepta/local/ActionDecision.java": [
    25712,
    "ee2a0481bb1ad0d2a3dd95b501c101d1955f4f1142adfe150ba3f9643fa88b20"
  ],
  "src/org/trillionnium/hepta/local/AppCatalogueRanker.java": [
    9217,
    "0bc99b3864ea994ee53ef9c0d5f256ae66309ed19c9104f892c2dbf840597075"
  ],
  "src/org/trillionnium/hepta/local/DecisionGrammar.java": [
    30605,
    "236d22187abfe777705d337241e310dd617b1c4c21ae39df4f52d960a1e106ca"
  ],
  "src/org/trillionnium/hepta/local/NotesOwnerIntent.java": [
    12329,
    "c3d8406e7d3bc6e513e0bad47d043f7d981cca82f5bbac095dce70aa84700e3f"
  ],
  "src/org/trillionnium/hepta/local/ObservedAppLabels.java": [
    4889,
    "0276171bb8aaebee880a6d36fea5cbfdb157b09d2728a07148e4ce85d5ffbb9e"
  ],
  "src/org/trillionnium/hepta/local/ObservedImeEnter.java": [
    4665,
    "e449d61e928dca5a72730b5394fa8f95a7db4dd4006440a95f839818e165acf1"
  ],
  "src/org/trillionnium/hepta/local/ObservedScrollActions.java": [
    2303,
    "c31012cf776fbc4177d6c617341d006f4a45ed63df3cfc435f705e515ebbc188"
  ],
  "src/org/trillionnium/hepta/local/ObservedTargetLabels.java": [
    4685,
    "c4e1b1a7ae0223fc7cda90864c6a5c3759a2875bb435359464672bc79465c8ba"
  ],
  "src/org/trillionnium/hepta/local/TaskAuthorization.java": [
    23598,
    "9dbcabb1d4f505d581c2dc4b9fd772a4f7578344573c372e1831c84e2f82ecc8"
  ],
  "src/org/trillionnium/hepta/local/web/WebFlightGoal.java": [
    9611,
    "02f260915f2b64894b8cd1ed4223392ace9964920d9b77e6765548252d9624ac"
  ],
  "src/org/trillionnium/hepta/local/web/WebShoppingGoal.java": [
    10767,
    "b8eb72eddb99842758dc39b347d2679d247714b97e0a0afe6df217bf2e8cd8c8"
  ],
  "src/org/trillionnium/hepta/webhelper/CaptureReadBudget.java": [
    2367,
    "d1b616cf263a01a1298c992ba1d009d0adf4aa420971b1e27dc95368ecc455cb"
  ],
  "src/org/trillionnium/hepta/webhelper/DomInstabilityEvidence.java": [
    5245,
    "1bf49e47f467ab36ef2dd30696cc442e146999a55b9682dbd6b929ca9dc4d766"
  ],
  "src/org/trillionnium/hepta/webhelper/Jsons.java": [
    5732,
    "484c6daa3a95a9e1849a70e4ceffb3666e23dd148851d2ae356361c2a6693ee5"
  ],
  "src/org/trillionnium/hepta/webhelper/ObservedLinkPermit.java": [
    5951,
    "003ddc4af2695dd31bf26c5afaeffd591d948233d1e0741f93b6aaee8d0efe2a"
  ],
  "src/org/trillionnium/hepta/webhelper/OfficialPageCapture.java": [
    26324,
    "ebb05c09a0fc5b01aa3a058ffba4f9104a9c7a4a4edbe6160b8ba9bccdc6dfc0"
  ],
  "src/org/trillionnium/hepta/webhelper/RemoteReply.java": [
    5433,
    "bb0c441bd6ddb5ae46d9124c471050077a61571aa0d121f8a0cdffaa74d816b4"
  ],
  "src/org/trillionnium/hepta/webprotocol/WebDomCanonical.java": [
    4424,
    "55209ef608fad0d8794d439aab2baf69bd7c8b043289c80ca7b25acaad1ff3d7"
  ],
  "src/org/trillionnium/hepta/webprotocol/WebDomStability.java": [
    16055,
    "f7e432c1191008afa25a134147cd6fd133f975e102aa4cab722da3dc82a4ea53"
  ],
  "src/org/trillionnium/hepta/webprotocol/WebEvidenceBinding.java": [
    4089,
    "90a414863297c1ff173fd14a7b31dce62bb5fbb561e7625f1fe3eb0dace47af7"
  ],
  "src/org/trillionnium/hepta/webprotocol/WebEvidenceProtocol.java": [
    5933,
    "3966bbe1122f6a6e13bf211291332aa63f755a891800d04169016958946f8f0e"
  ],
  "src/org/trillionnium/hepta/webprotocol/WebMiActionRegion.java": [
    20795,
    "027de25550bac1e58d835c1a0582f5f14aff144b76a2f4889f9d48b4f1abcd04"
  ],
  "src/org/trillionnium/hepta/webprotocol/WebObservedNavigation.java": [
    23060,
    "e524d91f50ec8d911692e371fed000d65e1be2f703f3efe36497ae64fd358132"
  ],
  "src/org/trillionnium/hepta/webprotocol/WebSitePolicy.java": [
    5255,
    "d74bf8292782fc7a9e48f3460b8961eecd009d038c8b4e94431b94ecdd04043a"
  ],
  "src/org/trillionnium/hepta/webprotocol/WebStorageEvidence.java": [
    8539,
    "9e8df742ad0fdaac0fbc051c99772a52fbb40aae49f0a43589e252e71acc7fc0"
  ],
  "src/org/trillionnium/hepta/webprotocol/WebTaskPurpose.java": [
    6731,
    "92303867e09343ebcbb3620b9a5850bce683c1d94988d1e534dd272dcaea8647"
  ],
  "tests/capture-retry/CaptureRetryHostTest.java": [
    20334,
    "c3a72bcc69f4470b83602900c7dd0a262a7dd7a3fb5fbd20c5aaa9a6a4329b71"
  ],
  "tests/capture-retry/stubs/android/content/Context.java": [
    334,
    "e61534e39c0fc29875121c95ca3e2fd9179f2b1f1cf7c85dc21f45daa1eb9679"
  ],
  "tests/capture-retry/stubs/android/content/res/AssetManager.java": [
    347,
    "d1b8900938d937823edf242413e566b254a6033b4e063b1fc71c5b35e226e2f6"
  ],
  "tests/capture-retry/stubs/android/graphics/Bitmap.java": [
    56,
    "b39c01638664c6ebb8740713b85ae6cec7bb777e9b9f74e936446c9dd23352eb"
  ],
  "tests/capture-retry/stubs/android/graphics/Rect.java": [
    167,
    "21dab6e39452450a9c7028c476e376e2b30c3fdf6a265f1091e49fc6891734b9"
  ],
  "tests/capture-retry/stubs/android/net/Uri.java": [
    147,
    "06e01f2c1f4e2480302b1f481b1d7df577d1d3e1b63c9eebaf535997ed8f100c"
  ],
  "tests/capture-retry/stubs/android/net/http/SslError.java": [
    58,
    "8d64e156626dc30973fe7e2d6790f771171117f678884ba0873a1233e36c5e4b"
  ],
  "tests/capture-retry/stubs/android/os/Looper.java": [
    232,
    "327a1d79a852807d380472bc720c3c0f9be9c9d40ebcefe008de7d79b9122178"
  ],
  "tests/capture-retry/stubs/android/os/Process.java": [
    133,
    "be51f173977d5d73d1231c445ebdda3448c2fe36c2bdcc5d47660650853a4e38"
  ],
  "tests/capture-retry/stubs/android/os/SystemClock.java": [
    134,
    "2b79c38882b3c91d64e8a6c6e92cf0d70a23cdd5e24a70cdf6f5ad69d333c9a0"
  ],
  "tests/capture-retry/stubs/android/view/Display.java": [
    142,
    "4fee2e98bd47b7c7d7ccbabddd9a3d9013f0b5b2d0b317ab03edfcc2505914bc"
  ],
  "tests/capture-retry/stubs/android/view/accessibility/AccessibilityNodeInfo.java": [
    207,
    "f80b51f869904c36da4c61c70bdd4672c47a409cb27e00a845ae32a8e9d174e3"
  ],
  "tests/capture-retry/stubs/android/webkit/SslErrorHandler.java": [
    79,
    "b1171328dda671ae92ff6f1f790103dd18680d821736e1c18364e9338b4e5946"
  ],
  "tests/capture-retry/stubs/android/webkit/ValueCallback.java": [
    92,
    "e882726ceda5fc142e675c33201302a6da52cffdf05d0316a437246989f91ef0"
  ],
  "tests/capture-retry/stubs/android/webkit/WebResourceError.java": [
    64,
    "e73a32d7125a89b75740285f3d7e7e167e1c05347109a5b1475ee651d2cf1437"
  ],
  "tests/capture-retry/stubs/android/webkit/WebResourceRequest.java": [
    136,
    "d4e3fd44f80e543edb5be1c9df9349cccef301864a783451d7f2335a468ad4a6"
  ],
  "tests/capture-retry/stubs/android/webkit/WebSettings.java": [
    208,
    "35cb3ab06906c1e560d9c51c89e21191c492b17b747cf1e7cd7a4965e696caf3"
  ],
  "tests/capture-retry/stubs/android/webkit/WebView.java": [
    3466,
    "e36d9e5e57129ddea53eee73c11c5da981dd7fe26845f71be731af7d3675d39f"
  ],
  "tests/capture-retry/stubs/android/webkit/WebViewClient.java": [
    621,
    "ef26acac3e8b3c7b1d0f1ab9869ff87c0a8e972d79bb0ab7cb9c9938b1665223"
  ],
  "tests/capture-retry/stubs/org/trillionnium/hepta/webhelper/PageSitePolicy.java": [
    544,
    "07eff4bd74df362767bf6429b367bd9260404d0b4f6e81936b17ea7f2c304142"
  ],
  "tests/scoped-navigation/WebScopedNavigationHostTest.java": [
    30607,
    "3db6472425f0e07cf0d529c326b5c702ad13f021dc862063f427af0f29e1f368"
  ],
  "tests/typed-callback/RemoteReplyHostTest.java": [
    14703,
    "9f6b0482c1963169226c6bf9a6d7f274843edf0a16d07471efef66274c4ee264"
  ],
  "tests/typed-callback/stubs/android/os/IBinder.java": [
    155,
    "c021316750f0146afb5fd226a58b5856c20ddff0fe9a0c120ac75ab12c4f2faf"
  ],
  "tests/typed-callback/stubs/android/os/Parcel.java": [
    659,
    "ea6f025c2b4a3673f5bac366e5eeb4d3b4c2c288c8f9f8e0c18f204f5f1b418c"
  ],
  "tests/typed-callback/stubs/android/os/ParcelFileDescriptor.java": [
    505,
    "4ae06bb002595c358c30b07e95fe7b0565c4f0936aa85c38dc32f7dd0166db0d"
  ],
  "tests/typed-callback/stubs/org/trillionnium/hepta/webhelper/EvidenceFiles.java": [
    578,
    "214eae8971b69bd0824ae96e47d809297872aa6991c39271e59ee7ac53b21f7a"
  ],
  "tests/typed-callback/stubs/org/trillionnium/hepta/webhelper/InstalledIdentity.java": [
    170,
    "51770eb4a606758ba488ac91d72c1480978b5d93fc6a10dbe45b31ea124b6af1"
  ]
}
# Preserve the original55-input javac argument order.
JAVA_INPUT_ORDER = [
  "src/org/trillionnium/hepta/background/FixedIntentTarget.java",
  "src/org/trillionnium/hepta/background/FixedIntentTools.java",
  "src/org/trillionnium/hepta/local/ActionDecision.java",
  "src/org/trillionnium/hepta/local/AppCatalogueRanker.java",
  "src/org/trillionnium/hepta/local/DecisionGrammar.java",
  "src/org/trillionnium/hepta/local/NotesOwnerIntent.java",
  "src/org/trillionnium/hepta/local/ObservedAppLabels.java",
  "src/org/trillionnium/hepta/local/ObservedImeEnter.java",
  "src/org/trillionnium/hepta/local/ObservedScrollActions.java",
  "src/org/trillionnium/hepta/local/ObservedTargetLabels.java",
  "src/org/trillionnium/hepta/local/TaskAuthorization.java",
  "src/org/trillionnium/hepta/local/web/WebFlightGoal.java",
  "src/org/trillionnium/hepta/local/web/WebShoppingGoal.java",
  "src/org/trillionnium/hepta/webhelper/CaptureReadBudget.java",
  "src/org/trillionnium/hepta/webhelper/DomInstabilityEvidence.java",
  "src/org/trillionnium/hepta/webhelper/Jsons.java",
  "src/org/trillionnium/hepta/webhelper/ObservedLinkPermit.java",
  "src/org/trillionnium/hepta/webhelper/OfficialPageCapture.java",
  "src/org/trillionnium/hepta/webhelper/RemoteReply.java",
  "src/org/trillionnium/hepta/webprotocol/WebDomCanonical.java",
  "src/org/trillionnium/hepta/webprotocol/WebDomStability.java",
  "src/org/trillionnium/hepta/webprotocol/WebEvidenceBinding.java",
  "src/org/trillionnium/hepta/webprotocol/WebEvidenceProtocol.java",
  "src/org/trillionnium/hepta/webprotocol/WebMiActionRegion.java",
  "src/org/trillionnium/hepta/webprotocol/WebObservedNavigation.java",
  "src/org/trillionnium/hepta/webprotocol/WebSitePolicy.java",
  "src/org/trillionnium/hepta/webprotocol/WebStorageEvidence.java",
  "src/org/trillionnium/hepta/webprotocol/WebTaskPurpose.java",
  "tests/capture-retry/CaptureRetryHostTest.java",
  "tests/capture-retry/stubs/android/content/Context.java",
  "tests/capture-retry/stubs/android/content/res/AssetManager.java",
  "tests/capture-retry/stubs/android/graphics/Bitmap.java",
  "tests/capture-retry/stubs/android/graphics/Rect.java",
  "tests/capture-retry/stubs/android/net/Uri.java",
  "tests/capture-retry/stubs/android/net/http/SslError.java",
  "tests/capture-retry/stubs/android/os/Looper.java",
  "tests/capture-retry/stubs/android/os/Process.java",
  "tests/capture-retry/stubs/android/os/SystemClock.java",
  "tests/capture-retry/stubs/android/view/Display.java",
  "tests/capture-retry/stubs/android/view/accessibility/AccessibilityNodeInfo.java",
  "tests/capture-retry/stubs/android/webkit/SslErrorHandler.java",
  "tests/capture-retry/stubs/android/webkit/ValueCallback.java",
  "tests/capture-retry/stubs/android/webkit/WebResourceError.java",
  "tests/capture-retry/stubs/android/webkit/WebResourceRequest.java",
  "tests/capture-retry/stubs/android/webkit/WebSettings.java",
  "tests/capture-retry/stubs/android/webkit/WebView.java",
  "tests/capture-retry/stubs/android/webkit/WebViewClient.java",
  "tests/capture-retry/stubs/org/trillionnium/hepta/webhelper/PageSitePolicy.java",
  "tests/scoped-navigation/WebScopedNavigationHostTest.java",
  "tests/typed-callback/RemoteReplyHostTest.java",
  "tests/typed-callback/stubs/android/os/IBinder.java",
  "tests/typed-callback/stubs/android/os/Parcel.java",
  "tests/typed-callback/stubs/android/os/ParcelFileDescriptor.java",
  "tests/typed-callback/stubs/org/trillionnium/hepta/webhelper/EvidenceFiles.java",
  "tests/typed-callback/stubs/org/trillionnium/hepta/webhelper/InstalledIdentity.java"
]
IDENTITY_FILES = {
    "HelperInstalledApkIdentityHostTest.java": [13958, "e3214559da39d358b585fa481e855d47483ece95404e2ec855bbcd7d4b123502"],
    "actual-apk-stat.txt": [433, "6c1dc85d204e0d806425069fc20ada3a0f5795ee2ffc3b0bf4218f5ed37f8c04"],
}
IDENTITY_BLOCKS = [
  {
    "signature": "private static String fileSha(",
    "bytes": 898,
    "sha256": "1b9fecb34bde6eb8d51bc68c7a5a869adaec6a32daa5553159e0fd4ec42147a3"
  },
  {
    "signature": "private static final class Stamp",
    "bytes": 702,
    "sha256": "79e72ca0079bde616a32b4e40d5960756abede8fe43c5325e3502e98f71eeff0"
  }
]
JSON_SHA256 = "3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
VERSION_TEST = "tests/scoped-navigation/WebScopedNavigationHostTest.java"
OLD_VERSION = b"identity(WebEvidenceProtocol.HELPER_PACKAGE,10123,6)"
CURRENT_VERSION = b"identity(WebEvidenceProtocol.HELPER_PACKAGE,10123,WebEvidenceProtocol.HELPER_VERSION_CODE)"


def need(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                       allow_nan=False) + "\n").encode("utf-8")


def read(path, maximum=4 << 20):
    need(path.is_absolute() and path == path.resolve(), "unlinked absolute input required")
    first = path.stat()
    need(stat.S_ISREG(first.st_mode) and first.st_nlink == 1
         and 0 <= first.st_size <= maximum, "bounded regular input required: " + str(path))
    raw = path.read_bytes()
    last = path.stat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(identity(first) == identity(last) and len(raw) == first.st_size,
         "input changed during read: " + str(path))
    return raw


def put(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    need(read(path, 64 << 20) == raw, "new output differs: " + str(path))


def commands(args, source, classes, identity_source, identity_classes, output):
    cp = str(classes) + os.pathsep + str(args.json_jar)
    return [
        ("focused-javac", [str(args.java_home / "bin/javac"), "--release", "8",
            "-encoding", "UTF-8", "-proc:none", "-cp", str(args.json_jar), "-d", str(classes),
            *[str(source / rel) for rel in JAVA_INPUT_ORDER]]),
        ("scoped-navigation", [str(args.java_home / "bin/java"), "-cp", cp,
            "org.trillionnium.hepta.webhelper.WebScopedNavigationHostTest",
            str(output / "SCOPED-NAVIGATION-RESULT.json")]),
        ("capture-retry", [str(args.java_home / "bin/java"), "-cp", cp,
            "org.trillionnium.hepta.webhelper.CaptureRetryHostTest",
            str(source / "assets/readonly_dom.js"), str(output / "CAPTURE-RETRY-RESULT.json")]),
        ("typed-callback", [str(args.java_home / "bin/java"), "-cp", cp,
            "org.trillionnium.hepta.webhelper.RemoteReplyHostTest"]),
        ("identity-javac", [str(args.java_home / "bin/javac"), "--release", "8",
            "-encoding", "UTF-8", "-proc:none", "-d", str(identity_classes),
            str(identity_source / "HelperInstalledApkIdentityHostTest.java")]),
        ("installed-identity", [str(args.java_home / "bin/java"), "-cp", str(identity_classes),
            "HelperInstalledApkIdentityHostTest", str(identity_source / "actual-apk-stat.txt"),
            str(output / "identity-io"), str(output / "INSTALLED-IDENTITY-RESULT.json")]),
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("helper-source", "retained-helper-tests", "identity-tests",
                 "output", "java-home", "json-jar"):
        parser.add_argument("--" + name, type=pathlib.Path, required=True)
    args = parser.parse_args()
    for name in ("helper_source", "retained_helper_tests", "identity_tests", "java_home", "json_jar"):
        original = getattr(args, name)
        resolved = original.resolve(strict=True)
        setattr(args, name, resolved)
    args.output = args.output.absolute()
    need(args.output.parent == args.output.parent.resolve(), "output parent must be canonical")
    for source_root in (args.helper_source, args.retained_helper_tests, args.identity_tests):
        need(args.output != source_root and source_root not in args.output.parents,
             "fresh output cannot be inside an input source tree")
    args.output.mkdir(parents=True, exist_ok=False)
    output = args.output
    originals = {}
    staged = {}
    staged_files = {}

    def take(path, maximum=4 << 20):
        raw = read(path, maximum)
        if path in originals:
            need(originals[path] == raw, "input changed between reads: " + str(path))
        originals[path] = raw
        return raw

    def stage(path, raw):
        put(path, raw)
        staged_files[path] = raw

    result = {
        "schema": "hepta.helper-retained87-host.v1",
        "all_pass": False,
        "started_epoch": time.time(),
        "phone_operations": 0,
        "android_binder_exercised": False,
        "real_fd_exercised": False,
        "actual_android_apk_rehashed": False,
        "business_verified": False,
        "original_cases_and_assertions_preserved": True,
        "original_compile_flags_and_input_order_preserved": True,
        "fresh_classes": True,
        "runtime_source_admission": "caller frozen complete source/build manifest; full supplied tree recorded here",
        "platform_boundaries": [
            "Original scoped-navigation/capture/typed-reply Android UID/Binder/WebView boundaries are host doubles",
            "Original identity test replays historical APK metadata and hashes synthetic host bytes",
            "No actual Android APK/PM/certificate or physical directory-fsync claim"
        ],
        "steps": [],
    }
    try:
        actual = {str(p.relative_to(args.retained_helper_tests))
                  for p in args.retained_helper_tests.rglob("*") if p.is_file()}
        need(actual == set(RETAINED) and len(actual) == 56, "complete original56 retained membership")
        need(len(JAVA_INPUT_ORDER) == len(set(JAVA_INPUT_ORDER)) == 55
             and set(JAVA_INPUT_ORDER) == {p for p in RETAINED if p.endswith(".java")},
             "exact original55 Java closure")
        actual_identity = {str(p.relative_to(args.identity_tests))
                           for p in args.identity_tests.rglob("*") if p.is_file()}
        need(actual_identity == set(IDENTITY_FILES), "complete original two identity fixtures")
        need(sha(take(args.json_jar)) == JSON_SHA256 and len(originals[args.json_jar]) == 78332,
             "original JSON dependency bytes")
        for tool in ("java", "javac"):
            take(args.java_home / "bin" / tool, 64 << 20)
        full_candidate = []
        for path in sorted(p for p in args.helper_source.rglob("*") if p.is_file()):
            raw = take(path)
            full_candidate.append({"path": str(path.relative_to(args.helper_source)),
                                   "bytes": len(raw), "sha256": sha(raw)})
        need(full_candidate, "nonempty supplied helper source")
        changes = []
        for rel, (length, digest) in sorted(RETAINED.items()):
            old = take(args.retained_helper_tests / rel)
            need(len(old) == length and sha(old) == digest, "original retained file differs: " + rel)
            new = take(args.helper_source / rel) if rel.startswith(("src/", "assets/")) else old
            if rel == VERSION_TEST:
                need(old.count(OLD_VERSION) == 1, "one original synthetic helper6 identity literal")
                new = old.replace(OLD_VERSION, CURRENT_VERSION)
            staged[rel] = new
            if new != old:
                changes.append({"path": rel, "old_sha256": sha(old), "new_sha256": sha(new),
                    "scope": "synthetic fixture version parameter" if rel.startswith("tests/")
                    else "current actual helper production source"})
        test_changes = [x for x in changes if x["path"].startswith("tests/")]
        need([x["path"] for x in test_changes] == [VERSION_TEST], "no original test/assertion changes")
        result["test_fixture_adaptations"] = test_changes
        result["production_replacements"] = [x for x in changes if not x["path"].startswith("tests/")]
        source = output / "source"
        classes = output / "classes"
        classes.mkdir()
        for rel, raw in staged.items():
            stage(source / rel, raw)
        old_test = originals[args.retained_helper_tests / VERSION_TEST]
        patch = "".join(difflib.unified_diff(
            old_test.decode().splitlines(True), staged[VERSION_TEST].decode().splitlines(True),
            fromfile="original/" + VERSION_TEST, tofile="current-version-fixture/" + VERSION_TEST))
        put(output / "SYNTHETIC-VERSION-FIXTURE.patch", patch.encode())
        put(output / "CURRENT-HELPER-SOURCE-INPUTS.json", encoded(full_candidate))
        identity_source = output / "identity-source"
        identity_classes = output / "identity-classes"
        identity_classes.mkdir()
        for rel, (length, digest) in IDENTITY_FILES.items():
            raw = take(args.identity_tests / rel)
            need(len(raw) == length and sha(raw) == digest, "original identity fixture changed: " + rel)
            stage(identity_source / rel, raw)
        runtime_identity = take(args.helper_source / "src/org/trillionnium/hepta/webhelper/InstalledIdentity.java")
        old_identity = originals[args.identity_tests / "HelperInstalledApkIdentityHostTest.java"]
        projections = []
        # These original bounded spans were extracted from the exact production methods.
        # A changed method fails this retained projection rather than silently running old code.
        for expected in IDENTITY_BLOCKS:
            signature = expected["signature"].encode()
            blocks = []
            for blob in (runtime_identity, old_identity):
                need(blob.count(signature) == 1, "unique original identity method")
                at = blob.index(signature)
                block = blob[at:at + expected["bytes"]]
                need(len(block) == expected["bytes"] and sha(block) == expected["sha256"],
                     "current actual identity method no longer equals retained exact projection")
                blocks.append(block)
            need(blocks[0] == blocks[1], "identity projection bytes differ")
            projections.append(dict(expected, current_production_and_original_test_exact=True))
        result["identity_method_projections"] = projections
        env = dict(os.environ)
        removed = []
        for name in ("CLASSPATH", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS",
                     "JDK_JAVAC_OPTIONS", "_JAVA_OPTIONS"):
            if name in env:
                removed.append(name)
                env.pop(name)
        result["removed_environment_option_names"] = removed
        for name, argv in commands(args, source, classes, identity_source, identity_classes, output):
            started = time.monotonic()
            process = subprocess.run(argv, capture_output=True, timeout=120,
                                     stdin=subprocess.DEVNULL, env=env)
            put(output / (name + ".stdout"), process.stdout)
            put(output / (name + ".stderr"), process.stderr)
            result["steps"].append({
                "name": name, "argv": argv, "exit_code": process.returncode,
                "elapsed_s": time.monotonic() - started,
                "stdout_bytes": len(process.stdout), "stderr_bytes": len(process.stderr),
                "stdout_sha256": sha(process.stdout), "stderr_sha256": sha(process.stderr),
            })
            need(process.returncode == 0, name + " failed: " + process.stderr.decode(errors="replace"))
        scope = json.loads(read(output / "SCOPED-NAVIGATION-RESULT.json"))
        capture = json.loads(read(output / "CAPTURE-RETRY-RESULT.json"))
        typed = json.loads(read(output / "typed-callback.stdout"))
        identity = json.loads(read(output / "INSTALLED-IDENTITY-RESULT.json"))
        need(scope["all_pass"] is True and (scope["cases"], scope["assertions"]) == (23, 99),
             "original scoped navigation23/99")
        need(capture["all_pass"] is True and (capture["cases"], capture["assertions"]) == (36, 191),
             "original capture retry36/191")
        need(typed["all_pass"] is True and (typed["case_count"], typed["assertion_count"]) == (18, 246),
             "original typed callback18/246")
        need(identity["all_pass"] is True and (identity["cases"], identity["assertions"]) == (10, 218)
             and identity["phone_actions"] == 0 and identity["android_syscalls_doubled"] is True
             and identity["actual_android_file_access_executed"] is False
             and identity["actual_three_link_apk_rehashed_here"] is False,
             "original identity10/218 and exact host boundary")
        need(all(x["phone_tested"] is False and x["business_verified"] is False
                 for x in (scope, capture, typed)), "host scopes cannot become phone/business")
        result.update(all_pass=True, cases=87, assertions=754,
                      scoped_navigation=scope, capture_retry=capture,
                      typed_callback=typed, installed_identity=identity)
    except Exception as error:
        result["error"] = str(error)
        put(output / "ERROR.txt", traceback.format_exc().encode())
    finally:
        try:
            result["originals_and_current_inputs_unchanged"] = all(
                read(path, 64 << 20) == raw for path, raw in originals.items())
            result["staged_source_unchanged"] = all(
                read(path, 64 << 20) == raw for path, raw in staged_files.items())
        except Exception as error:
            result["originals_and_current_inputs_unchanged"] = False
            result["staged_source_unchanged"] = False
            result["final_input_check_error"] = str(error)
        result["all_pass"] = (result["all_pass"] and result["originals_and_current_inputs_unchanged"]
                              and result["staged_source_unchanged"])
        result["input_files"] = [{"path": str(path), "bytes": len(raw), "sha256": sha(raw)}
                                for path, raw in originals.items()]
        result["finished_epoch"] = time.time()
        raw = encoded(result)
        put(output / "RESULT.json", raw)
        print(json.dumps({"all_pass": result["all_pass"], "error": result.get("error"),
            "cases": result.get("cases"), "assertions": result.get("assertions"),
            "result": str(output / "RESULT.json"), "sha256": sha(raw), "bytes": len(raw)},
            ensure_ascii=False))
    return 0 if result["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
