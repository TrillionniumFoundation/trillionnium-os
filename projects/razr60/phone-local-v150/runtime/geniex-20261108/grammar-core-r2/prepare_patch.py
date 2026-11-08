#!/usr/bin/env python3
"""Generate two reviewable patches from the exact pinned upstream source.

Only a new output directory is written. Does not download, edit the upstream
checkout, invoke an Android compiler, stage a runtime, or access a phone.
"""
from pathlib import Path
import argparse
import difflib
import hashlib
import json

HERE = Path(__file__).resolve().parent
PIN = "ab24abb1f66cb3d8fe624cb8649ec23bd36da41c"
FILES = {
    "core/src/llm/llm_model.cpp": ("0cf276786431f9190b90c599bd57a893caebfae0", "d164374f843ab3918134e1f7f0e6b1e436f212ba2e574dcc1be03ebf074a6eb8"),
    "CMakeLists.txt": ("89e4e256887eac74540b43cce0bfccc63f9a8127", "b33192d8d430913e2c4ae4ef36b37301c3d589da3648224d8cbf976157c5c13a"),
    "core/include/llm/sampler_utils.h": ("f9fdd4d345590e438cecef7fe941ba4db5f07161", "1ef79f1e37ee06b362ff244d0ad0c214bb36673be646bd7c45c896b8606bb470"),
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source-root", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    root = args.source_root.resolve(strict=True)
    original = {}
    for relative, (blob, digest) in FILES.items():
        raw = (root / relative).read_bytes()
        git_blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        require(git_blob == blob and sha(raw) == digest, "fixed source differs: " + relative)
        original[relative] = raw.decode("utf-8")
    replacement = (HERE / "prepare_sampler.inc").read_text()
    sample_replacement = (HERE / "sample_next_token.inc").read_text()
    function_start = "void LLMModel::prepareSampler("
    function_end = "\nvoid LLMModel::resolveKVLayout()"
    llm = original["core/src/llm/llm_model.cpp"]
    require(llm.count(function_start) == 1 and llm.count(function_end) == 1, "method boundary differs")
    begin, end = llm.index(function_start), llm.index(function_end)
    require(replacement.startswith(function_start) and replacement.rstrip().endswith("}"), "replacement method differs")
    patched_llm = llm[:begin] + replacement.rstrip() + "\n" + llm[end:]
    sample_start = "int32_t LLMModel::sampleNextToken("
    sample_end = "\nvoid LLMModel::readLastLogits("
    require(patched_llm.count(sample_start) == 1 and patched_llm.count(sample_end) == 1, "sample method boundary differs")
    sample_begin, sample_finish = patched_llm.index(sample_start), patched_llm.index(sample_end)
    require(sample_replacement.startswith(sample_start), "sample replacement differs")
    patched_llm = patched_llm[:sample_begin] + sample_replacement.rstrip() + "\n" + patched_llm[sample_finish:]

    cmake = original["CMakeLists.txt"]
    block = """set(GENIEXPROC_BUILD_SHARED_LIBS ON CACHE BOOL "" FORCE)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/third-party/geniex-proc third-party/geniex-proc)
"""
    imported = """# Optional core-only build against the exact already-qualified processor ABI.
# The default path remains the upstream source build.
set(GENIEX_PROC_PREBUILT_LIBRARY "" CACHE FILEPATH "Pinned Android libgeniex-proc.so")
set(GENIEX_PROC_PREBUILT_INCLUDE_DIR "" CACHE PATH "Pinned geniex-proc public include directory")
set(GENIEX_PROC_PUBLIC_DEPENDENCY_INCLUDE_DIRS "" CACHE STRING "Pinned transitive public header directories")
option(GENIEX_SKIP_HTP_RUNTIME_COPY "Skip runtime copying for an isolated core-only build" OFF)
if(GENIEX_PROC_PREBUILT_LIBRARY)
    if(NOT ANDROID OR GENIEX_BUILD_VLM OR GENIEX_BUILD_AUDIO OR GENIEX_BUILD_OCR)
        message(FATAL_ERROR "Prebuilt processor mode is limited to the Android core-only target")
    endif()
    if(NOT EXISTS "${GENIEX_PROC_PREBUILT_LIBRARY}" OR
       NOT EXISTS "${GENIEX_PROC_PREBUILT_INCLUDE_DIR}/geniex-proc/sampler.h")
        message(FATAL_ERROR "Pinned processor library/public headers are absent")
    endif()
    add_library(geniex-proc SHARED IMPORTED GLOBAL)
    set_target_properties(geniex-proc PROPERTIES
        IMPORTED_LOCATION "${GENIEX_PROC_PREBUILT_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${GENIEX_PROC_PREBUILT_INCLUDE_DIR};${GENIEX_PROC_PUBLIC_DEPENDENCY_INCLUDE_DIRS}"
        INTERFACE_COMPILE_DEFINITIONS GENIEXPROC_SHARED)
else()
    set(GENIEXPROC_BUILD_SHARED_LIBS ON CACHE BOOL "" FORCE)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/third-party/geniex-proc third-party/geniex-proc)
endif()
"""
    require(cmake.count(block) == 1, "processor dependency block differs")
    patched_cmake = cmake.replace(block, imported)
    condition = "if(DEFINED GENIEX_HTP_DIR)"
    require(patched_cmake.count(condition) == 1, "HTP runtime-copy block differs")
    patched_cmake = patched_cmake.replace(condition, "if(DEFINED GENIEX_HTP_DIR AND NOT GENIEX_SKIP_HTP_RUNTIME_COPY)")
    out = args.output.resolve()
    out.mkdir(parents=False, exist_ok=False)
    patches = []
    for relative, changed, filename in (
        ("core/src/llm/llm_model.cpp", patched_llm, "qairt-core-sampler.patch"),
        ("CMakeLists.txt", patched_cmake, "qairt-core-prebuilt-proc.patch"),
    ):
        diff = "".join(difflib.unified_diff(original[relative].splitlines(keepends=True), changed.splitlines(keepends=True),
                                          fromfile="a/" + relative, tofile="b/" + relative))
        require(diff, "empty patch")
        raw = diff.encode()
        (out / filename).write_bytes(raw)
        patches.append({"file": filename, "bytes": len(raw), "sha256": sha(raw), "target": relative,
                        "upstream_sha256": FILES[relative][1], "patched_source_sha256": sha(changed.encode())})
    manifest = {"schema": "hepta.qairt-core-grammar-patch.v2", "status": "source_candidate_only_no_Android_binary",
                "upstream_repository": "qualcomm/geniex-qairt-plugin", "upstream_commit": PIN,
                "processor_commit_unchanged": "6b68dd0de5b9a84c316cc3babfe9f2477d9c6079",
                "processor_binary_sha256_unchanged": "7a1a80346ddd7d1e775a00435b87303d7794c08d3c75251bcfc5d911fa82227d",
                "replacement_functions_sha256": {"prepare_sampler.inc": sha(replacement.encode()), "sample_next_token.inc": sha(sample_replacement.encode())}, "patches": patches,
                "source_checks": [{"path": path, "git_blob_sha": pair[0], "sha256": pair[1]} for path, pair in FILES.items()],
                "phone_runtime_modified": False, "Android_compiler_invoked": False,
                "model_weights_QNN_proc_worker_changed": False}
    (out / "PATCH-MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
