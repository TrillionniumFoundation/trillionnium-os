#!/usr/bin/env python3
"""Preserve installed Main56, Helper6 and the actual Recovery56 terminal while installing signed Main57.

The earlier failed Flight56 and its complete Helper50 inventory remain separate originals.
The current Notes recovery has one actual request and a normally closed native parent.
Root alone executes one install -r and ordinary MAIN; no Start, task, site or model.
No clear, uninstall, replay, unknown-outcome retry or rollback. Main57 and the new owner remain late-bound.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import time

BASE = Path("/home/alex/hepta-local-007f-20261111")
PKG = "org.trillionnium.hepta.local"
HELPER_PACKAGE = "org.trillionnium.hepta.webhelper"
HELPER_UID = 10484
HISTORICAL_APK_SHA = "0729f54704a058049e12041c7f901b1b6650924500663cf9952a03d6a33a8b8a"
HISTORICAL_BUILD_SHA = "eadc9dbb63b411015571a488377be6a8704c9f78415169a5164c8f13571f0f72"
HISTORICAL_BUILD_PATH = BASE / "v54-main-host-r4/assembly-r1/RESULT.json"
HISTORICAL_BUILD_BYTES = 15659
HISTORICAL_SOURCE = "42d3a0f447807659c0f78c8273edee01dd1b734f"
HISTORICAL_INVENTORY = "8675c0c438cdf10f599c23a3a6305a5678fd59270f09b4f73a43f7a67bf2237d"
HISTORICAL_INSTALLER = BASE / "install_v54_idle_r1.py"
HISTORICAL_INSTALLER_SHA = "5db1d36dc7faabe5fd8a9dad1f1dedd23cf2dc527709d564436c5fbb1a96f9d7"
HISTORICAL_INSTALLER_BYTES = 112460
HISTORICAL_LIBRARY_PINS = {"libMNN.so": "5019009bfc9b209afeb89d23db0f1c52985cc1111e3364a448f7c7ed7a4c457d", "libc++_shared.so": "77a34d3f03b17709f3f6473f37cb7795314e51fa3e5e652b5c37d53cfd05c754", "libgeniex.so": "99e2dbc8d95b08f8bb31b61b3c84219f4b70d6effeb38d224d54eeb621f28a56", "libgeniex_plugin_llama_cpp.so": "cc186649cc0dab10240395f89d14d007e62b3bc78283060027d37ee80a21604a", "libggml-base.so": "bdd15d0ea024fd34a64d2eba32de79f615d35b79253e25b27b1440944fa6df40", "libggml-cpu.so": "b603d578bb3beb0c3727be748f327c002619827df701bf0b894632272670943b", "libggml-hexagon.so": "67b886eb9bcdd298268a8463d74f07da4213024fe7ed89911c2e76c9e0d1491f", "libggml-htp-v79.so": "110d9e6ff7cff02fa73b0a3c03d8259222758934bdbcae5c819dae6729f362d5", "libggml-opencl.so": "e395cf83e695aa9d21dd90a89460f936742c7c8c706cfbbdfa647dd316dd0875", "libggml.so": "5dff1d15e528d1accb1704a1049a6556784cbfc32131fb64cef5c8847c171149", "libhepta_local_runner.so": "eeded3063bcbd28ce560ce11295391495e42a6b3b7a8a3e4abe6e5478a103ab5", "libhepta_mobimind_runner.so": "b3899c03f88070e0042132dc9f17d81437d2b018c3406598f97939fc52ff9020", "libhepta_ui_venus_runner.so": "5fa2dcae05fb649157d96481c5890c157301c76dab3522fcabcbe01b9b0d8551", "libllama-common.so": "8b05589a739339dd38ad524e9733d89650ef40b0a83fe3a95ff83716c98c6122", "libllama.so": "4bb7bd0f4fe0bd24ac32a80f920838fd2f525430ad58c5d5742cc745f7d0b835", "libmtmd.so": "ccf32e264cdccc6378d5e4e005f4aedae39eb3e9a198550c5f7f3a4583bcaa4d", "libomp.so": "b0b507bb9e89360304272ba335d5fb2f6661f88842c2b3c749474cb7b8acda76"}
V55_APK_SHA = "ea485e6d28544d75a9010e441aae8df348d1b64884f9ff7a50cb909a3f8ea45e"
V55_BUILD_SHA = "3caa0d8ae5252352fb606db1d851fd9e960423c0f7374a76c58b89c688556535"
V55_BUILD_BYTES = 31662
V55_SOURCE = "dd2cd48054c2c6f0b2597b7d9be05edd8ce6b34e"
V55_INVENTORY = "65bf7934d82692f45c10aedb947613043453b30bc7d55c4dc8b7e44e4ca0bed1"
V55_BUILD_SCHEMA = "hepta.isolated-v55-assembly.v1"
V55_APK_BYTES = 21014354
V55_BUILD_PATH = "/home/alex/hepta-local-007f-20261111/v55-main-sign-r1/RESULT.json"
V55_APK_PATH = "/home/alex/hepta-local-007f-20261111/v55-main-sign-r1/out/hepta-local-0.55.0.apk"
V55_COUNTS = json.loads("{\"source_file_count\":594,\"actual_compiler_source_inputs\":216,\"host_check_records\":101,\"host_input_count\":418,\"packaged_library_count\":17}")
V55_LIBRARY_PINS = json.loads("{\"libMNN.so\":\"5019009bfc9b209afeb89d23db0f1c52985cc1111e3364a448f7c7ed7a4c457d\",\"libc++_shared.so\":\"77a34d3f03b17709f3f6473f37cb7795314e51fa3e5e652b5c37d53cfd05c754\",\"libgeniex.so\":\"99e2dbc8d95b08f8bb31b61b3c84219f4b70d6effeb38d224d54eeb621f28a56\",\"libgeniex_plugin_llama_cpp.so\":\"cc186649cc0dab10240395f89d14d007e62b3bc78283060027d37ee80a21604a\",\"libggml-base.so\":\"bdd15d0ea024fd34a64d2eba32de79f615d35b79253e25b27b1440944fa6df40\",\"libggml-cpu.so\":\"b603d578bb3beb0c3727be748f327c002619827df701bf0b894632272670943b\",\"libggml-hexagon.so\":\"67b886eb9bcdd298268a8463d74f07da4213024fe7ed89911c2e76c9e0d1491f\",\"libggml-htp-v79.so\":\"110d9e6ff7cff02fa73b0a3c03d8259222758934bdbcae5c819dae6729f362d5\",\"libggml-opencl.so\":\"e395cf83e695aa9d21dd90a89460f936742c7c8c706cfbbdfa647dd316dd0875\",\"libggml.so\":\"5dff1d15e528d1accb1704a1049a6556784cbfc32131fb64cef5c8847c171149\",\"libhepta_local_runner.so\":\"eeded3063bcbd28ce560ce11295391495e42a6b3b7a8a3e4abe6e5478a103ab5\",\"libhepta_mobimind_runner.so\":\"b3899c03f88070e0042132dc9f17d81437d2b018c3406598f97939fc52ff9020\",\"libhepta_ui_venus_runner.so\":\"5fa2dcae05fb649157d96481c5890c157301c76dab3522fcabcbe01b9b0d8551\",\"libllama-common.so\":\"8b05589a739339dd38ad524e9733d89650ef40b0a83fe3a95ff83716c98c6122\",\"libllama.so\":\"4bb7bd0f4fe0bd24ac32a80f920838fd2f525430ad58c5d5742cc745f7d0b835\",\"libmtmd.so\":\"ccf32e264cdccc6378d5e4e005f4aedae39eb3e9a198550c5f7f3a4583bcaa4d\",\"libomp.so\":\"b0b507bb9e89360304272ba335d5fb2f6661f88842c2b3c749474cb7b8acda76\"}")
V55_NATIVE_FIELDS = json.loads("{\"worker_sha256\":\"eeded3063bcbd28ce560ce11295391495e42a6b3b7a8a3e4abe6e5478a103ab5\",\"native_worker_binding\":{\"schema\":\"hepta.preserved-local-worker-binding.v1\",\"name\":\"libhepta_local_runner.so\",\"sha256\":\"eeded3063bcbd28ce560ce11295391495e42a6b3b7a8a3e4abe6e5478a103ab5\",\"previous_sha256\":\"eeded3063bcbd28ce560ce11295391495e42a6b3b7a8a3e4abe6e5478a103ab5\",\"native_worker_updated\":false,\"native_recompiled_here\":false,\"cancellation_sdk_phone_verified\":false,\"source_commit\":\"dd2cd48054c2c6f0b2597b7d9be05edd8ce6b34e\",\"actual_compiler_receipt_sha256\":\"226c807ffed4e7e0a9f62c36d6046303f709eba7311f321e24acdad1a696d4ba\",\"actual_compiler_receipt_kind\":\"pocket4_java_native_reuse\",\"original_native_compiler_receipt_sha256\":\"51265398de2dcc4ccefb5aa0e24ea91770d8c9f3b54248f3d88068e04a4436cc\",\"actual_mac_stage_sha256\":\"a037b49f05ea48caccb2902b95bbb2314a5f767e230138dd14ae3a16851ee4b2\",\"generated_worker_sha256\":\"77b914eae46ea000d3c955628c35f6e96a715a4a14da3eb075923d2e6024bbb0\",\"upstream_worker_sha256\":\"07cd434bea9d1214acef499a69ed204ecef879a6ac05c82f24d062160e2efb3e\"},\"unchanged_native_library_count\":17,\"unchanged_native_library_pins\":{\"libMNN.so\":\"5019009bfc9b209afeb89d23db0f1c52985cc1111e3364a448f7c7ed7a4c457d\",\"libc++_shared.so\":\"77a34d3f03b17709f3f6473f37cb7795314e51fa3e5e652b5c37d53cfd05c754\",\"libgeniex.so\":\"99e2dbc8d95b08f8bb31b61b3c84219f4b70d6effeb38d224d54eeb621f28a56\",\"libgeniex_plugin_llama_cpp.so\":\"cc186649cc0dab10240395f89d14d007e62b3bc78283060027d37ee80a21604a\",\"libggml-base.so\":\"bdd15d0ea024fd34a64d2eba32de79f615d35b79253e25b27b1440944fa6df40\",\"libggml-cpu.so\":\"b603d578bb3beb0c3727be748f327c002619827df701bf0b894632272670943b\",\"libggml-hexagon.so\":\"67b886eb9bcdd298268a8463d74f07da4213024fe7ed89911c2e76c9e0d1491f\",\"libggml-htp-v79.so\":\"110d9e6ff7cff02fa73b0a3c03d8259222758934bdbcae5c819dae6729f362d5\",\"libggml-opencl.so\":\"e395cf83e695aa9d21dd90a89460f936742c7c8c706cfbbdfa647dd316dd0875\",\"libggml.so\":\"5dff1d15e528d1accb1704a1049a6556784cbfc32131fb64cef5c8847c171149\",\"libhepta_local_runner.so\":\"eeded3063bcbd28ce560ce11295391495e42a6b3b7a8a3e4abe6e5478a103ab5\",\"libhepta_mobimind_runner.so\":\"b3899c03f88070e0042132dc9f17d81437d2b018c3406598f97939fc52ff9020\",\"libhepta_ui_venus_runner.so\":\"5fa2dcae05fb649157d96481c5890c157301c76dab3522fcabcbe01b9b0d8551\",\"libllama-common.so\":\"8b05589a739339dd38ad524e9733d89650ef40b0a83fe3a95ff83716c98c6122\",\"libllama.so\":\"4bb7bd0f4fe0bd24ac32a80f920838fd2f525430ad58c5d5742cc745f7d0b835\",\"libmtmd.so\":\"ccf32e264cdccc6378d5e4e005f4aedae39eb3e9a198550c5f7f3a4583bcaa4d\",\"libomp.so\":\"b0b507bb9e89360304272ba335d5fb2f6661f88842c2b3c749474cb7b8acda76\"},\"native_libraries_identical_to_formal_v54\":true,\"native_libraries_identical_to_formal_v53\":true,\"native_recompiled_here\":false,\"ndk_or_clang_executed_here\":false,\"native_payloads_reused_from_signed54\":true,\"native_baseline_signed_receipt_sha256\":\"eadc9dbb63b411015571a488377be6a8704c9f78415169a5164c8f13571f0f72\",\"historical_native_static_receipt_sha256\":\"23a4d98257b29f9c2a06d87823c3b9379831d6d88563b63c0768980aee1e85d6\",\"cancellation_sdk_phone_verified\":false}")
V55_VERSION_NAME = "0.55.0-scoped-official-web"
V55_PERMISSIONS = ["org.trillionnium.hepta.webhelper.permission.BIND_EVIDENCE"]
V56_APK_SHA = "067ab5a286b100404fa2b00e341964cd70f005907988dc11eb486c9a4b3bab62"
V56_BUILD_SHA = "e27e74e94b0668c1c07b04863c9aaabf1b3235f9ff2d0d0d8bd9a346e46b2c6b"
V56_BUILD_BYTES = 32758
V56_SOURCE = "9f4168616546233033edd4b254b4236ae987ea7e"
V56_INVENTORY = "ca24673843908c7f9343c949af64b8393e69ce53605128782036ae9ce9d1f46e"
V56_BUILD_SCHEMA = "hepta.isolated-v56-assembly.v1"
V56_APK_BYTES = 21030740
V56_BUILD_PATH = "/home/alex/hepta-local-007f-20261111/v56-main-sign-r1/RESULT.json"
V56_APK_PATH = "/home/alex/hepta-local-007f-20261111/v56-main-sign-r1/out/hepta-local-0.56.0.apk"
V56_COUNTS = json.loads("{\"source_file_count\":595,\"actual_compiler_source_inputs\":217,\"host_check_records\":101,\"host_input_count\":419,\"packaged_library_count\":17}")
V56_LIBRARY_PINS = json.loads("{\"libMNN.so\":\"5019009bfc9b209afeb89d23db0f1c52985cc1111e3364a448f7c7ed7a4c457d\",\"libc++_shared.so\":\"77a34d3f03b17709f3f6473f37cb7795314e51fa3e5e652b5c37d53cfd05c754\",\"libgeniex.so\":\"99e2dbc8d95b08f8bb31b61b3c84219f4b70d6effeb38d224d54eeb621f28a56\",\"libgeniex_plugin_llama_cpp.so\":\"cc186649cc0dab10240395f89d14d007e62b3bc78283060027d37ee80a21604a\",\"libggml-base.so\":\"bdd15d0ea024fd34a64d2eba32de79f615d35b79253e25b27b1440944fa6df40\",\"libggml-cpu.so\":\"b603d578bb3beb0c3727be748f327c002619827df701bf0b894632272670943b\",\"libggml-hexagon.so\":\"67b886eb9bcdd298268a8463d74f07da4213024fe7ed89911c2e76c9e0d1491f\",\"libggml-htp-v79.so\":\"110d9e6ff7cff02fa73b0a3c03d8259222758934bdbcae5c819dae6729f362d5\",\"libggml-opencl.so\":\"e395cf83e695aa9d21dd90a89460f936742c7c8c706cfbbdfa647dd316dd0875\",\"libggml.so\":\"5dff1d15e528d1accb1704a1049a6556784cbfc32131fb64cef5c8847c171149\",\"libhepta_local_runner.so\":\"eeded3063bcbd28ce560ce11295391495e42a6b3b7a8a3e4abe6e5478a103ab5\",\"libhepta_mobimind_runner.so\":\"b3899c03f88070e0042132dc9f17d81437d2b018c3406598f97939fc52ff9020\",\"libhepta_ui_venus_runner.so\":\"5fa2dcae05fb649157d96481c5890c157301c76dab3522fcabcbe01b9b0d8551\",\"libllama-common.so\":\"8b05589a739339dd38ad524e9733d89650ef40b0a83fe3a95ff83716c98c6122\",\"libllama.so\":\"4bb7bd0f4fe0bd24ac32a80f920838fd2f525430ad58c5d5742cc745f7d0b835\",\"libmtmd.so\":\"ccf32e264cdccc6378d5e4e005f4aedae39eb3e9a198550c5f7f3a4583bcaa4d\",\"libomp.so\":\"b0b507bb9e89360304272ba335d5fb2f6661f88842c2b3c749474cb7b8acda76\"}")
V56_NATIVE_FIELDS = json.loads("{\"worker_sha256\":\"eeded3063bcbd28ce560ce11295391495e42a6b3b7a8a3e4abe6e5478a103ab5\",\"native_worker_binding\":{\"schema\":\"hepta.preserved-local-worker-binding.v1\",\"name\":\"libhepta_local_runner.so\",\"sha256\":\"eeded3063bcbd28ce560ce11295391495e42a6b3b7a8a3e4abe6e5478a103ab5\",\"previous_sha256\":\"eeded3063bcbd28ce560ce11295391495e42a6b3b7a8a3e4abe6e5478a103ab5\",\"native_worker_updated\":false,\"native_recompiled_here\":false,\"cancellation_sdk_phone_verified\":false,\"source_commit\":\"9f4168616546233033edd4b254b4236ae987ea7e\",\"actual_compiler_receipt_sha256\":\"2c8626102e21841327cd22692021238fed124b1ec7fd580d536dea353725767b\",\"actual_compiler_receipt_kind\":\"pocket4_java_native_reuse\",\"original_native_compiler_receipt_sha256\":\"51265398de2dcc4ccefb5aa0e24ea91770d8c9f3b54248f3d88068e04a4436cc\",\"actual_mac_stage_sha256\":\"a037b49f05ea48caccb2902b95bbb2314a5f767e230138dd14ae3a16851ee4b2\",\"generated_worker_sha256\":\"77b914eae46ea000d3c955628c35f6e96a715a4a14da3eb075923d2e6024bbb0\",\"upstream_worker_sha256\":\"07cd434bea9d1214acef499a69ed204ecef879a6ac05c82f24d062160e2efb3e\"},\"unchanged_native_library_count\":17,\"unchanged_native_library_pins\":{\"libMNN.so\":\"5019009bfc9b209afeb89d23db0f1c52985cc1111e3364a448f7c7ed7a4c457d\",\"libc++_shared.so\":\"77a34d3f03b17709f3f6473f37cb7795314e51fa3e5e652b5c37d53cfd05c754\",\"libgeniex.so\":\"99e2dbc8d95b08f8bb31b61b3c84219f4b70d6effeb38d224d54eeb621f28a56\",\"libgeniex_plugin_llama_cpp.so\":\"cc186649cc0dab10240395f89d14d007e62b3bc78283060027d37ee80a21604a\",\"libggml-base.so\":\"bdd15d0ea024fd34a64d2eba32de79f615d35b79253e25b27b1440944fa6df40\",\"libggml-cpu.so\":\"b603d578bb3beb0c3727be748f327c002619827df701bf0b894632272670943b\",\"libggml-hexagon.so\":\"67b886eb9bcdd298268a8463d74f07da4213024fe7ed89911c2e76c9e0d1491f\",\"libggml-htp-v79.so\":\"110d9e6ff7cff02fa73b0a3c03d8259222758934bdbcae5c819dae6729f362d5\",\"libggml-opencl.so\":\"e395cf83e695aa9d21dd90a89460f936742c7c8c706cfbbdfa647dd316dd0875\",\"libggml.so\":\"5dff1d15e528d1accb1704a1049a6556784cbfc32131fb64cef5c8847c171149\",\"libhepta_local_runner.so\":\"eeded3063bcbd28ce560ce11295391495e42a6b3b7a8a3e4abe6e5478a103ab5\",\"libhepta_mobimind_runner.so\":\"b3899c03f88070e0042132dc9f17d81437d2b018c3406598f97939fc52ff9020\",\"libhepta_ui_venus_runner.so\":\"5fa2dcae05fb649157d96481c5890c157301c76dab3522fcabcbe01b9b0d8551\",\"libllama-common.so\":\"8b05589a739339dd38ad524e9733d89650ef40b0a83fe3a95ff83716c98c6122\",\"libllama.so\":\"4bb7bd0f4fe0bd24ac32a80f920838fd2f525430ad58c5d5742cc745f7d0b835\",\"libmtmd.so\":\"ccf32e264cdccc6378d5e4e005f4aedae39eb3e9a198550c5f7f3a4583bcaa4d\",\"libomp.so\":\"b0b507bb9e89360304272ba335d5fb2f6661f88842c2b3c749474cb7b8acda76\"},\"native_libraries_identical_to_formal_v54\":true,\"native_libraries_identical_to_formal_v53\":true,\"native_recompiled_here\":false,\"ndk_or_clang_executed_here\":false,\"native_payloads_reused_from_signed54\":true,\"native_baseline_signed_receipt_sha256\":\"eadc9dbb63b411015571a488377be6a8704c9f78415169a5164c8f13571f0f72\",\"historical_native_static_receipt_sha256\":\"23a4d98257b29f9c2a06d87823c3b9379831d6d88563b63c0768980aee1e85d6\",\"cancellation_sdk_phone_verified\":false}")
V56_VERSION_NAME = "0.56.0-flight-stability"
V56_PERMISSIONS = ["org.trillionnium.hepta.webhelper.permission.BIND_EVIDENCE"]
V57_APK_SHA = "c1e126031ff8728a3335a5ef1e6d546b3b089ca03ee73a8b3671b67b7e124ad4"
V57_BUILD_SHA = "9deb86d5ba6b066bf250a432559bdc1fcee1138596af3f40133943c6259dd60c"
V57_BUILD_BYTES = 35104
V57_SOURCE = "313685edc580a750aea6301d8ff3cfd617d6fab6"
V57_INVENTORY = "22d32f2de9ecd5690e1dfe7de8fa682b3a0469584ade1ec83ac69bf6558d10b6"
V57_BUILD_SCHEMA = "hepta.isolated-v57-assembly.v1"
V57_APK_BYTES = 21038933
V57_BUILD_PATH = "/home/alex/hepta-local-007f-20261111/v57-main-sign-r1/RESULT.json"
V57_APK_PATH = "/home/alex/hepta-local-007f-20261111/v57-main-sign-r1/out/hepta-local-0.57.0.apk"
V57_COUNTS = json.loads("{\"source_file_count\":595,\"actual_compiler_source_inputs\":217,\"host_check_records\":101,\"host_input_count\":419,\"packaged_library_count\":17}")
V57_LIBRARY_PINS = json.loads("{\n    \"libMNN.so\": \"5019009bfc9b209afeb89d23db0f1c52985cc1111e3364a448f7c7ed7a4c457d\",\n    \"libc++_shared.so\": \"77a34d3f03b17709f3f6473f37cb7795314e51fa3e5e652b5c37d53cfd05c754\",\n    \"libgeniex.so\": \"99e2dbc8d95b08f8bb31b61b3c84219f4b70d6effeb38d224d54eeb621f28a56\",\n    \"libgeniex_plugin_llama_cpp.so\": \"cc186649cc0dab10240395f89d14d007e62b3bc78283060027d37ee80a21604a\",\n    \"libggml-base.so\": \"bdd15d0ea024fd34a64d2eba32de79f615d35b79253e25b27b1440944fa6df40\",\n    \"libggml-cpu.so\": \"b603d578bb3beb0c3727be748f327c002619827df701bf0b894632272670943b\",\n    \"libggml-hexagon.so\": \"67b886eb9bcdd298268a8463d74f07da4213024fe7ed89911c2e76c9e0d1491f\",\n    \"libggml-htp-v79.so\": \"110d9e6ff7cff02fa73b0a3c03d8259222758934bdbcae5c819dae6729f362d5\",\n    \"libggml-opencl.so\": \"e395cf83e695aa9d21dd90a89460f936742c7c8c706cfbbdfa647dd316dd0875\",\n    \"libggml.so\": \"5dff1d15e528d1accb1704a1049a6556784cbfc32131fb64cef5c8847c171149\",\n    \"libhepta_local_runner.so\": \"eeded3063bcbd28ce560ce11295391495e42a6b3b7a8a3e4abe6e5478a103ab5\",\n    \"libhepta_mobimind_runner.so\": \"b3899c03f88070e0042132dc9f17d81437d2b018c3406598f97939fc52ff9020\",\n    \"libhepta_ui_venus_runner.so\": \"5fa2dcae05fb649157d96481c5890c157301c76dab3522fcabcbe01b9b0d8551\",\n    \"libllama-common.so\": \"8b05589a739339dd38ad524e9733d89650ef40b0a83fe3a95ff83716c98c6122\",\n    \"libllama.so\": \"4bb7bd0f4fe0bd24ac32a80f920838fd2f525430ad58c5d5742cc745f7d0b835\",\n    \"libmtmd.so\": \"ccf32e264cdccc6378d5e4e005f4aedae39eb3e9a198550c5f7f3a4583bcaa4d\",\n    \"libomp.so\": \"b0b507bb9e89360304272ba335d5fb2f6661f88842c2b3c749474cb7b8acda76\"\n  }")
V57_NATIVE_FIELDS = json.loads("{\"worker_sha256\":\"eeded3063bcbd28ce560ce11295391495e42a6b3b7a8a3e4abe6e5478a103ab5\",\"native_worker_binding\":{\n    \"schema\": \"hepta.preserved-local-worker-binding.v1\",\n    \"name\": \"libhepta_local_runner.so\",\n    \"sha256\": \"eeded3063bcbd28ce560ce11295391495e42a6b3b7a8a3e4abe6e5478a103ab5\",\n    \"previous_sha256\": \"eeded3063bcbd28ce560ce11295391495e42a6b3b7a8a3e4abe6e5478a103ab5\",\n    \"native_worker_updated\": false,\n    \"native_recompiled_here\": false,\n    \"cancellation_sdk_phone_verified\": false,\n    \"source_commit\": \"313685edc580a750aea6301d8ff3cfd617d6fab6\",\n    \"actual_compiler_receipt_sha256\": \"d448fcd425b8c11b4a134999cf1f7d5ed15e94ebde875b00962d721cb877e7d7\",\n    \"actual_compiler_receipt_kind\": \"pocket4_java_native_reuse\",\n    \"original_native_compiler_receipt_sha256\": \"51265398de2dcc4ccefb5aa0e24ea91770d8c9f3b54248f3d88068e04a4436cc\",\n    \"actual_mac_stage_sha256\": \"a037b49f05ea48caccb2902b95bbb2314a5f767e230138dd14ae3a16851ee4b2\",\n    \"generated_worker_sha256\": \"77b914eae46ea000d3c955628c35f6e96a715a4a14da3eb075923d2e6024bbb0\",\n    \"upstream_worker_sha256\": \"07cd434bea9d1214acef499a69ed204ecef879a6ac05c82f24d062160e2efb3e\"\n  },\"unchanged_native_library_count\":17,\"unchanged_native_library_pins\":{\n    \"libMNN.so\": \"5019009bfc9b209afeb89d23db0f1c52985cc1111e3364a448f7c7ed7a4c457d\",\n    \"libc++_shared.so\": \"77a34d3f03b17709f3f6473f37cb7795314e51fa3e5e652b5c37d53cfd05c754\",\n    \"libgeniex.so\": \"99e2dbc8d95b08f8bb31b61b3c84219f4b70d6effeb38d224d54eeb621f28a56\",\n    \"libgeniex_plugin_llama_cpp.so\": \"cc186649cc0dab10240395f89d14d007e62b3bc78283060027d37ee80a21604a\",\n    \"libggml-base.so\": \"bdd15d0ea024fd34a64d2eba32de79f615d35b79253e25b27b1440944fa6df40\",\n    \"libggml-cpu.so\": \"b603d578bb3beb0c3727be748f327c002619827df701bf0b894632272670943b\",\n    \"libggml-hexagon.so\": \"67b886eb9bcdd298268a8463d74f07da4213024fe7ed89911c2e76c9e0d1491f\",\n    \"libggml-htp-v79.so\": \"110d9e6ff7cff02fa73b0a3c03d8259222758934bdbcae5c819dae6729f362d5\",\n    \"libggml-opencl.so\": \"e395cf83e695aa9d21dd90a89460f936742c7c8c706cfbbdfa647dd316dd0875\",\n    \"libggml.so\": \"5dff1d15e528d1accb1704a1049a6556784cbfc32131fb64cef5c8847c171149\",\n    \"libhepta_local_runner.so\": \"eeded3063bcbd28ce560ce11295391495e42a6b3b7a8a3e4abe6e5478a103ab5\",\n    \"libhepta_mobimind_runner.so\": \"b3899c03f88070e0042132dc9f17d81437d2b018c3406598f97939fc52ff9020\",\n    \"libhepta_ui_venus_runner.so\": \"5fa2dcae05fb649157d96481c5890c157301c76dab3522fcabcbe01b9b0d8551\",\n    \"libllama-common.so\": \"8b05589a739339dd38ad524e9733d89650ef40b0a83fe3a95ff83716c98c6122\",\n    \"libllama.so\": \"4bb7bd0f4fe0bd24ac32a80f920838fd2f525430ad58c5d5742cc745f7d0b835\",\n    \"libmtmd.so\": \"ccf32e264cdccc6378d5e4e005f4aedae39eb3e9a198550c5f7f3a4583bcaa4d\",\n    \"libomp.so\": \"b0b507bb9e89360304272ba335d5fb2f6661f88842c2b3c749474cb7b8acda76\"\n  },\"native_libraries_identical_to_formal_v54\":true,\"native_libraries_identical_to_formal_v53\":true,\"native_recompiled_here\":false,\"ndk_or_clang_executed_here\":false,\"native_payloads_reused_from_signed54\":true,\"native_baseline_signed_receipt_sha256\":\"eadc9dbb63b411015571a488377be6a8704c9f78415169a5164c8f13571f0f72\",\"historical_native_static_receipt_sha256\":\"23a4d98257b29f9c2a06d87823c3b9379831d6d88563b63c0768980aee1e85d6\",\"cancellation_sdk_phone_verified\":false}")
V57_VERSION_NAME = "0.57.0-flight-observation-stability"
V57_PERMISSIONS = ["org.trillionnium.hepta.webhelper.permission.BIND_EVIDENCE"]
MAIN55_INSTALL_SOURCE = {"path":"/home/alex/hepta-local-007f-20261111/install_v55_idle_r1.py","bytes":144014,"sha256":"52c4a4bea94e63b39171d5d3fc5cc5197985dd58e756df3dec439756df05eceb"}
MAIN55_INSTALL_RESULT = {"path":"/home/alex/hepta-local-007f-20261111/phone-install-v55-r1/RESULT.json","bytes":29456,"sha256":"5ef0b5523a84d6e5e17a3527ea5bbe8f7b8df01ee11102d54b27019784b1555d"}
WEB55_SUPPORT = {"path":"/home/alex/hepta-local-007f-20261111/background-web-adapters-v55-r1/web_entry_support.py","bytes":70091,"sha256":"e5bbc07cd151bfb10c8b331706ef7158fd0a73b08d457f5c13f2c33ff2d90d21"}
MAIN55_SAVED_PREFS = {"path":"/home/alex/hepta-local-007f-20261111/phone-install-v55-r1/before-background-ui-choice.xml","bytes":653,"sha256":"c9364dde8c0b52e7890835d720967987f708e972b397fcc3f76d9d76a667137f"}
OWNER = json.loads("{\"root\":\"/home/alex/hepta-local-007f-20261111/owner-24\",\"pid\":3386576,\"start_ticks\":\"31571391\",\"boot_id\":\"97d9600f-e081-465c-9e6e-62651e09806b\"}")
HELPER6_UPGRADE_SOURCE = {"path":"/home/alex/hepta-local-007f-20261111/install_helper6_idle_r1.py","bytes":85795,"sha256":"5c046432394987dce23a05059255d06d656fc366f81834a074f215fe9cd72459"}
HELPER6_INSTALL_RESULT = {"path":"/home/alex/hepta-local-007f-20261111/v55-web-helper-code6-reconcile-r1/RESULT.json","bytes":71263,"sha256":"463d04f9af87bce27c55fc4ea46aea4f1f6a547928d5a5873ecc60a3021aa901"}
HELPER6_INSTALL_EXPECTED = json.loads("{\"schema\":\"hepta.helper6.postinstall-reconciliation.v1\",\"revision\":\"binding-identity-excludes-raw-dump-digest-r1\",\"current_terminal_reference\":{\n    \"identity\": {\n      \"package\": \"org.trillionnium.hepta.webhelper\",\n      \"uid\": 10484,\n      \"apks\": [\n        {\n          \"path\": \"/data/app/~~7tm-0viTiSPtMXQrKQNE5A==/org.trillionnium.hepta.webhelper-FzFUV5CCtZ60uGZ1qVOzWg==/base.apk\",\n          \"sha256\": \"b5e56ce0c2967489b55150c157f8289fdd82ad5b89caacc8b106013a7caeaf4f\"\n        }\n      ]\n    },\n    \"diagnostics\": {\n      \"diagnostic-020c1d13a67d132eed6874ba43cf0d6f35cd473c095e94f890ac6bc2e6b2667f.json\": {\n        \"bytes\": 30993,\n        \"sha256\": \"386f86ef76923ce994574893bc05eec906f3ef839f32d8a77a68092e0115d986\",\n        \"uid\": 10484\n      },\n      \"diagnostic-0e8377e803ac9a467c4a5cb52e5937a15a6a93b43f7934bcaebeedba84b689fc.json\": {\n        \"bytes\": 308739,\n        \"sha256\": \"96aecf073ee65951c988a5710fea394713e64af161f0513e36ee2d539991ebc3\",\n        \"uid\": 10484\n      },\n      \"diagnostic-200d1eb4031744b38d899525241af8f89643659ed769590d5cf4614cc0f376c5.json\": {\n        \"bytes\": 305357,\n        \"sha256\": \"ffe2b5a4cf79e12098abafdc63a006583f9eaddb7f786671bcf1d03bc03e4f83\",\n        \"uid\": 10484\n      },\n      \"diagnostic-2185104639ec2e909a3eb0241b33d7f2714925010d63223c7e6509f4ec8c660b.json\": {\n        \"bytes\": 305381,\n        \"sha256\": \"4d41342931181e4a208439b0dab4766d25d9d0b2e0bd08d5a24c420cae99f969\",\n        \"uid\": 10484\n      },\n      \"diagnostic-260f603251c34639addc7c70fea84f3bcf676e12d373bdaa69f43d6c9fbe3f46.json\": {\n        \"bytes\": 305386,\n        \"sha256\": \"f716aaac6fd44a1015a1f6f1d61b4a0fb2efdda433b3fddcce684840fe103ea9\",\n        \"uid\": 10484\n      },\n      \"diagnostic-292f3f81694870ce87b987a04046ccb48e0b3cd6b11813b24f014a5f6a5cccea.json\": {\n        \"bytes\": 308752,\n        \"sha256\": \"b5d351b711eac0b70c7458bc0c1f3f52c4e5d4f9e8e0a3b35a9e2529585adf22\",\n        \"uid\": 10484\n      },\n      \"diagnostic-342e51e1e6c5fac683309de2758c0586b1bff94816565a36c127ae276cade8fb.json\": {\n        \"bytes\": 61927,\n        \"sha256\": \"5a34609ecb6965fac2e2525673583ac9f5bcc38652f674d81b8090f5dc17cf57\",\n        \"uid\": 10484\n      },\n      \"diagnostic-3534609dabda0ed5ee97004cdf586290d34aacb8a51857e109007dfbc0911500.json\": {\n        \"bytes\": 305381,\n        \"sha256\": \"27b9eddd923d7efb44e3eabebe87b503e63869c84a8074ba4ecce53a553db806\",\n        \"uid\": 10484\n      },\n      \"diagnostic-361c2e19f1f7b8b606ada953ce8764a08d3c97b859d1d5d56a2cbab4cd113b55.json\": {\n        \"bytes\": 305381,\n        \"sha256\": \"17ffb325c0ae0ebfd4186c21e1d07ce0ae6110bd6c7392a477cd983622831fc8\",\n        \"uid\": 10484\n      },\n      \"diagnostic-3c8fb015d9749da98ed615aab0a6d0d6315b45b9836b92b6ca4d40bb1cf35e16.json\": {\n        \"bytes\": 309230,\n        \"sha256\": \"383622b7853d7e39d870c08522ed7287760de6d9b18cdc8ae08230a23c8afbb3\",\n        \"uid\": 10484\n      },\n      \"diagnostic-4d769f772d5eaf8fa7128b3c7f3a7e5ccc978c535a185e602b9747a81adcdea5.json\": {\n        \"bytes\": 308216,\n        \"sha256\": \"cc2e3cdef57f3adcd4e64779e6ff827c1586e9e0b2d15737db808441856dffc9\",\n        \"uid\": 10484\n      },\n      \"diagnostic-4edc3ac8e659e5438cd1ff507c370b6f34a899e0ce8391af67809996e66e6547.json\": {\n        \"bytes\": 63083,\n        \"sha256\": \"737a08eef8ccca27b42b11900daa5182cf27b538bafd275dad9fcbd23530d416\",\n        \"uid\": 10484\n      },\n      \"diagnostic-53ddffb0458add0e7c1faf8fe6a090a5640a9ef3db51904199d2d9fa946d45b3.json\": {\n        \"bytes\": 308752,\n        \"sha256\": \"0861ac8b133b636478364f3957eed71391dd63e79e4b29530538fbaaafb31136\",\n        \"uid\": 10484\n      },\n      \"diagnostic-5988650db5f7f527be3c7e4e8ea17b3fa7d9d6158e020178f218bfd2da0a0019.json\": {\n        \"bytes\": 305381,\n        \"sha256\": \"74bac5bde381e25e4af3978e9184c3d2f70331a7c2ad943c7845b62511a532f3\",\n        \"uid\": 10484\n      },\n      \"diagnostic-5d1be4c0d35bdebf71644cde85a6e5284c11933ab08286070abb99ce332620e4.json\": {\n        \"bytes\": 305699,\n        \"sha256\": \"6535ad2d33943cb0e55fba533fca0c172a6f27b1a18e255d783f2fb02c34598a\",\n        \"uid\": 10484\n      },\n      \"diagnostic-612297bc8413908925c112255fcbda05a294ca746122db1fc9b50c7e05999c88.json\": {\n        \"bytes\": 305381,\n        \"sha256\": \"05c2064dc1fce4c42c516d3d0e2c4a76f86e69b1e2fbe31149d0b99505c24bfc\",\n        \"uid\": 10484\n      },\n      \"diagnostic-6926d45f605fe7e01b4060920f868da64534095f0601bc5ea648da9de669d20b.json\": {\n        \"bytes\": 309579,\n        \"sha256\": \"60d2c114cf1dd29dc77bace83afff6f991e9423bf01e5e93298ba5f4a7601328\",\n        \"uid\": 10484\n      },\n      \"diagnostic-6f948b0dfff7afd85b17de1f34cbe3a4efafd7d77c1339788cd570cc192ba2bf.json\": {\n        \"bytes\": 305381,\n        \"sha256\": \"5e2b305ed6681abec482db258269a839c3de4bbbf9a8d9509541701fbb516fbc\",\n        \"uid\": 10484\n      },\n      \"diagnostic-774161b299dfb95da9b6d80f2a60c1ca38e7a4b1fa9540698fc5b11d22e24677.json\": {\n        \"bytes\": 16983,\n        \"sha256\": \"e717bcbf4def54057def6b90ce5a52f86ca2270c7d14f097fa501a216c3cddd0\",\n        \"uid\": 10484\n      },\n      \"diagnostic-80c8614b93cffb391969fe3f3ebab1a433dd5ecb102ab573feee469e5b4a5e82.json\": {\n        \"bytes\": 305381,\n        \"sha256\": \"3bc2c24b558df3c5bd248c93172b1b18027464b6506b6aa90fcae466f442d718\",\n        \"uid\": 10484\n      },\n      \"diagnostic-839c1cc1b1d1c76a695c6a855c6323be0cda6a1f67d8e7f575028fffb3a7e78f.json\": {\n        \"bytes\": 305381,\n        \"sha256\": \"e57bacfe2d127e9805a352cb02c1ce959fe17ed01dd9663a2fc5d3083c501cc0\",\n        \"uid\": 10484\n      },\n      \"diagnostic-84b334a0ca431d9387e45114fe4121919bb79efae43eaafef1ecc09fd3eb656d.json\": {\n        \"bytes\": 305381,\n        \"sha256\": \"41bc9473e7803d1d1374a78d840dc17d2c84d14dc3e7fb090475f670ce61dd70\",\n        \"uid\": 10484\n      },\n      \"diagnostic-963551623468fb947925862e7eb1e6b5fda0c53ba5ed9fb2b1e474f04a6e9d86.json\": {\n        \"bytes\": 308728,\n        \"sha256\": \"9218dc03267ace444073fffb4f24db6f5ea6994e510643cd558557e4b6c2d7b8\",\n        \"uid\": 10484\n      },\n      \"diagnostic-9aad2bf65e8bc7aa21e2aee5638694040fd88a1b47e1b9a061d726032bbb653c.json\": {\n        \"bytes\": 305381,\n        \"sha256\": \"455e1c6e287badf5b717877ab6792e87b4ac91bff9d1cf2836474225e86b6560\",\n        \"uid\": 10484\n      },\n      \"diagnostic-bb8cf70a120986c87db41ac296f7a471441e142eca1f95a45451415c2e6d1452.json\": {\n        \"bytes\": 305381,\n        \"sha256\": \"b1d93f8d8710f22455b6ab7dfdc17f316ac0fb4a23ff62bd9f88ba5cabf7a494\",\n        \"uid\": 10484\n      },\n      \"diagnostic-bfdc6653be17b14c965ea9d236f2e3b0d8a3c14723a332381eacc7261376752a.json\": {\n        \"bytes\": 963232,\n        \"sha256\": \"1b0305a9002f64ddbe41dc197aafff8b0ace70f668f2b608d3b76b6feb7b2dda\",\n        \"uid\": 10484\n      },\n      \"diagnostic-c3e5c2949009203895f588c088fe97373396c5672e72c89d5284723735fab2ae.json\": {\n        \"bytes\": 63091,\n        \"sha256\": \"c4c74dda1e632fce53fbef0688583b8c28cedfa6d0462ca149cdd0ebf3628da8\",\n        \"uid\": 10484\n      },\n      \"diagnostic-c4017cc82c05814c36b2515ca5cbb22f12d5331bf96cd43389460ec937bbffe8.json\": {\n        \"bytes\": 963233,\n        \"sha256\": \"0d2e76e387ac5e82ee5adaa0c2a17d75a9aea9e7700d707ac86ae6506b61e840\",\n        \"uid\": 10484\n      },\n      \"diagnostic-close-1dfe5600-0db0-49a9-a145-b697ec617956.json\": {\n        \"bytes\": 1529,\n        \"sha256\": \"f4b9ce45808da1904b58d19e07f9c87cb1860bbc7315aef6a7ad89e0fe641060\",\n        \"uid\": 10484\n      },\n      \"diagnostic-close-972509d1-f0d8-4f8b-ac09-38783d062331.json\": {\n        \"bytes\": 1708,\n        \"sha256\": \"bd72d3481e48521bcd1736d46ee25446bffa916aab118a3273ffb83ead241967\",\n        \"uid\": 10484\n      },\n      \"diagnostic-close-c681b5ba-d88b-441c-b1ee-5dad210718cc.json\": {\n        \"bytes\": 1632,\n        \"sha256\": \"d10cedcc236d4d93114f3c3cae3515ef7dac658dca34f565f9802e86bcda4c0e\",\n        \"uid\": 10484\n      },\n      \"diagnostic-d12138c40d118cddb742ebaa38b93944b10ecccede48565fad27f9a4e462dffa.json\": {\n        \"bytes\": 305381,\n        \"sha256\": \"0136ddd29c328a8a2866853e765337f3b50f03bddb3bb47619f2a1f0e12e5679\",\n        \"uid\": 10484\n      },\n      \"diagnostic-e34366c697facacb44049015744abeecab23f84982963f95e4369c0f2b5cf931.json\": {\n        \"bytes\": 305381,\n        \"sha256\": \"21fe48d7cc2b7b86dafd9f0cd359f0b4eeb4f4962690b0b1cd53e2add25ec8f0\",\n        \"uid\": 10484\n      },\n      \"diagnostic-e413cb069e3c5196bf59f929590c16f979d73703ca7194a1c3fc87373df96c49.json\": {\n        \"bytes\": 59144,\n        \"sha256\": \"3a5be3816a291ab75bef4997ce04226e9a252a8e26c1a7fcc7056c1b6c3eb009\",\n        \"uid\": 10484\n      },\n      \"diagnostic-e94b76746ba64e1c54e2799d62814b2e3f0c3bc0185dd8a74e2496a5d29c231f.json\": {\n        \"bytes\": 305381,\n        \"sha256\": \"af3aeb11c295b62c1a47c6c5bd04993bd545a91dc7689e79ee89d7a40c17472e\",\n        \"uid\": 10484\n      },\n      \"diagnostic-f596b99af486f258e6e100b38bc48bb35864243dcf4335bdd4fde73258053e27.json\": {\n        \"bytes\": 386724,\n        \"sha256\": \"f61fd86cb24b212c3434bb5eda1a4e29b65c06c22d3fc4238366f31a324dd7fa\",\n        \"uid\": 10484\n      },\n      \"diagnostic-unstarted-fd01c43b-ccf1-4ebd-8579-92ed09924fe2.json\": {\n        \"bytes\": 260,\n        \"sha256\": \"3f1b4bcec3bec8e7d1a04cff0204bfb002edc0ab15464537743acabb8ada0b85\",\n        \"uid\": 10484\n      }\n    },\n    \"task_id\": \"3c90bb05c4974a8980655fd254fc933e\",\n    \"result_sha256\": \"6881749bc9429b4ce1332353ecd67fe2d524ae19b14349a1208a08b9b41195d7\",\n    \"collection_sha256\": \"642b7136d7d1ba94701c004615ef1024a0ae87eb0d701505df87deca87f502f0\",\n    \"helper_was_unstarted\": true,\n    \"formal_lease_cleanup_verified\": false,\n    \"business_verified\": false,\n    \"unstarted_original_sha256\": \"3f1b4bcec3bec8e7d1a04cff0204bfb002edc0ab15464537743acabb8ada0b85\"\n  },\"formal_artifact_proof\":{\n    \"signed\": {\n      \"path\": \"/home/alex/hepta-local-007f-20261111/v55-web-helper-code6-sign-r1/out/RESULT.json\",\n      \"bytes\": 195558,\n      \"sha256\": \"020921fcb9459f3e64773d15e978e1d6e63de535c351873b86baa1965cbc3258\"\n    },\n    \"build\": {\n      \"path\": \"/home/alex/hepta-local-007f-20261111/v55-web-helper-code6-p4-build-r3/RESULT.json\",\n      \"bytes\": 230541,\n      \"sha256\": \"8dad8522b39d9fb017fdb869bfdf9c8081f14d445a314bb4555d84e11e49539d\"\n    },\n    \"apk\": {\n      \"path\": \"/home/alex/hepta-local-007f-20261111/v55-web-helper-code6-sign-r1/out/hepta-web-helper-0.6.0-v4.apk\",\n      \"bytes\": 1410047,\n      \"sha256\": \"02360c24c471dcd4be0cbc7c7fdb316a7918d656edd1407d765540b5a3f2f5ff\"\n    },\n    \"source_file_count\": 43,\n    \"compiled_member_count\": 372,\n    \"unchanged_compiled_payload_count\": 369,\n    \"all_signed_members_and_local_headers_recomputed\": true,\n    \"source_archive_all44_members_recomputed\": true,\n    \"helper5_signed_receipt_sha256\": \"ad9fe0cb5ea808e6d563b398b45e79286a1158fc3db43ea2226f4fd0edd29580\",\n    \"phone_or_business_proof\": false\n  },\"installed_identity_before\":{\n    \"package\": \"org.trillionnium.hepta.webhelper\",\n    \"uid\": 10484,\n    \"apks\": [\n      {\n        \"path\": \"/data/app/~~7tm-0viTiSPtMXQrKQNE5A==/org.trillionnium.hepta.webhelper-FzFUV5CCtZ60uGZ1qVOzWg==/base.apk\",\n        \"sha256\": \"b5e56ce0c2967489b55150c157f8289fdd82ad5b89caacc8b106013a7caeaf4f\"\n      }\n    ]\n  },\"observer_installed_identity\":{\n    \"package\": \"org.trillionnium.hepta.webhelper\",\n    \"uid\": 10484,\n    \"apks\": [\n      {\n        \"path\": \"/data/app/~~iuCpyfrLdnn2FSYG4ZOcYQ==/org.trillionnium.hepta.webhelper-LMxwSbN_9UdoiNCifY0iXw==/base.apk\",\n        \"sha256\": \"02360c24c471dcd4be0cbc7c7fdb316a7918d656edd1407d765540b5a3f2f5ff\"\n      }\n    ]\n  },\"main_identity_before\":{\n    \"package\": \"org.trillionnium.hepta.local\",\n    \"uid\": 10481,\n    \"apks\": [\n      {\n        \"path\": \"/data/app/~~hQX6r7v5s_gKn7o8ImvScQ==/org.trillionnium.hepta.local-PNZseE9N9jPiez75ykUSRA==/base.apk\",\n        \"sha256\": \"0729f54704a058049e12041c7f901b1b6650924500663cf9952a03d6a33a8b8a\"\n      }\n    ],\n    \"version_code\": 54\n  },\"main_identity_preserved\":{\n    \"package\": \"org.trillionnium.hepta.local\",\n    \"uid\": 10481,\n    \"apks\": [\n      {\n        \"path\": \"/data/app/~~hQX6r7v5s_gKn7o8ImvScQ==/org.trillionnium.hepta.local-PNZseE9N9jPiez75ykUSRA==/base.apk\",\n        \"sha256\": \"0729f54704a058049e12041c7f901b1b6650924500663cf9952a03d6a33a8b8a\"\n      }\n    ],\n    \"version_code\": 54\n  },\"diagnostics_before_upgrade\":{\n    \"diagnostic-020c1d13a67d132eed6874ba43cf0d6f35cd473c095e94f890ac6bc2e6b2667f.json\": {\n      \"bytes\": 30993,\n      \"sha256\": \"386f86ef76923ce994574893bc05eec906f3ef839f32d8a77a68092e0115d986\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 241724,\n        \"uid\": 10484,\n        \"bytes\": 30993,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794457866,\n        \"ctime_s\": 1794457866\n      }\n    },\n    \"diagnostic-0e8377e803ac9a467c4a5cb52e5937a15a6a93b43f7934bcaebeedba84b689fc.json\": {\n      \"bytes\": 308739,\n      \"sha256\": \"96aecf073ee65951c988a5710fea394713e64af161f0513e36ee2d539991ebc3\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 240970,\n        \"uid\": 10484,\n        \"bytes\": 308739,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794445463,\n        \"ctime_s\": 1794445463\n      }\n    },\n    \"diagnostic-200d1eb4031744b38d899525241af8f89643659ed769590d5cf4614cc0f376c5.json\": {\n      \"bytes\": 305357,\n      \"sha256\": \"ffe2b5a4cf79e12098abafdc63a006583f9eaddb7f786671bcf1d03bc03e4f83\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 232057,\n        \"uid\": 10484,\n        \"bytes\": 305357,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794437226,\n        \"ctime_s\": 1794437226\n      }\n    },\n    \"diagnostic-2185104639ec2e909a3eb0241b33d7f2714925010d63223c7e6509f4ec8c660b.json\": {\n      \"bytes\": 305381,\n      \"sha256\": \"4d41342931181e4a208439b0dab4766d25d9d0b2e0bd08d5a24c420cae99f969\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 238033,\n        \"uid\": 10484,\n        \"bytes\": 305381,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794440505,\n        \"ctime_s\": 1794440505\n      }\n    },\n    \"diagnostic-260f603251c34639addc7c70fea84f3bcf676e12d373bdaa69f43d6c9fbe3f46.json\": {\n      \"bytes\": 305386,\n      \"sha256\": \"f716aaac6fd44a1015a1f6f1d61b4a0fb2efdda433b3fddcce684840fe103ea9\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 239740,\n        \"uid\": 10484,\n        \"bytes\": 305386,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794440612,\n        \"ctime_s\": 1794440612\n      }\n    },\n    \"diagnostic-292f3f81694870ce87b987a04046ccb48e0b3cd6b11813b24f014a5f6a5cccea.json\": {\n      \"bytes\": 308752,\n      \"sha256\": \"b5d351b711eac0b70c7458bc0c1f3f52c4e5d4f9e8e0a3b35a9e2529585adf22\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 241732,\n        \"uid\": 10484,\n        \"bytes\": 308752,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794450932,\n        \"ctime_s\": 1794450932\n      }\n    },\n    \"diagnostic-342e51e1e6c5fac683309de2758c0586b1bff94816565a36c127ae276cade8fb.json\": {\n      \"bytes\": 61927,\n      \"sha256\": \"5a34609ecb6965fac2e2525673583ac9f5bcc38652f674d81b8090f5dc17cf57\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 241158,\n        \"uid\": 10484,\n        \"bytes\": 61927,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794441841,\n        \"ctime_s\": 1794441841\n      }\n    },\n    \"diagnostic-3534609dabda0ed5ee97004cdf586290d34aacb8a51857e109007dfbc0911500.json\": {\n      \"bytes\": 305381,\n      \"sha256\": \"27b9eddd923d7efb44e3eabebe87b503e63869c84a8074ba4ecce53a553db806\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 239647,\n        \"uid\": 10484,\n        \"bytes\": 305381,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794440614,\n        \"ctime_s\": 1794440614\n      }\n    },\n    \"diagnostic-361c2e19f1f7b8b606ada953ce8764a08d3c97b859d1d5d56a2cbab4cd113b55.json\": {\n      \"bytes\": 305381,\n      \"sha256\": \"17ffb325c0ae0ebfd4186c21e1d07ce0ae6110bd6c7392a477cd983622831fc8\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 239985,\n        \"uid\": 10484,\n        \"bytes\": 305381,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794440615,\n        \"ctime_s\": 1794440615\n      }\n    },\n    \"diagnostic-3c8fb015d9749da98ed615aab0a6d0d6315b45b9836b92b6ca4d40bb1cf35e16.json\": {\n      \"bytes\": 309230,\n      \"sha256\": \"383622b7853d7e39d870c08522ed7287760de6d9b18cdc8ae08230a23c8afbb3\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 236205,\n        \"uid\": 10484,\n        \"bytes\": 309230,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794457699,\n        \"ctime_s\": 1794457699\n      }\n    },\n    \"diagnostic-4d769f772d5eaf8fa7128b3c7f3a7e5ccc978c535a185e602b9747a81adcdea5.json\": {\n      \"bytes\": 308216,\n      \"sha256\": \"cc2e3cdef57f3adcd4e64779e6ff827c1586e9e0b2d15737db808441856dffc9\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 238742,\n        \"uid\": 10484,\n        \"bytes\": 308216,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794444293,\n        \"ctime_s\": 1794444293\n      }\n    },\n    \"diagnostic-4edc3ac8e659e5438cd1ff507c370b6f34a899e0ce8391af67809996e66e6547.json\": {\n      \"bytes\": 63083,\n      \"sha256\": \"737a08eef8ccca27b42b11900daa5182cf27b538bafd275dad9fcbd23530d416\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 241945,\n        \"uid\": 10484,\n        \"bytes\": 63083,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794457072,\n        \"ctime_s\": 1794457072\n      }\n    },\n    \"diagnostic-53ddffb0458add0e7c1faf8fe6a090a5640a9ef3db51904199d2d9fa946d45b3.json\": {\n      \"bytes\": 308752,\n      \"sha256\": \"0861ac8b133b636478364f3957eed71391dd63e79e4b29530538fbaaafb31136\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 240966,\n        \"uid\": 10484,\n        \"bytes\": 308752,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794445463,\n        \"ctime_s\": 1794445463\n      }\n    },\n    \"diagnostic-5988650db5f7f527be3c7e4e8ea17b3fa7d9d6158e020178f218bfd2da0a0019.json\": {\n      \"bytes\": 305381,\n      \"sha256\": \"74bac5bde381e25e4af3978e9184c3d2f70331a7c2ad943c7845b62511a532f3\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 240475,\n        \"uid\": 10484,\n        \"bytes\": 305381,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794438908,\n        \"ctime_s\": 1794438908\n      }\n    },\n    \"diagnostic-5d1be4c0d35bdebf71644cde85a6e5284c11933ab08286070abb99ce332620e4.json\": {\n      \"bytes\": 305699,\n      \"sha256\": \"6535ad2d33943cb0e55fba533fca0c172a6f27b1a18e255d783f2fb02c34598a\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 239866,\n        \"uid\": 10484,\n        \"bytes\": 305699,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794440616,\n        \"ctime_s\": 1794440616\n      }\n    },\n    \"diagnostic-612297bc8413908925c112255fcbda05a294ca746122db1fc9b50c7e05999c88.json\": {\n      \"bytes\": 305381,\n      \"sha256\": \"05c2064dc1fce4c42c516d3d0e2c4a76f86e69b1e2fbe31149d0b99505c24bfc\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 239878,\n        \"uid\": 10484,\n        \"bytes\": 305381,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794440615,\n        \"ctime_s\": 1794440615\n      }\n    },\n    \"diagnostic-6926d45f605fe7e01b4060920f868da64534095f0601bc5ea648da9de669d20b.json\": {\n      \"bytes\": 309579,\n      \"sha256\": \"60d2c114cf1dd29dc77bace83afff6f991e9423bf01e5e93298ba5f4a7601328\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 216193,\n        \"uid\": 10484,\n        \"bytes\": 309579,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794458819,\n        \"ctime_s\": 1794458819\n      }\n    },\n    \"diagnostic-6f948b0dfff7afd85b17de1f34cbe3a4efafd7d77c1339788cd570cc192ba2bf.json\": {\n      \"bytes\": 305381,\n      \"sha256\": \"5e2b305ed6681abec482db258269a839c3de4bbbf9a8d9509541701fbb516fbc\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 239440,\n        \"uid\": 10484,\n        \"bytes\": 305381,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794440613,\n        \"ctime_s\": 1794440613\n      }\n    },\n    \"diagnostic-774161b299dfb95da9b6d80f2a60c1ca38e7a4b1fa9540698fc5b11d22e24677.json\": {\n      \"bytes\": 16983,\n      \"sha256\": \"e717bcbf4def54057def6b90ce5a52f86ca2270c7d14f097fa501a216c3cddd0\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 238530,\n        \"uid\": 10484,\n        \"bytes\": 16983,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794436933,\n        \"ctime_s\": 1794436933\n      }\n    },\n    \"diagnostic-80c8614b93cffb391969fe3f3ebab1a433dd5ecb102ab573feee469e5b4a5e82.json\": {\n      \"bytes\": 305381,\n      \"sha256\": \"3bc2c24b558df3c5bd248c93172b1b18027464b6506b6aa90fcae466f442d718\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 240260,\n        \"uid\": 10484,\n        \"bytes\": 305381,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794438907,\n        \"ctime_s\": 1794438907\n      }\n    },\n    \"diagnostic-839c1cc1b1d1c76a695c6a855c6323be0cda6a1f67d8e7f575028fffb3a7e78f.json\": {\n      \"bytes\": 305381,\n      \"sha256\": \"e57bacfe2d127e9805a352cb02c1ce959fe17ed01dd9663a2fc5d3083c501cc0\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 240031,\n        \"uid\": 10484,\n        \"bytes\": 305381,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794440618,\n        \"ctime_s\": 1794440618\n      }\n    },\n    \"diagnostic-84b334a0ca431d9387e45114fe4121919bb79efae43eaafef1ecc09fd3eb656d.json\": {\n      \"bytes\": 305381,\n      \"sha256\": \"41bc9473e7803d1d1374a78d840dc17d2c84d14dc3e7fb090475f670ce61dd70\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 238187,\n        \"uid\": 10484,\n        \"bytes\": 305381,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794440503,\n        \"ctime_s\": 1794440503\n      }\n    },\n    \"diagnostic-963551623468fb947925862e7eb1e6b5fda0c53ba5ed9fb2b1e474f04a6e9d86.json\": {\n      \"bytes\": 308728,\n      \"sha256\": \"9218dc03267ace444073fffb4f24db6f5ea6994e510643cd558557e4b6c2d7b8\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 239983,\n        \"uid\": 10484,\n        \"bytes\": 308728,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794446256,\n        \"ctime_s\": 1794446256\n      }\n    },\n    \"diagnostic-9aad2bf65e8bc7aa21e2aee5638694040fd88a1b47e1b9a061d726032bbb653c.json\": {\n      \"bytes\": 305381,\n      \"sha256\": \"455e1c6e287badf5b717877ab6792e87b4ac91bff9d1cf2836474225e86b6560\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 238341,\n        \"uid\": 10484,\n        \"bytes\": 305381,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794440501,\n        \"ctime_s\": 1794440501\n      }\n    },\n    \"diagnostic-bb8cf70a120986c87db41ac296f7a471441e142eca1f95a45451415c2e6d1452.json\": {\n      \"bytes\": 305381,\n      \"sha256\": \"b1d93f8d8710f22455b6ab7dfdc17f316ac0fb4a23ff62bd9f88ba5cabf7a494\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 239974,\n        \"uid\": 10484,\n        \"bytes\": 305381,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794440616,\n        \"ctime_s\": 1794440616\n      }\n    },\n    \"diagnostic-bfdc6653be17b14c965ea9d236f2e3b0d8a3c14723a332381eacc7261376752a.json\": {\n      \"bytes\": 963232,\n      \"sha256\": \"1b0305a9002f64ddbe41dc197aafff8b0ace70f668f2b608d3b76b6feb7b2dda\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 240597,\n        \"uid\": 10484,\n        \"bytes\": 963232,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794474727,\n        \"ctime_s\": 1794474727\n      }\n    },\n    \"diagnostic-c3e5c2949009203895f588c088fe97373396c5672e72c89d5284723735fab2ae.json\": {\n      \"bytes\": 63091,\n      \"sha256\": \"c4c74dda1e632fce53fbef0688583b8c28cedfa6d0462ca149cdd0ebf3628da8\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 238206,\n        \"uid\": 10484,\n        \"bytes\": 63091,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794458825,\n        \"ctime_s\": 1794458825\n      }\n    },\n    \"diagnostic-c4017cc82c05814c36b2515ca5cbb22f12d5331bf96cd43389460ec937bbffe8.json\": {\n      \"bytes\": 963233,\n      \"sha256\": \"0d2e76e387ac5e82ee5adaa0c2a17d75a9aea9e7700d707ac86ae6506b61e840\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 240557,\n        \"uid\": 10484,\n        \"bytes\": 963233,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794474727,\n        \"ctime_s\": 1794474727\n      }\n    },\n    \"diagnostic-close-1dfe5600-0db0-49a9-a145-b697ec617956.json\": {\n      \"bytes\": 1529,\n      \"sha256\": \"f4b9ce45808da1904b58d19e07f9c87cb1860bbc7315aef6a7ad89e0fe641060\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 238958,\n        \"uid\": 10484,\n        \"bytes\": 1529,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794458831,\n        \"ctime_s\": 1794458831\n      }\n    },\n    \"diagnostic-close-972509d1-f0d8-4f8b-ac09-38783d062331.json\": {\n      \"bytes\": 1708,\n      \"sha256\": \"bd72d3481e48521bcd1736d46ee25446bffa916aab118a3273ffb83ead241967\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 241826,\n        \"uid\": 10484,\n        \"bytes\": 1708,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794475894,\n        \"ctime_s\": 1794475894\n      }\n    },\n    \"diagnostic-close-c681b5ba-d88b-441c-b1ee-5dad210718cc.json\": {\n      \"bytes\": 1632,\n      \"sha256\": \"d10cedcc236d4d93114f3c3cae3515ef7dac658dca34f565f9802e86bcda4c0e\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 239478,\n        \"uid\": 10484,\n        \"bytes\": 1632,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794467234,\n        \"ctime_s\": 1794467234\n      }\n    },\n    \"diagnostic-d12138c40d118cddb742ebaa38b93944b10ecccede48565fad27f9a4e462dffa.json\": {\n      \"bytes\": 305381,\n      \"sha256\": \"0136ddd29c328a8a2866853e765337f3b50f03bddb3bb47619f2a1f0e12e5679\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 239771,\n        \"uid\": 10484,\n        \"bytes\": 305381,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794440607,\n        \"ctime_s\": 1794440607\n      }\n    },\n    \"diagnostic-e34366c697facacb44049015744abeecab23f84982963f95e4369c0f2b5cf931.json\": {\n      \"bytes\": 305381,\n      \"sha256\": \"21fe48d7cc2b7b86dafd9f0cd359f0b4eeb4f4962690b0b1cd53e2add25ec8f0\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 239642,\n        \"uid\": 10484,\n        \"bytes\": 305381,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794440614,\n        \"ctime_s\": 1794440614\n      }\n    },\n    \"diagnostic-e413cb069e3c5196bf59f929590c16f979d73703ca7194a1c3fc87373df96c49.json\": {\n      \"bytes\": 59144,\n      \"sha256\": \"3a5be3816a291ab75bef4997ce04226e9a252a8e26c1a7fcc7056c1b6c3eb009\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 241578,\n        \"uid\": 10484,\n        \"bytes\": 59144,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794431946,\n        \"ctime_s\": 1794431946\n      }\n    },\n    \"diagnostic-e94b76746ba64e1c54e2799d62814b2e3f0c3bc0185dd8a74e2496a5d29c231f.json\": {\n      \"bytes\": 305381,\n      \"sha256\": \"af3aeb11c295b62c1a47c6c5bd04993bd545a91dc7689e79ee89d7a40c17472e\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 238253,\n        \"uid\": 10484,\n        \"bytes\": 305381,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794440503,\n        \"ctime_s\": 1794440503\n      }\n    },\n    \"diagnostic-f596b99af486f258e6e100b38bc48bb35864243dcf4335bdd4fde73258053e27.json\": {\n      \"bytes\": 386724,\n      \"sha256\": \"f61fd86cb24b212c3434bb5eda1a4e29b65c06c22d3fc4238366f31a324dd7fa\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 238688,\n        \"uid\": 10484,\n        \"bytes\": 386724,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794458395,\n        \"ctime_s\": 1794458395\n      }\n    },\n    \"diagnostic-unstarted-fd01c43b-ccf1-4ebd-8579-92ed09924fe2.json\": {\n      \"bytes\": 260,\n      \"sha256\": \"3f1b4bcec3bec8e7d1a04cff0204bfb002edc0ab15464537743acabb8ada0b85\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 241042,\n        \"uid\": 10484,\n        \"bytes\": 260,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794488567,\n        \"ctime_s\": 1794488567\n      }\n    }\n  },\"diagnostics_after_upgrade\":{\n    \"diagnostic-020c1d13a67d132eed6874ba43cf0d6f35cd473c095e94f890ac6bc2e6b2667f.json\": {\n      \"bytes\": 30993,\n      \"sha256\": \"386f86ef76923ce994574893bc05eec906f3ef839f32d8a77a68092e0115d986\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 241724,\n        \"uid\": 10484,\n        \"bytes\": 30993,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794457866,\n        \"ctime_s\": 1794457866\n      }\n    },\n    \"diagnostic-0e8377e803ac9a467c4a5cb52e5937a15a6a93b43f7934bcaebeedba84b689fc.json\": {\n      \"bytes\": 308739,\n      \"sha256\": \"96aecf073ee65951c988a5710fea394713e64af161f0513e36ee2d539991ebc3\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 240970,\n        \"uid\": 10484,\n        \"bytes\": 308739,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794445463,\n        \"ctime_s\": 1794445463\n      }\n    },\n    \"diagnostic-200d1eb4031744b38d899525241af8f89643659ed769590d5cf4614cc0f376c5.json\": {\n      \"bytes\": 305357,\n      \"sha256\": \"ffe2b5a4cf79e12098abafdc63a006583f9eaddb7f786671bcf1d03bc03e4f83\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 232057,\n        \"uid\": 10484,\n        \"bytes\": 305357,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794437226,\n        \"ctime_s\": 1794437226\n      }\n    },\n    \"diagnostic-2185104639ec2e909a3eb0241b33d7f2714925010d63223c7e6509f4ec8c660b.json\": {\n      \"bytes\": 305381,\n      \"sha256\": \"4d41342931181e4a208439b0dab4766d25d9d0b2e0bd08d5a24c420cae99f969\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 238033,\n        \"uid\": 10484,\n        \"bytes\": 305381,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794440505,\n        \"ctime_s\": 1794440505\n      }\n    },\n    \"diagnostic-260f603251c34639addc7c70fea84f3bcf676e12d373bdaa69f43d6c9fbe3f46.json\": {\n      \"bytes\": 305386,\n      \"sha256\": \"f716aaac6fd44a1015a1f6f1d61b4a0fb2efdda433b3fddcce684840fe103ea9\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 239740,\n        \"uid\": 10484,\n        \"bytes\": 305386,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794440612,\n        \"ctime_s\": 1794440612\n      }\n    },\n    \"diagnostic-292f3f81694870ce87b987a04046ccb48e0b3cd6b11813b24f014a5f6a5cccea.json\": {\n      \"bytes\": 308752,\n      \"sha256\": \"b5d351b711eac0b70c7458bc0c1f3f52c4e5d4f9e8e0a3b35a9e2529585adf22\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 241732,\n        \"uid\": 10484,\n        \"bytes\": 308752,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794450932,\n        \"ctime_s\": 1794450932\n      }\n    },\n    \"diagnostic-342e51e1e6c5fac683309de2758c0586b1bff94816565a36c127ae276cade8fb.json\": {\n      \"bytes\": 61927,\n      \"sha256\": \"5a34609ecb6965fac2e2525673583ac9f5bcc38652f674d81b8090f5dc17cf57\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 241158,\n        \"uid\": 10484,\n        \"bytes\": 61927,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794441841,\n        \"ctime_s\": 1794441841\n      }\n    },\n    \"diagnostic-3534609dabda0ed5ee97004cdf586290d34aacb8a51857e109007dfbc0911500.json\": {\n      \"bytes\": 305381,\n      \"sha256\": \"27b9eddd923d7efb44e3eabebe87b503e63869c84a8074ba4ecce53a553db806\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 239647,\n        \"uid\": 10484,\n        \"bytes\": 305381,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794440614,\n        \"ctime_s\": 1794440614\n      }\n    },\n    \"diagnostic-361c2e19f1f7b8b606ada953ce8764a08d3c97b859d1d5d56a2cbab4cd113b55.json\": {\n      \"bytes\": 305381,\n      \"sha256\": \"17ffb325c0ae0ebfd4186c21e1d07ce0ae6110bd6c7392a477cd983622831fc8\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 239985,\n        \"uid\": 10484,\n        \"bytes\": 305381,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794440615,\n        \"ctime_s\": 1794440615\n      }\n    },\n    \"diagnostic-3c8fb015d9749da98ed615aab0a6d0d6315b45b9836b92b6ca4d40bb1cf35e16.json\": {\n      \"bytes\": 309230,\n      \"sha256\": \"383622b7853d7e39d870c08522ed7287760de6d9b18cdc8ae08230a23c8afbb3\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 236205,\n        \"uid\": 10484,\n        \"bytes\": 309230,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794457699,\n        \"ctime_s\": 1794457699\n      }\n    },\n    \"diagnostic-4d769f772d5eaf8fa7128b3c7f3a7e5ccc978c535a185e602b9747a81adcdea5.json\": {\n      \"bytes\": 308216,\n      \"sha256\": \"cc2e3cdef57f3adcd4e64779e6ff827c1586e9e0b2d15737db808441856dffc9\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 238742,\n        \"uid\": 10484,\n        \"bytes\": 308216,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794444293,\n        \"ctime_s\": 1794444293\n      }\n    },\n    \"diagnostic-4edc3ac8e659e5438cd1ff507c370b6f34a899e0ce8391af67809996e66e6547.json\": {\n      \"bytes\": 63083,\n      \"sha256\": \"737a08eef8ccca27b42b11900daa5182cf27b538bafd275dad9fcbd23530d416\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 241945,\n        \"uid\": 10484,\n        \"bytes\": 63083,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794457072,\n        \"ctime_s\": 1794457072\n      }\n    },\n    \"diagnostic-53ddffb0458add0e7c1faf8fe6a090a5640a9ef3db51904199d2d9fa946d45b3.json\": {\n      \"bytes\": 308752,\n      \"sha256\": \"0861ac8b133b636478364f3957eed71391dd63e79e4b29530538fbaaafb31136\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 240966,\n        \"uid\": 10484,\n        \"bytes\": 308752,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794445463,\n        \"ctime_s\": 1794445463\n      }\n    },\n    \"diagnostic-5988650db5f7f527be3c7e4e8ea17b3fa7d9d6158e020178f218bfd2da0a0019.json\": {\n      \"bytes\": 305381,\n      \"sha256\": \"74bac5bde381e25e4af3978e9184c3d2f70331a7c2ad943c7845b62511a532f3\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 240475,\n        \"uid\": 10484,\n        \"bytes\": 305381,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794438908,\n        \"ctime_s\": 1794438908\n      }\n    },\n    \"diagnostic-5d1be4c0d35bdebf71644cde85a6e5284c11933ab08286070abb99ce332620e4.json\": {\n      \"bytes\": 305699,\n      \"sha256\": \"6535ad2d33943cb0e55fba533fca0c172a6f27b1a18e255d783f2fb02c34598a\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 239866,\n        \"uid\": 10484,\n        \"bytes\": 305699,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794440616,\n        \"ctime_s\": 1794440616\n      }\n    },\n    \"diagnostic-612297bc8413908925c112255fcbda05a294ca746122db1fc9b50c7e05999c88.json\": {\n      \"bytes\": 305381,\n      \"sha256\": \"05c2064dc1fce4c42c516d3d0e2c4a76f86e69b1e2fbe31149d0b99505c24bfc\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 239878,\n        \"uid\": 10484,\n        \"bytes\": 305381,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794440615,\n        \"ctime_s\": 1794440615\n      }\n    },\n    \"diagnostic-6926d45f605fe7e01b4060920f868da64534095f0601bc5ea648da9de669d20b.json\": {\n      \"bytes\": 309579,\n      \"sha256\": \"60d2c114cf1dd29dc77bace83afff6f991e9423bf01e5e93298ba5f4a7601328\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 216193,\n        \"uid\": 10484,\n        \"bytes\": 309579,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794458819,\n        \"ctime_s\": 1794458819\n      }\n    },\n    \"diagnostic-6f948b0dfff7afd85b17de1f34cbe3a4efafd7d77c1339788cd570cc192ba2bf.json\": {\n      \"bytes\": 305381,\n      \"sha256\": \"5e2b305ed6681abec482db258269a839c3de4bbbf9a8d9509541701fbb516fbc\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 239440,\n        \"uid\": 10484,\n        \"bytes\": 305381,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794440613,\n        \"ctime_s\": 1794440613\n      }\n    },\n    \"diagnostic-774161b299dfb95da9b6d80f2a60c1ca38e7a4b1fa9540698fc5b11d22e24677.json\": {\n      \"bytes\": 16983,\n      \"sha256\": \"e717bcbf4def54057def6b90ce5a52f86ca2270c7d14f097fa501a216c3cddd0\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 238530,\n        \"uid\": 10484,\n        \"bytes\": 16983,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794436933,\n        \"ctime_s\": 1794436933\n      }\n    },\n    \"diagnostic-80c8614b93cffb391969fe3f3ebab1a433dd5ecb102ab573feee469e5b4a5e82.json\": {\n      \"bytes\": 305381,\n      \"sha256\": \"3bc2c24b558df3c5bd248c93172b1b18027464b6506b6aa90fcae466f442d718\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 240260,\n        \"uid\": 10484,\n        \"bytes\": 305381,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794438907,\n        \"ctime_s\": 1794438907\n      }\n    },\n    \"diagnostic-839c1cc1b1d1c76a695c6a855c6323be0cda6a1f67d8e7f575028fffb3a7e78f.json\": {\n      \"bytes\": 305381,\n      \"sha256\": \"e57bacfe2d127e9805a352cb02c1ce959fe17ed01dd9663a2fc5d3083c501cc0\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 240031,\n        \"uid\": 10484,\n        \"bytes\": 305381,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794440618,\n        \"ctime_s\": 1794440618\n      }\n    },\n    \"diagnostic-84b334a0ca431d9387e45114fe4121919bb79efae43eaafef1ecc09fd3eb656d.json\": {\n      \"bytes\": 305381,\n      \"sha256\": \"41bc9473e7803d1d1374a78d840dc17d2c84d14dc3e7fb090475f670ce61dd70\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 238187,\n        \"uid\": 10484,\n        \"bytes\": 305381,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794440503,\n        \"ctime_s\": 1794440503\n      }\n    },\n    \"diagnostic-963551623468fb947925862e7eb1e6b5fda0c53ba5ed9fb2b1e474f04a6e9d86.json\": {\n      \"bytes\": 308728,\n      \"sha256\": \"9218dc03267ace444073fffb4f24db6f5ea6994e510643cd558557e4b6c2d7b8\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 239983,\n        \"uid\": 10484,\n        \"bytes\": 308728,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794446256,\n        \"ctime_s\": 1794446256\n      }\n    },\n    \"diagnostic-9aad2bf65e8bc7aa21e2aee5638694040fd88a1b47e1b9a061d726032bbb653c.json\": {\n      \"bytes\": 305381,\n      \"sha256\": \"455e1c6e287badf5b717877ab6792e87b4ac91bff9d1cf2836474225e86b6560\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 238341,\n        \"uid\": 10484,\n        \"bytes\": 305381,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794440501,\n        \"ctime_s\": 1794440501\n      }\n    },\n    \"diagnostic-bb8cf70a120986c87db41ac296f7a471441e142eca1f95a45451415c2e6d1452.json\": {\n      \"bytes\": 305381,\n      \"sha256\": \"b1d93f8d8710f22455b6ab7dfdc17f316ac0fb4a23ff62bd9f88ba5cabf7a494\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 239974,\n        \"uid\": 10484,\n        \"bytes\": 305381,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794440616,\n        \"ctime_s\": 1794440616\n      }\n    },\n    \"diagnostic-bfdc6653be17b14c965ea9d236f2e3b0d8a3c14723a332381eacc7261376752a.json\": {\n      \"bytes\": 963232,\n      \"sha256\": \"1b0305a9002f64ddbe41dc197aafff8b0ace70f668f2b608d3b76b6feb7b2dda\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 240597,\n        \"uid\": 10484,\n        \"bytes\": 963232,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794474727,\n        \"ctime_s\": 1794474727\n      }\n    },\n    \"diagnostic-c3e5c2949009203895f588c088fe97373396c5672e72c89d5284723735fab2ae.json\": {\n      \"bytes\": 63091,\n      \"sha256\": \"c4c74dda1e632fce53fbef0688583b8c28cedfa6d0462ca149cdd0ebf3628da8\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 238206,\n        \"uid\": 10484,\n        \"bytes\": 63091,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794458825,\n        \"ctime_s\": 1794458825\n      }\n    },\n    \"diagnostic-c4017cc82c05814c36b2515ca5cbb22f12d5331bf96cd43389460ec937bbffe8.json\": {\n      \"bytes\": 963233,\n      \"sha256\": \"0d2e76e387ac5e82ee5adaa0c2a17d75a9aea9e7700d707ac86ae6506b61e840\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 240557,\n        \"uid\": 10484,\n        \"bytes\": 963233,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794474727,\n        \"ctime_s\": 1794474727\n      }\n    },\n    \"diagnostic-close-1dfe5600-0db0-49a9-a145-b697ec617956.json\": {\n      \"bytes\": 1529,\n      \"sha256\": \"f4b9ce45808da1904b58d19e07f9c87cb1860bbc7315aef6a7ad89e0fe641060\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 238958,\n        \"uid\": 10484,\n        \"bytes\": 1529,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794458831,\n        \"ctime_s\": 1794458831\n      }\n    },\n    \"diagnostic-close-972509d1-f0d8-4f8b-ac09-38783d062331.json\": {\n      \"bytes\": 1708,\n      \"sha256\": \"bd72d3481e48521bcd1736d46ee25446bffa916aab118a3273ffb83ead241967\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 241826,\n        \"uid\": 10484,\n        \"bytes\": 1708,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794475894,\n        \"ctime_s\": 1794475894\n      }\n    },\n    \"diagnostic-close-c681b5ba-d88b-441c-b1ee-5dad210718cc.json\": {\n      \"bytes\": 1632,\n      \"sha256\": \"d10cedcc236d4d93114f3c3cae3515ef7dac658dca34f565f9802e86bcda4c0e\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 239478,\n        \"uid\": 10484,\n        \"bytes\": 1632,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794467234,\n        \"ctime_s\": 1794467234\n      }\n    },\n    \"diagnostic-d12138c40d118cddb742ebaa38b93944b10ecccede48565fad27f9a4e462dffa.json\": {\n      \"bytes\": 305381,\n      \"sha256\": \"0136ddd29c328a8a2866853e765337f3b50f03bddb3bb47619f2a1f0e12e5679\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 239771,\n        \"uid\": 10484,\n        \"bytes\": 305381,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794440607,\n        \"ctime_s\": 1794440607\n      }\n    },\n    \"diagnostic-e34366c697facacb44049015744abeecab23f84982963f95e4369c0f2b5cf931.json\": {\n      \"bytes\": 305381,\n      \"sha256\": \"21fe48d7cc2b7b86dafd9f0cd359f0b4eeb4f4962690b0b1cd53e2add25ec8f0\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 239642,\n        \"uid\": 10484,\n        \"bytes\": 305381,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794440614,\n        \"ctime_s\": 1794440614\n      }\n    },\n    \"diagnostic-e413cb069e3c5196bf59f929590c16f979d73703ca7194a1c3fc87373df96c49.json\": {\n      \"bytes\": 59144,\n      \"sha256\": \"3a5be3816a291ab75bef4997ce04226e9a252a8e26c1a7fcc7056c1b6c3eb009\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 241578,\n        \"uid\": 10484,\n        \"bytes\": 59144,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794431946,\n        \"ctime_s\": 1794431946\n      }\n    },\n    \"diagnostic-e94b76746ba64e1c54e2799d62814b2e3f0c3bc0185dd8a74e2496a5d29c231f.json\": {\n      \"bytes\": 305381,\n      \"sha256\": \"af3aeb11c295b62c1a47c6c5bd04993bd545a91dc7689e79ee89d7a40c17472e\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 238253,\n        \"uid\": 10484,\n        \"bytes\": 305381,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794440503,\n        \"ctime_s\": 1794440503\n      }\n    },\n    \"diagnostic-f596b99af486f258e6e100b38bc48bb35864243dcf4335bdd4fde73258053e27.json\": {\n      \"bytes\": 386724,\n      \"sha256\": \"f61fd86cb24b212c3434bb5eda1a4e29b65c06c22d3fc4238366f31a324dd7fa\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 238688,\n        \"uid\": 10484,\n        \"bytes\": 386724,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794458395,\n        \"ctime_s\": 1794458395\n      }\n    },\n    \"diagnostic-unstarted-fd01c43b-ccf1-4ebd-8579-92ed09924fe2.json\": {\n      \"bytes\": 260,\n      \"sha256\": \"3f1b4bcec3bec8e7d1a04cff0204bfb002edc0ab15464537743acabb8ada0b85\",\n      \"uid\": 10484,\n      \"stat\": {\n        \"device\": 65086,\n        \"inode\": 241042,\n        \"uid\": 10484,\n        \"bytes\": 260,\n        \"links\": 1,\n        \"mode\": 33152,\n        \"mtime_s\": 1794488567,\n        \"ctime_s\": 1794488567\n      }\n    }\n  },\"focus_before\":{\n    \"display_id\": 0,\n    \"focus_line\": \"mCurrentFocus=Window{9dbf25a u0 org.trillionnium.hepta.local/org.trillionnium.hepta.local.MainActivity}\",\n    \"focus_package\": \"org.trillionnium.hepta.local\",\n    \"focus_source\": \"dumpsys window displays: unique display 0 mCurrentFocus\"\n  },\"focus_after\":{\n    \"display_id\": 0,\n    \"focus_line\": \"mCurrentFocus=Window{9dbf25a u0 org.trillionnium.hepta.local/org.trillionnium.hepta.local.MainActivity}\",\n    \"focus_package\": \"org.trillionnium.hepta.local\",\n    \"focus_source\": \"dumpsys window displays: unique display 0 mCurrentFocus\"\n  },\"formal_binding_before\":{\n    \"verified\": true,\n    \"component\": \"org.trillionnium.hepta.local/org.trillionnium.hepta.local.HeptaAccessibilityService\",\n    \"app_pid\": 31544,\n    \"app_uid\": 10481,\n    \"client_pid\": 3622,\n    \"client_uid\": 1000,\n    \"binder_received\": true,\n    \"has_bound\": true,\n    \"connection_ids\": [\n      \"f7fe27c\"\n    ],\n    \"service_dump_sha256\": \"9721d5865277d468ad3f6e2fb865f59c9a52d7364f5b513964a5999801a4c6a8\",\n    \"identity_scope\": \"exact active AMS ServiceRecord and live system-client binding; label-only AccessibilityManager rows are not component attestation\"\n  },\"formal_binding_after\":{\n    \"verified\": true,\n    \"component\": \"org.trillionnium.hepta.local/org.trillionnium.hepta.local.HeptaAccessibilityService\",\n    \"app_pid\": 31544,\n    \"app_uid\": 10481,\n    \"client_pid\": 3622,\n    \"client_uid\": 1000,\n    \"binder_received\": true,\n    \"has_bound\": true,\n    \"connection_ids\": [\n      \"f7fe27c\"\n    ],\n    \"service_dump_sha256\": \"24b4ca7e3c8e5fb87b292207bbc31ffa5895079d6134eadb20776e0022920088\",\n    \"identity_scope\": \"exact active AMS ServiceRecord and live system-client binding; label-only AccessibilityManager rows are not component attestation\"\n  }}")
HELPER6_EXPECTED_IDENTITY = json.loads("{\n    \"package\": \"org.trillionnium.hepta.webhelper\",\n    \"uid\": 10484,\n    \"apks\": [\n      {\n        \"path\": \"/data/app/~~iuCpyfrLdnn2FSYG4ZOcYQ==/org.trillionnium.hepta.webhelper-LMxwSbN_9UdoiNCifY0iXw==/base.apk\",\n        \"sha256\": \"02360c24c471dcd4be0cbc7c7fdb316a7918d656edd1407d765540b5a3f2f5ff\"\n      }\n    ]\n  }")
HELPER6_RECONCILIATION_SOURCE = {"path":"/home/alex/hepta-local-007f-20261111/reconcile_helper6_postinstall_r1.py","bytes":90022,"sha256":"046cd794e66c0136d09bf55b88c09b9d21e5b023d1223454c7c7c2b4208a2f49"}
HELPER6_FAILED_INSTALL_RESULT = {"path":"/home/alex/hepta-local-007f-20261111/v55-web-helper-code6-upgrade-r1/RESULT.json","bytes":33072,"sha256":"d6afb1f04481f969b88ea641abbdd69541e72bbde6bd770038912caf533d1ad2"}

PROFILE_HELPER_SHA = "411f41f5e4836cc6014011d1d26cf1bdcfe5c8573fdf6591c24d7b1a29ca83f1"
CERT = "202d00f853589c753069189086e0c76cb308d11745c33e70200985e4de3129d5"
PREFERENCES_PATH = "shared_prefs/background-ui-choice-v1.xml"
MOBI_PIN_SOURCE = "src/org/trillionnium/hepta/local/MobiMindPins.java"
MOBI_PIN_SOURCE_SHA = "2f7117fd3234d514775717eef9bf04a67e347f809a93a1f34623e62a8b7a552e"
MOBI_DIRECTORY = "files/model/mobimind-1.5-2b-w8a8-0717-f02848b6"
OLD_IMPORT_PART = "files/model/.LFM2.5-8B-A1B-Q4_0.gguf.import-code22-20261109-r2-fc8792d2.part"
OLD_IMPORT_BYTES = 4844678368
OLD_IMPORT_SHA = "48ed1465d761311b2fd57b7fb46cf969a20b3a8281945b04e10f52bd1609e715"
HISTORICAL_CURRENT = json.loads("{\"schema\":\"hepta.current-flight-failed-upgrade-baseline.v1\",\"result\":{\"path\":\"/home/alex/hepta-local-007f-20261111/background-web-v54-lfm3-flight-r1/RESULT.json\",\"bytes\":56378,\"sha256\":\"6881749bc9429b4ce1332353ecd67fe2d524ae19b14349a1208a08b9b41195d7\"},\"collection\":{\"path\":\"/home/alex/hepta-local-007f-20261111/background-web-v54-lfm3-flight-r1/COLLECTION.json\",\"bytes\":25668,\"sha256\":\"642b7136d7d1ba94701c004615ef1024a0ae87eb0d701505df87deca87f502f0\"},\"unstarted\":{\"path\":\"/home/alex/hepta-local-007f-20261111/background-web-v54-lfm3-flight-r1/evidence/helper/diagnostic-unstarted-fd01c43b-ccf1-4ebd-8579-92ed09924fe2.json\",\"bytes\":260,\"sha256\":\"3f1b4bcec3bec8e7d1a04cff0204bfb002edc0ab15464537743acabb8ada0b85\"},\"main_identity\":{\"package\":\"org.trillionnium.hepta.local\",\"uid\":10481,\"apks\":[{\"path\":\"/data/app/~~hQX6r7v5s_gKn7o8ImvScQ==/org.trillionnium.hepta.local-PNZseE9N9jPiez75ykUSRA==/base.apk\",\"sha256\":\"0729f54704a058049e12041c7f901b1b6650924500663cf9952a03d6a33a8b8a\"}]},\"helper_identity\":{\"package\":\"org.trillionnium.hepta.webhelper\",\"uid\":10484,\"apks\":[{\"path\":\"/data/app/~~7tm-0viTiSPtMXQrKQNE5A==/org.trillionnium.hepta.webhelper-FzFUV5CCtZ60uGZ1qVOzWg==/base.apk\",\"sha256\":\"b5e56ce0c2967489b55150c157f8289fdd82ad5b89caacc8b106013a7caeaf4f\"}]},\"task_id\":\"3c90bb05c4974a8980655fd254fc933e\",\"session_sha256\":\"bae493e3556ba59351c9f9aabcf01e78e5f1c9bd52c9fb69ba536dd4c2db3123\",\"task_result_sha256\":\"4144b8b44cbb478c54c1db8e9a01bd80f5aa7e7e4fddc8bb3a7473ef22422302\",\"prefs_sha256\":\"c9364dde8c0b52e7890835d720967987f708e972b397fcc3f76d9d76a667137f\",\"config_sha256\":\"b1fa9a0f9f23562b667217063ce491eeb5bfe489f3dd45044d1ae733e2056ef2\",\"helper_count\":37,\"expected_session\":{\"schema\":\"hepta.local-session.v1\",\"status\":\"failed\",\"task_id\":\"3c90bb05c4974a8980655fd254fc933e\",\"origin\":\"user_button\",\"instruction_sha256\":\"868050b2cd0f02abb963559bbe60afcdfea9a0e2be5e62d06ba6f354f85ad2ee\",\"task_authorization_sha256\":\"7362e28a99e174f17c45f4070472c883a033c9bfcb9446f1cc19e2221e1edacc\",\"task_authorization\":{\"schema\":\"hepta.owner-task-authorization.v1\",\"parser\":\"hepta.owner-tool-clauses.zh.v4-fixed-intents+natural-flight-ceiling.v1\",\"instruction_sha256\":\"868050b2cd0f02abb963559bbe60afcdfea9a0e2be5e62d06ba6f354f85ad2ee\",\"authorization_sha256\":\"7362e28a99e174f17c45f4070472c883a033c9bfcb9446f1cc19e2221e1edacc\",\"allowed_tools\":[\"back\",\"click\",\"done\",\"open\",\"scroll\",\"submit\",\"type\",\"wait\"],\"require_find_app_before_open\":false,\"find_query\":null,\"recognized_rules\":[\"natural_public_flight_tool_ceiling.v1\"],\"arbitrary_semantic_constraints_verified\":false},\"background_request\":{\"mode\":\"background\",\"allowed_packages\":[\"org.trillionnium.hepta.webhelper\"],\"bootstrap_package\":\"org.trillionnium.hepta.webhelper\",\"bootstrap_source\":\"owner_intent_within_explicit_ui_selection\",\"bootstrap_model_issued\":false,\"main_display_fallback\":false,\"home_allowed\":false,\"owner_task_selection\":{\"schema\":\"hepta.owner-task-app-selection.v1\",\"owner_sha256\":\"868050b2cd0f02abb963559bbe60afcdfea9a0e2be5e62d06ba6f354f85ad2ee\",\"recognition\":\"natural_explicit_date_single_adult_flight_query.v1\",\"original_ui_initial_package\":\"com.motorola.stylus\",\"original_ui_allowed_packages\":[\"com.motorola.stylus\",\"org.trillionnium.hepta.webhelper\"],\"effective_initial_package\":\"org.trillionnium.hepta.webhelper\",\"effective_allowed_packages\":[\"org.trillionnium.hepta.webhelper\"],\"effective_scope_within_selected_apps\":true,\"effective_scope_strictly_smaller\":true,\"initial_app_changed\":true,\"package_from_model_or_screen\":false,\"grants_tool_authority\":false,\"changes_saved_preferences\":false}},\"background_lease_unreleased\":false,\"web_helper_lease_unreleased\":false,\"debug_nonce_sha256\":null,\"expected_scope_sha256\":null,\"actual_scope_sha256\":null,\"state\":\"regular immutable APK required\",\"pending\":false,\"running\":false,\"blocked\":false,\"cleanup_known\":true,\"app_uid\":10481,\"updated_wall_ms\":1794488567931,\"external_model\":false,\"automatic_resume\":false,\"goal_independently_verified\":false,\"evidence_directory\":\"/data/data/org.trillionnium.hepta.local/files/control-tasks/3c90bb05c4974a8980655fd254fc933e\",\"model_reported_success\":false,\"steps\":0,\"completion_verified\":false,\"completion_evidence\":{\"schema\":\"hepta.task-completion.v1\",\"kind\":\"web_search_results\",\"owner_sha256\":\"868050b2cd0f02abb963559bbe60afcdfea9a0e2be5e62d06ba6f354f85ad2ee\",\"contract_sha256\":\"8c6d1341ad84a376fd8c87daf7dbb05761a5c1f6b134d601480b1f2f49d418a2\",\"source\":\"controller_observation_checks_not_model_claims\",\"completion_verified\":false,\"missing\":[\"model_bound_web_query_dispatch_missing\",\"actual_same_record_flight_results_not_yet_verified\"],\"rejected_success_claims\":0,\"max_rejected_success_claims\":2,\"web_query_dispatched\":false,\"writes_required_for_unknown_or_read_only_goal\":false,\"grants_tool_authority\":false,\"task_id\":\"3c90bb05c4974a8980655fd254fc933e\",\"contract\":{\"schema\":\"hepta.task-completion.v1\",\"kind\":\"web_search_results\",\"owner_sha256\":\"868050b2cd0f02abb963559bbe60afcdfea9a0e2be5e62d06ba6f354f85ad2ee\",\"contract_sha256\":\"8c6d1341ad84a376fd8c87daf7dbb05761a5c1f6b134d601480b1f2f49d418a2\",\"recognition\":\"natural_csair_flight_owner.v1\",\"expected_body_sha256\":null,\"source\":\"immutable_owner_contract\",\"model_may_change_goal\":false,\"grants_tool_authority\":false},\"proofs\":[],\"model_success_claims\":[],\"identity_failure\":null,\"display_id\":null,\"background_generation\":null,\"persistent_storage_bytes_verified\":false,\"new_database_item_identity_verified\":false,\"observation_chain_verified\":false,\"terminal_binding_and_cleanup_verified\":false,\"completion_actor\":null,\"model_done_synthesized\":false,\"controller_completion_requested\":false,\"controller_native_parent_session_bound\":null}},\"expected_helper_inventory\":{\"diagnostic-020c1d13a67d132eed6874ba43cf0d6f35cd473c095e94f890ac6bc2e6b2667f.json\":{\"bytes\":30993,\"sha256\":\"386f86ef76923ce994574893bc05eec906f3ef839f32d8a77a68092e0115d986\",\"uid\":10484},\"diagnostic-0e8377e803ac9a467c4a5cb52e5937a15a6a93b43f7934bcaebeedba84b689fc.json\":{\"bytes\":308739,\"sha256\":\"96aecf073ee65951c988a5710fea394713e64af161f0513e36ee2d539991ebc3\",\"uid\":10484},\"diagnostic-200d1eb4031744b38d899525241af8f89643659ed769590d5cf4614cc0f376c5.json\":{\"bytes\":305357,\"sha256\":\"ffe2b5a4cf79e12098abafdc63a006583f9eaddb7f786671bcf1d03bc03e4f83\",\"uid\":10484},\"diagnostic-2185104639ec2e909a3eb0241b33d7f2714925010d63223c7e6509f4ec8c660b.json\":{\"bytes\":305381,\"sha256\":\"4d41342931181e4a208439b0dab4766d25d9d0b2e0bd08d5a24c420cae99f969\",\"uid\":10484},\"diagnostic-260f603251c34639addc7c70fea84f3bcf676e12d373bdaa69f43d6c9fbe3f46.json\":{\"bytes\":305386,\"sha256\":\"f716aaac6fd44a1015a1f6f1d61b4a0fb2efdda433b3fddcce684840fe103ea9\",\"uid\":10484},\"diagnostic-292f3f81694870ce87b987a04046ccb48e0b3cd6b11813b24f014a5f6a5cccea.json\":{\"bytes\":308752,\"sha256\":\"b5d351b711eac0b70c7458bc0c1f3f52c4e5d4f9e8e0a3b35a9e2529585adf22\",\"uid\":10484},\"diagnostic-342e51e1e6c5fac683309de2758c0586b1bff94816565a36c127ae276cade8fb.json\":{\"bytes\":61927,\"sha256\":\"5a34609ecb6965fac2e2525673583ac9f5bcc38652f674d81b8090f5dc17cf57\",\"uid\":10484},\"diagnostic-3534609dabda0ed5ee97004cdf586290d34aacb8a51857e109007dfbc0911500.json\":{\"bytes\":305381,\"sha256\":\"27b9eddd923d7efb44e3eabebe87b503e63869c84a8074ba4ecce53a553db806\",\"uid\":10484},\"diagnostic-361c2e19f1f7b8b606ada953ce8764a08d3c97b859d1d5d56a2cbab4cd113b55.json\":{\"bytes\":305381,\"sha256\":\"17ffb325c0ae0ebfd4186c21e1d07ce0ae6110bd6c7392a477cd983622831fc8\",\"uid\":10484},\"diagnostic-3c8fb015d9749da98ed615aab0a6d0d6315b45b9836b92b6ca4d40bb1cf35e16.json\":{\"bytes\":309230,\"sha256\":\"383622b7853d7e39d870c08522ed7287760de6d9b18cdc8ae08230a23c8afbb3\",\"uid\":10484},\"diagnostic-4d769f772d5eaf8fa7128b3c7f3a7e5ccc978c535a185e602b9747a81adcdea5.json\":{\"bytes\":308216,\"sha256\":\"cc2e3cdef57f3adcd4e64779e6ff827c1586e9e0b2d15737db808441856dffc9\",\"uid\":10484},\"diagnostic-4edc3ac8e659e5438cd1ff507c370b6f34a899e0ce8391af67809996e66e6547.json\":{\"bytes\":63083,\"sha256\":\"737a08eef8ccca27b42b11900daa5182cf27b538bafd275dad9fcbd23530d416\",\"uid\":10484},\"diagnostic-53ddffb0458add0e7c1faf8fe6a090a5640a9ef3db51904199d2d9fa946d45b3.json\":{\"bytes\":308752,\"sha256\":\"0861ac8b133b636478364f3957eed71391dd63e79e4b29530538fbaaafb31136\",\"uid\":10484},\"diagnostic-5988650db5f7f527be3c7e4e8ea17b3fa7d9d6158e020178f218bfd2da0a0019.json\":{\"bytes\":305381,\"sha256\":\"74bac5bde381e25e4af3978e9184c3d2f70331a7c2ad943c7845b62511a532f3\",\"uid\":10484},\"diagnostic-5d1be4c0d35bdebf71644cde85a6e5284c11933ab08286070abb99ce332620e4.json\":{\"bytes\":305699,\"sha256\":\"6535ad2d33943cb0e55fba533fca0c172a6f27b1a18e255d783f2fb02c34598a\",\"uid\":10484},\"diagnostic-612297bc8413908925c112255fcbda05a294ca746122db1fc9b50c7e05999c88.json\":{\"bytes\":305381,\"sha256\":\"05c2064dc1fce4c42c516d3d0e2c4a76f86e69b1e2fbe31149d0b99505c24bfc\",\"uid\":10484},\"diagnostic-6926d45f605fe7e01b4060920f868da64534095f0601bc5ea648da9de669d20b.json\":{\"bytes\":309579,\"sha256\":\"60d2c114cf1dd29dc77bace83afff6f991e9423bf01e5e93298ba5f4a7601328\",\"uid\":10484},\"diagnostic-6f948b0dfff7afd85b17de1f34cbe3a4efafd7d77c1339788cd570cc192ba2bf.json\":{\"bytes\":305381,\"sha256\":\"5e2b305ed6681abec482db258269a839c3de4bbbf9a8d9509541701fbb516fbc\",\"uid\":10484},\"diagnostic-774161b299dfb95da9b6d80f2a60c1ca38e7a4b1fa9540698fc5b11d22e24677.json\":{\"bytes\":16983,\"sha256\":\"e717bcbf4def54057def6b90ce5a52f86ca2270c7d14f097fa501a216c3cddd0\",\"uid\":10484},\"diagnostic-80c8614b93cffb391969fe3f3ebab1a433dd5ecb102ab573feee469e5b4a5e82.json\":{\"bytes\":305381,\"sha256\":\"3bc2c24b558df3c5bd248c93172b1b18027464b6506b6aa90fcae466f442d718\",\"uid\":10484},\"diagnostic-839c1cc1b1d1c76a695c6a855c6323be0cda6a1f67d8e7f575028fffb3a7e78f.json\":{\"bytes\":305381,\"sha256\":\"e57bacfe2d127e9805a352cb02c1ce959fe17ed01dd9663a2fc5d3083c501cc0\",\"uid\":10484},\"diagnostic-84b334a0ca431d9387e45114fe4121919bb79efae43eaafef1ecc09fd3eb656d.json\":{\"bytes\":305381,\"sha256\":\"41bc9473e7803d1d1374a78d840dc17d2c84d14dc3e7fb090475f670ce61dd70\",\"uid\":10484},\"diagnostic-963551623468fb947925862e7eb1e6b5fda0c53ba5ed9fb2b1e474f04a6e9d86.json\":{\"bytes\":308728,\"sha256\":\"9218dc03267ace444073fffb4f24db6f5ea6994e510643cd558557e4b6c2d7b8\",\"uid\":10484},\"diagnostic-9aad2bf65e8bc7aa21e2aee5638694040fd88a1b47e1b9a061d726032bbb653c.json\":{\"bytes\":305381,\"sha256\":\"455e1c6e287badf5b717877ab6792e87b4ac91bff9d1cf2836474225e86b6560\",\"uid\":10484},\"diagnostic-bb8cf70a120986c87db41ac296f7a471441e142eca1f95a45451415c2e6d1452.json\":{\"bytes\":305381,\"sha256\":\"b1d93f8d8710f22455b6ab7dfdc17f316ac0fb4a23ff62bd9f88ba5cabf7a494\",\"uid\":10484},\"diagnostic-bfdc6653be17b14c965ea9d236f2e3b0d8a3c14723a332381eacc7261376752a.json\":{\"bytes\":963232,\"sha256\":\"1b0305a9002f64ddbe41dc197aafff8b0ace70f668f2b608d3b76b6feb7b2dda\",\"uid\":10484},\"diagnostic-c3e5c2949009203895f588c088fe97373396c5672e72c89d5284723735fab2ae.json\":{\"bytes\":63091,\"sha256\":\"c4c74dda1e632fce53fbef0688583b8c28cedfa6d0462ca149cdd0ebf3628da8\",\"uid\":10484},\"diagnostic-c4017cc82c05814c36b2515ca5cbb22f12d5331bf96cd43389460ec937bbffe8.json\":{\"bytes\":963233,\"sha256\":\"0d2e76e387ac5e82ee5adaa0c2a17d75a9aea9e7700d707ac86ae6506b61e840\",\"uid\":10484},\"diagnostic-close-1dfe5600-0db0-49a9-a145-b697ec617956.json\":{\"bytes\":1529,\"sha256\":\"f4b9ce45808da1904b58d19e07f9c87cb1860bbc7315aef6a7ad89e0fe641060\",\"uid\":10484},\"diagnostic-close-972509d1-f0d8-4f8b-ac09-38783d062331.json\":{\"bytes\":1708,\"sha256\":\"bd72d3481e48521bcd1736d46ee25446bffa916aab118a3273ffb83ead241967\",\"uid\":10484},\"diagnostic-close-c681b5ba-d88b-441c-b1ee-5dad210718cc.json\":{\"bytes\":1632,\"sha256\":\"d10cedcc236d4d93114f3c3cae3515ef7dac658dca34f565f9802e86bcda4c0e\",\"uid\":10484},\"diagnostic-d12138c40d118cddb742ebaa38b93944b10ecccede48565fad27f9a4e462dffa.json\":{\"bytes\":305381,\"sha256\":\"0136ddd29c328a8a2866853e765337f3b50f03bddb3bb47619f2a1f0e12e5679\",\"uid\":10484},\"diagnostic-e34366c697facacb44049015744abeecab23f84982963f95e4369c0f2b5cf931.json\":{\"bytes\":305381,\"sha256\":\"21fe48d7cc2b7b86dafd9f0cd359f0b4eeb4f4962690b0b1cd53e2add25ec8f0\",\"uid\":10484},\"diagnostic-e413cb069e3c5196bf59f929590c16f979d73703ca7194a1c3fc87373df96c49.json\":{\"bytes\":59144,\"sha256\":\"3a5be3816a291ab75bef4997ce04226e9a252a8e26c1a7fcc7056c1b6c3eb009\",\"uid\":10484},\"diagnostic-e94b76746ba64e1c54e2799d62814b2e3f0c3bc0185dd8a74e2496a5d29c231f.json\":{\"bytes\":305381,\"sha256\":\"af3aeb11c295b62c1a47c6c5bd04993bd545a91dc7689e79ee89d7a40c17472e\",\"uid\":10484},\"diagnostic-f596b99af486f258e6e100b38bc48bb35864243dcf4335bdd4fde73258053e27.json\":{\"bytes\":386724,\"sha256\":\"f61fd86cb24b212c3434bb5eda1a4e29b65c06c22d3fc4238366f31a324dd7fa\",\"uid\":10484},\"diagnostic-unstarted-fd01c43b-ccf1-4ebd-8579-92ed09924fe2.json\":{\"bytes\":260,\"sha256\":\"3f1b4bcec3bec8e7d1a04cff0204bfb002edc0ab15464537743acabb8ada0b85\",\"uid\":10484}},\"expected_task_files\":[{\"path\":\"/home/alex/hepta-local-007f-20261111/background-web-v54-lfm3-flight-r1/evidence/task/background-binding.json\",\"bytes\":2007,\"sha256\":\"b5da077af167cdf1a5bbb7287f69cea9f46cca8c0e54810f19b5a2779a06d37d\",\"package\":\"org.trillionnium.hepta.local\",\"device_path\":\"files/control-tasks/3c90bb05c4974a8980655fd254fc933e/background-binding.json\",\"relative_path\":\"background-binding.json\"},{\"path\":\"/home/alex/hepta-local-007f-20261111/background-web-v54-lfm3-flight-r1/evidence/task/background-bootstrap.json\",\"bytes\":6591,\"sha256\":\"3739f30a871ff5a0498ea320c4a4bb1cbe2397b730ed2ffcb4c7527c25db19eb\",\"package\":\"org.trillionnium.hepta.local\",\"device_path\":\"files/control-tasks/3c90bb05c4974a8980655fd254fc933e/background-bootstrap.json\",\"relative_path\":\"background-bootstrap.json\"},{\"path\":\"/home/alex/hepta-local-007f-20261111/background-web-v54-lfm3-flight-r1/evidence/task/background-broker-06f4fb29-94fc-4f1c-b481-3f7188e21bba.bin\",\"bytes\":185,\"sha256\":\"d6082b22ee81acccb2764c34dcae743c9dd20daf12bff12c7a3ddf353759e6d4\",\"package\":\"org.trillionnium.hepta.local\",\"device_path\":\"files/control-tasks/3c90bb05c4974a8980655fd254fc933e/background-broker-06f4fb29-94fc-4f1c-b481-3f7188e21bba.bin\",\"relative_path\":\"background-broker-06f4fb29-94fc-4f1c-b481-3f7188e21bba.bin\"},{\"path\":\"/home/alex/hepta-local-007f-20261111/background-web-v54-lfm3-flight-r1/evidence/task/background-broker-06f4fb29-94fc-4f1c-b481-3f7188e21bba.json\",\"bytes\":851,\"sha256\":\"ca922d34cab447a463327a2d72d8d612e0b55f58298d755f1a538b8370fd17e9\",\"package\":\"org.trillionnium.hepta.local\",\"device_path\":\"files/control-tasks/3c90bb05c4974a8980655fd254fc933e/background-broker-06f4fb29-94fc-4f1c-b481-3f7188e21bba.json\",\"relative_path\":\"background-broker-06f4fb29-94fc-4f1c-b481-3f7188e21bba.json\"},{\"path\":\"/home/alex/hepta-local-007f-20261111/background-web-v54-lfm3-flight-r1/evidence/task/background-cleanup.json\",\"bytes\":5226,\"sha256\":\"fdd2b22d6988952fdf3976f825812fe3f7a40e2e10444d91461b2a67f32a147d\",\"package\":\"org.trillionnium.hepta.local\",\"device_path\":\"files/control-tasks/3c90bb05c4974a8980655fd254fc933e/background-cleanup.json\",\"relative_path\":\"background-cleanup.json\"},{\"path\":\"/home/alex/hepta-local-007f-20261111/background-web-v54-lfm3-flight-r1/evidence/task/owner.json\",\"bytes\":4180,\"sha256\":\"0bf4ebde88b229c7913da452f3d68df2371263f4ffd4dde00e116427b98da95c\",\"package\":\"org.trillionnium.hepta.local\",\"device_path\":\"files/control-tasks/3c90bb05c4974a8980655fd254fc933e/owner.json\",\"relative_path\":\"owner.json\"},{\"path\":\"/home/alex/hepta-local-007f-20261111/background-web-v54-lfm3-flight-r1/evidence/task/result.json\",\"bytes\":16136,\"sha256\":\"4144b8b44cbb478c54c1db8e9a01bd80f5aa7e7e4fddc8bb3a7473ef22422302\",\"package\":\"org.trillionnium.hepta.local\",\"device_path\":\"files/control-tasks/3c90bb05c4974a8980655fd254fc933e/result.json\",\"relative_path\":\"result.json\"},{\"path\":\"/home/alex/hepta-local-007f-20261111/background-web-v54-lfm3-flight-r1/evidence/task/scope-binding.json\",\"bytes\":1203,\"sha256\":\"6a1effab5ff10d293f5a3d4c1726276c84960374f64d3496e89dce04d7583cc4\",\"package\":\"org.trillionnium.hepta.local\",\"device_path\":\"files/control-tasks/3c90bb05c4974a8980655fd254fc933e/scope-binding.json\",\"relative_path\":\"scope-binding.json\"}]}")
PREVIOUS_FLIGHT55 = json.loads("{\"schema\":\"hepta.current-flight55-failed-upgrade-baseline.v1\",\"result\":{\"path\":\"/home/alex/hepta-local-007f-20261111/background-web-v55-lfm3-flight-r1/RESULT.json\",\"bytes\":38514,\"sha256\":\"708b724edf3e459a43f4e9aafc9cb3670d6aa9e1f6511e572f7aa0725143d46f\"},\"collection\":{\"path\":\"/home/alex/hepta-local-007f-20261111/background-web-v55-lfm3-flight-r1/COLLECTION.json\",\"bytes\":80655,\"sha256\":\"a4b81a3cbd8cc9cefe6c411f36171c933eaf371d8c407ae9a5ec555c14e634a6\"},\"capture_index\":{\"path\":\"/home/alex/hepta-local-007f-20261111/background-web-v55-lfm3-flight-r1/CAPTURE-RAW-INDEX.json\",\"bytes\":12077,\"sha256\":\"921b9c538b6d709c997c3fc43dc76d00ccc87e569093103b9419a1f24a6f8ed5\"},\"evidence_directory\":\"/home/alex/hepta-local-007f-20261111/background-web-v55-lfm3-flight-r1/evidence\",\"task_id\":\"6dfcaf6cbb3f4252b472f9cf6f80b5cc\",\"session_sha256\":\"a98539b93542b71fc4b89dbad5c60d6e971254c85adaf1a30af63f7a0f2b4652\",\"task_result_sha256\":\"616cf5d0ee9e05779959784bea51200f0e16e431c66747122a463452a39bbe3a\",\"prefs_sha256\":\"c9364dde8c0b52e7890835d720967987f708e972b397fcc3f76d9d76a667137f\",\"config_sha256\":\"b1fa9a0f9f23562b667217063ce491eeb5bfe489f3dd45044d1ae733e2056ef2\",\"main_identity\":{\"package\":\"org.trillionnium.hepta.local\",\"uid\":10481,\"apks\":[{\"path\":\"/data/app/~~ydmcznFzr59wjiXBKk_ZDQ==/org.trillionnium.hepta.local-PHrugxpSPRrvNXFBFIs7Cg==/base.apk\",\"sha256\":\"ea485e6d28544d75a9010e441aae8df348d1b64884f9ff7a50cb909a3f8ea45e\"}]},\"helper_identity\":{\"package\":\"org.trillionnium.hepta.webhelper\",\"uid\":10484,\"apks\":[{\"path\":\"/data/app/~~iuCpyfrLdnn2FSYG4ZOcYQ==/org.trillionnium.hepta.webhelper-LMxwSbN_9UdoiNCifY0iXw==/base.apk\",\"sha256\":\"02360c24c471dcd4be0cbc7c7fdb316a7918d656edd1407d765540b5a3f2f5ff\"}]},\"expected_status\":\"failed\",\"expected_state\":\"画面连续变化，已停止操作以免点错目标\",\"expected_steps\":3,\"helper_count\":46,\"task_file_count\":75,\"model_file_count\":31,\"request_ids\":[\"07218943e8624c3abda03e090a64d7a9\",\"09fd767ef57f4056a6b6a0999cdfd4d0\",\"01158f07052341d6af6a47e7eb447aaf\"],\"parent_generation\":\"c84accb2d1b54d89a13fffbd32317cd3\",\"formal_helper_record_names\":[\"capture-5a26fffdc6ac42a79ec5279d82e4abb5764689dc95424b37931a2e408a3293dd.json\",\"capture-5e3cbc7e753640e0a04800414709507e69d51a30bc8143f992b0c211bb836eb8.json\",\"capture-626cbed43019410e901b0d68d516a51e7df789fff6794d5bba39041d760a9cf2.json\",\"capture-6ec921bc5f764229a177da8acaee9353287437479ae64305807c8717c9e2b57d.json\",\"capture-8e83b31ce2fd43b79d7df3d170db1c88fd0dd09f8b4b4d539be27d6526454ac9.json\",\"capture-b4e19734a7d544df93e0d22bbffb266ea720947f797b46de9dc7e00500ec9383.json\",\"close-73419c48-dfd3-42f9-ac4f-a359e36a080f.json\",\"close-dc627a3c-d35d-463e-ae7d-c7dcf0c485c2.json\",\"lease-journal.json\"]}")
MAIN56_INSTALL_SOURCE = json.loads("{\"path\":\"/home/alex/hepta-local-007f-20261111/install_v56_idle_r1.py\",\"bytes\":181990,\"sha256\":\"a5dfa14be81683dbe6bdc716105a861389e674e914842f41487dfad97f2512ba\"}")
MAIN56_INSTALL_RESULT = json.loads("{\"path\":\"/home/alex/hepta-local-007f-20261111/phone-install-v56-r1/RESULT.json\",\"bytes\":120757,\"sha256\":\"8425e9788a927e3c646f0630482c7fbd9cc5ef00990a73a625ee9c0b0cd87db6\"}")
WEB56_SUPPORT = json.loads("{\"path\":\"/home/alex/hepta-local-007f-20261111/background-web-adapters-v56-r1/web_entry_support.py\",\"bytes\":70091,\"sha256\":\"40bd9c3d4d6b600396cabc15635688c53c520fc3cec2f9aff19abecdc4af8cde\"}")
HELPER_CURRENT = json.loads("{\"task_id\":\"11f5735392b2402495a19e1ed5474d13\",\"result\":{\"path\":\"/home/alex/hepta-local-007f-20261111/background-web-v56-lfm3-flight-r1/RESULT.json\",\"bytes\":32719,\"sha256\":\"392f239be032c6c45d048222bc0d3cc7003ed03dc7d193a07e3c504f3fb0da52\"},\"collection\":{\"path\":\"/home/alex/hepta-local-007f-20261111/background-web-v56-lfm3-flight-r1/COLLECTION.json\",\"bytes\":56496,\"sha256\":\"5a1c0bf3906b5432288471d7750fdf934df18f4829de62a269d6dbb02d9e5d44\"},\"capture_index\":{\"path\":\"/home/alex/hepta-local-007f-20261111/background-web-v56-lfm3-flight-r1/CAPTURE-RAW-INDEX.json\",\"bytes\":4221,\"sha256\":\"0a83307e1d5ac266b3553f28c1583c498b7a89a017039260f34538480293c9a3\"},\"evidence_directory\":\"/home/alex/hepta-local-007f-20261111/background-web-v56-lfm3-flight-r1/evidence\",\"session_sha256\":\"c72c1a6c018968409ad43e60f5459bce4aab5faee83405cd49185f2e70898d1e\",\"task_result_sha256\":\"821b67811eb7a7f4cae632d05bc844b40360d525344ed10e6c72634f288a83d6\",\"expected_status\":\"failed\",\"expected_state\":\"AX/DOM bracket changed; no current page capability published\",\"expected_steps\":1,\"request_ids\":[\"b5c52bd3c04044f28108aa9001772e9f\"],\"parent_generation\":\"df4b2c9dcefa44f1918bb285e2da17ba\",\"task_file_count\":41,\"model_file_count\":13,\"helper_count\":50,\"config_sha256\":\"b1fa9a0f9f23562b667217063ce491eeb5bfe489f3dd45044d1ae733e2056ef2\",\"prefs_sha256\":\"c9364dde8c0b52e7890835d720967987f708e972b397fcc3f76d9d76a667137f\",\"main_identity\":{\"package\":\"org.trillionnium.hepta.local\",\"uid\":10481,\"apks\":[{\"path\":\"/data/app/~~kjtm2QzruYL9-aUBXFIlQw==/org.trillionnium.hepta.local-UnoGsU3bLEhG5iG5r16jHA==/base.apk\",\"sha256\":\"067ab5a286b100404fa2b00e341964cd70f005907988dc11eb486c9a4b3bab62\"}]},\"helper_identity\":{\"package\":\"org.trillionnium.hepta.webhelper\",\"uid\":10484,\"apks\":[{\"path\":\"/data/app/~~iuCpyfrLdnn2FSYG4ZOcYQ==/org.trillionnium.hepta.webhelper-LMxwSbN_9UdoiNCifY0iXw==/base.apk\",\"sha256\":\"02360c24c471dcd4be0cbc7c7fdb316a7918d656edd1407d765540b5a3f2f5ff\"}]},\"formal_helper_record_names\":[\"capture-5a26fffdc6ac42a79ec5279d82e4abb5764689dc95424b37931a2e408a3293dd.json\",\"capture-5e3cbc7e753640e0a04800414709507e69d51a30bc8143f992b0c211bb836eb8.json\",\"capture-626cbed43019410e901b0d68d516a51e7df789fff6794d5bba39041d760a9cf2.json\",\"capture-6ec921bc5f764229a177da8acaee9353287437479ae64305807c8717c9e2b57d.json\",\"capture-8e83b31ce2fd43b79d7df3d170db1c88fd0dd09f8b4b4d539be27d6526454ac9.json\",\"capture-95e2b067dfe243fd86d5a6771057e5b2429f777826b34bb298e5652ea17754eb.json\",\"capture-b4e19734a7d544df93e0d22bbffb266ea720947f797b46de9dc7e00500ec9383.json\",\"capture-c57b83ee6f8446efb5b80b6d7a6e4043ce026faa78414c5ba2e58128a621c03b.json\",\"close-73419c48-dfd3-42f9-ac4f-a359e36a080f.json\",\"close-ac33261d-e73b-4a21-8592-c3a48cb0d0a6.json\",\"close-ce67bd37-8341-4b67-87f3-187ca49a3aba.json\",\"close-dc627a3c-d35d-463e-ae7d-c7dcf0c485c2.json\",\"lease-journal.json\"]}")
CURRENT = json.loads("{\"task_id\":\"bb16d934fabe4dc7818289d55be113ac\",\"result\":{\"path\":\"/home/alex/hepta-local-007f-20261111/background-notes-v56-lfm3-recovery-r1/RESULT.json\",\"bytes\":147387,\"sha256\":\"4f321b5d1ac7265cdff90e090d255076b7cfcd598ada5909eaf2c953619d3a38\"},\"evidence_directory\":\"/home/alex/hepta-local-007f-20261111/background-notes-v56-lfm3-recovery-r1/evidence\",\"session_sha256\":null,\"session_pin_source\":\"first stable device read after exact typed binding to the pinned Recovery56 last_session\",\"task_result_sha256\":\"7d9b6a2149336c488eee85f2273ce24a90c22d686aa138f86321c93447fe134c\",\"expected_status\":\"controller_verified_done\",\"expected_state\":\"已保存并重新打开这条笔记，正文核对一致。\",\"expected_steps\":1,\"request_ids\":[\"2d30769b2d9249aea0629794e88aabb1\"],\"parent_generation\":\"1c4181b08b9048ce96e955e2310fa94f\",\"task_file_count\":44,\"model_file_count\":12,\"helper_count\":50,\"config_sha256\":\"b1fa9a0f9f23562b667217063ce491eeb5bfe489f3dd45044d1ae733e2056ef2\",\"prefs_sha256\":\"c9364dde8c0b52e7890835d720967987f708e972b397fcc3f76d9d76a667137f\",\"main_identity\":{\"package\":\"org.trillionnium.hepta.local\",\"uid\":10481,\"apks\":[{\"path\":\"/data/app/~~kjtm2QzruYL9-aUBXFIlQw==/org.trillionnium.hepta.local-UnoGsU3bLEhG5iG5r16jHA==/base.apk\",\"sha256\":\"067ab5a286b100404fa2b00e341964cd70f005907988dc11eb486c9a4b3bab62\"}]},\"helper_identity\":{\"package\":\"org.trillionnium.hepta.webhelper\",\"uid\":10484,\"apks\":[{\"path\":\"/data/app/~~iuCpyfrLdnn2FSYG4ZOcYQ==/org.trillionnium.hepta.webhelper-LMxwSbN_9UdoiNCifY0iXw==/base.apk\",\"sha256\":\"02360c24c471dcd4be0cbc7c7fdb316a7918d656edd1407d765540b5a3f2f5ff\"}]},\"formal_helper_record_names\":[\"capture-5a26fffdc6ac42a79ec5279d82e4abb5764689dc95424b37931a2e408a3293dd.json\",\"capture-5e3cbc7e753640e0a04800414709507e69d51a30bc8143f992b0c211bb836eb8.json\",\"capture-626cbed43019410e901b0d68d516a51e7df789fff6794d5bba39041d760a9cf2.json\",\"capture-6ec921bc5f764229a177da8acaee9353287437479ae64305807c8717c9e2b57d.json\",\"capture-8e83b31ce2fd43b79d7df3d170db1c88fd0dd09f8b4b4d539be27d6526454ac9.json\",\"capture-95e2b067dfe243fd86d5a6771057e5b2429f777826b34bb298e5652ea17754eb.json\",\"capture-b4e19734a7d544df93e0d22bbffb266ea720947f797b46de9dc7e00500ec9383.json\",\"capture-c57b83ee6f8446efb5b80b6d7a6e4043ce026faa78414c5ba2e58128a621c03b.json\",\"close-73419c48-dfd3-42f9-ac4f-a359e36a080f.json\",\"close-ac33261d-e73b-4a21-8592-c3a48cb0d0a6.json\",\"close-ce67bd37-8341-4b67-87f3-187ca49a3aba.json\",\"close-dc627a3c-d35d-463e-ae7d-c7dcf0c485c2.json\",\"lease-journal.json\"],\"selection\":{\"mode\":\"background\",\"allowed_packages\":[\"com.motorola.stylus\"],\"bootstrap_package\":\"com.motorola.stylus\",\"bootstrap_source\":\"owner_intent_within_explicit_ui_selection\",\"bootstrap_model_issued\":false,\"main_display_fallback\":false,\"home_allowed\":false,\"owner_task_selection\":{\"schema\":\"hepta.owner-task-app-selection.v1\",\"owner_sha256\":\"dddf5b7a31b6e27dc08b116c7d36b6494dadcf7eb8f8937629377e8f551aa03d\",\"recognition\":\"natural_note_comma_prefix.v1\",\"original_ui_initial_package\":\"com.motorola.stylus\",\"original_ui_allowed_packages\":[\"com.motorola.stylus\",\"org.trillionnium.hepta.webhelper\"],\"effective_initial_package\":\"com.motorola.stylus\",\"effective_allowed_packages\":[\"com.motorola.stylus\"],\"effective_scope_within_selected_apps\":true,\"effective_scope_strictly_smaller\":true,\"initial_app_changed\":false,\"package_from_model_or_screen\":false,\"grants_tool_authority\":false,\"changes_saved_preferences\":false}},\"owner_sha256\":\"dddf5b7a31b6e27dc08b116c7d36b6494dadcf7eb8f8937629377e8f551aa03d\",\"display_id\":27,\"generation\":\"f97f9157-fc0e-4b98-baff-bcb9d082f7cd\"}")
EXPECTED_CONFIG_SHA = CURRENT["config_sha256"]
# None values above must be replaced only from actual signed/installed original receipts.

def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def mobimind_cache_pins(raw):
    need(sha(raw) == MOBI_PIN_SOURCE_SHA, "MobiMind model pin source differs")
    source = raw.decode("utf-8", errors="strict")
    directories = re.findall(r'MODEL_DIRECTORY="([^"\\]+)";', source)
    need(directories == [MOBI_DIRECTORY[len("files/"):]], "MobiMind directory pin differs")
    matches = re.findall(r'new FilePin\("([A-Za-z0-9_.-]+)",([0-9]+)L,"([0-9a-f]{64})"\)', source)
    need(len(matches) == 11 and len({name for name, _, _ in matches}) == 11,
         "exact eleven MobiMind file pins required")
    return {MOBI_DIRECTORY + "/" + name: {"bytes": int(size), "sha256": digest}
            for name, size, digest in matches}


def require_mobi_members(entries, pins):
    need(len(entries) == 11 and len(set(entries)) == 11 and set(entries) == set(pins),
         "MobiMind cache must contain exactly its eleven pinned regular files; no extra directory/member")


def cache_file_contract(path, size, profiles, mobi_pins):
    if path == OLD_IMPORT_PART:
        need(size == OLD_IMPORT_BYTES, "observed inactive import residue size differs")
        return {"kind": "inactive_observed_import_residue", "hash_content": True, "pin_sha256": OLD_IMPORT_SHA}
    if path in mobi_pins:
        need(size == mobi_pins[path]["bytes"], "pinned MobiMind file size differs: " + path)
        return {"kind": "pinned_mobimind_file", "hash_content": True, "pin_sha256": mobi_pins[path]["sha256"]}
    need(re.fullmatch(r"files/model/[A-Za-z0-9_.-]+", path), "unknown nested cache file")
    if path.endswith(".gguf"):
        found = [value for value in profiles.PROFILES.values() if path == "files/model/" + value["file"]]
        need(len(found) == 1 and size == found[0]["bytes"], "unknown or wrong-size cached GGUF")
        return {"kind": "pinned_gguf_metadata_continuity", "hash_content": False, "pin_sha256": found[0]["sha256"]}
    need(size <= (1 << 20), "unknown non-model cache file exceeds metadata bound")
    return {"kind": "bounded_metadata", "hash_content": True, "pin_sha256": None}


def parse_cache_stat(raw, uid, directory=False):
    fields = raw.strip().split()
    need(len(fields) == 8 and all(re.fullmatch(r"[0-9]+", fields[i]) for i in (0, 1, 2, 3, 4, 6, 7))
         and re.fullmatch(r"[0-9a-fA-F]+", fields[5]), "unsupported cache continuity stat")
    values = [int(x, 16 if i == 5 else 10) for i, x in enumerate(fields)]
    device, inode, owner, size, links, mode, mtime, ctime = values
    need(owner == uid and inode > 0 and (stat.S_ISDIR(mode) and links >= 1 if directory else stat.S_ISREG(mode) and links == 1),
         "cache entry type/ownership/link count differs")
    return dict(device=device, inode=inode, uid=owner, bytes=size, links=links, mode=mode, mtime_s=mtime, ctime_s=ctime)


def signed_certificate(output):
    certificates = re.findall(r"^Signer #[0-9]+ certificate SHA-256 digest: ([0-9a-fA-F]{64})$", output, re.M)
    need(len(certificates) == 1 and certificates[0].lower() == CERT, "APK is not signed solely by the existing reviewed certificate")
    return certificates[0].lower()


def installed_version(raw, expected=None):
    headers = re.findall(r"^[ \t]*Package \[([^\]]+)\]", raw, re.M)
    need(headers.count(PKG) == 1, "exact package block unavailable")
    versions = re.findall(r"^[ \t]*versionCode=([0-9]+)\b", raw, re.M)
    need(len(versions) == 1 and int(versions[0]) > 0, "installed versionCode not unique")
    version = int(versions[0])
    need(expected is None or version == expected, "installed versionCode differs")
    need("android.permission.INTERNET" not in raw, "unexpected INTERNET permission in installed package dump")
    return version


def require_no_barriers(entries):
    need(len(entries) <= 512 and all(re.fullmatch(r"files/[A-Za-z0-9_.-]+", name) for name in entries), "unrecognized private state inventory")
    for entry in entries:
        name = entry[len("files/"):]
        forbidden = (name == "qualification-scope.json" or name.startswith(("background-session.active.json", "web-helper-session.active.json", "web-helper.active.json"))
            or name.startswith("control-session.recovery-pending-") or "interrupted" in name
            or name.endswith((".bak", ".new")) and any(name.startswith(prefix) for prefix in
                ("control-session.json", "mobi-probe-session.json", "ui-venus-probe-session.json", "background-permission-session.json")))
        need(not forbidden, "lease/latch/sidecar/scope must be absent; no expired-lease exception: " + name)



def same_json_types(a, b):
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return set(a) == set(b) and all(same_json_types(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(same_json_types(x, y) for x, y in zip(a, b))
    return a == b


def require_terminal(session, result, task, uid, controller_proof=None):
    need(session.get("schema") == "hepta.local-session.v1" and session.get("task_id") == task
         and type(session.get("app_uid")) is int and session["app_uid"] == uid
         and (session.get("status") in ("model_reported_done", "partial", "failed", "cancelled")
              or session.get("status") == "controller_verified_done"
              and isinstance(controller_proof, dict)
              and ((controller_proof.get("schema") == "hepta.controller-terminal-idle-compatibility.v1"
                    and controller_proof.get("idle_compatible") is True
                    and controller_proof.get("qualified") is False
                    and controller_proof.get("task_id") == task and controller_proof.get("app_uid") == uid
                    and controller_proof.get("apk_sha256") == HISTORICAL_APK_SHA
                    and controller_proof.get("actual_signed_build_binding", {}).get("build_receipt_sha256") == HISTORICAL_BUILD_SHA)
                   or (controller_proof.get("schema") == "hepta.background-notes-acceptance.v1"
                       and controller_proof.get("driver_revision") == "notes-background-v56-dual-ui-actual-signed-comma-r1"
                       and controller_proof.get("qualified") is False and controller_proof.get("task_id") == CURRENT["task_id"] == task
                       and controller_proof.get("actual_build_binding", {}).get("build_receipt_sha256") == V56_BUILD_SHA
                       and controller_proof.get("actual_build_binding", {}).get("apk_sha256") == V56_APK_SHA
                       and same_json_types(controller_proof.get("last_session"), session)
                       and session.get("completion_verified") is True
                       and session.get("goal_independently_verified") is True
                       and session.get("model_reported_success") is False)))
         and all(session.get(key) is False for key in ("pending", "running", "blocked", "background_lease_unreleased", "external_model", "automatic_resume"))
         and session.get("cleanup_known") is True, "expected task is not cleanly terminal")
    need(isinstance(session.get("state"), str) and type(session.get("updated_wall_ms")) is int and session["updated_wall_ms"] > 0
         and isinstance(session.get("origin"), str) and 0 < len(session["origin"]) <= 80 and "\0" not in session["origin"]
         and isinstance(session.get("instruction_sha256"), str) and re.fullmatch(r"[0-9a-f]{64}", session["instruction_sha256"])
         and "debug_nonce_sha256" in session
         and (session.get("debug_nonce_sha256") is None or isinstance(session.get("debug_nonce_sha256"), str)
              and re.fullmatch(r"[0-9a-f]{64}", session["debug_nonce_sha256"])), "terminal record lacks valid original identity")
    need(session["origin"] != "private_debug_nonce" or session.get("debug_nonce_sha256") is not None,
         "debug terminal record lacks its original nonce binding")
    need(result.get("task_id") == task and result.get("status") == session["status"]
         and result.get("cleanup_known") is True and result.get("external_model") is False
         and result.get("automatic_replay") is False, "matching clean terminal result receipt required")



def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate JSON member")
            result[key] = value
        return result
    return json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def file_identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_uid, value.st_gid, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def host_original(pin, observed, maximum=32 << 20, allow_empty=False):
    need(type(pin) is dict and set(pin) == {"path", "bytes", "sha256"}
         and type(pin["path"]) is str and type(pin["bytes"]) is int
         and type(allow_empty) is bool and (0 if allow_empty else 1) <= pin["bytes"] <= maximum
         and type(pin["sha256"]) is str
         and re.fullmatch(r"[0-9a-f]{64}", pin["sha256"]), "exact immutable original pin required")
    path = Path(pin["path"])
    need(path.is_absolute() and BASE in path.parents
         and all(not item.is_symlink() for item in (path, *path.parents)), "exact task-root original path")
    fd = os.open(str(path), os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_size == pin["bytes"], "host original shape differs")
        with os.fdopen(os.dup(fd), "rb") as stream:
            raw = stream.read(pin["bytes"] + 1)
        identity = file_identity(before)
        need(identity == file_identity(os.fstat(fd)) == file_identity(os.lstat(path))
             and len(raw) == pin["bytes"] and sha(raw) == pin["sha256"], "host original changed")
        if str(path) in observed:
            need(observed[str(path)] == (identity, pin["sha256"]), "original changed between checks")
        observed[str(path)] = (identity, pin["sha256"])
        return raw
    finally:
        os.close(fd)


def require_helper6_install_pins():
    need(type(OWNER) is dict and set(OWNER) == {"root", "pid", "start_ticks", "boot_id"}
         and type(OWNER["pid"]) is int and OWNER["pid"] > 1
         and type(OWNER["root"]) is str and Path(OWNER["root"]).parent == BASE
         and re.fullmatch(r"owner-[0-9]+", Path(OWNER["root"]).name)
         and type(OWNER["start_ticks"]) is str and re.fullmatch(r"[1-9][0-9]*", OWNER["start_ticks"])
         and type(OWNER["boot_id"]) is str
         and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", OWNER["boot_id"]),
         "actual current owner must be sealed; historical owner is not executable")
    for pin in (HELPER6_UPGRADE_SOURCE, HELPER6_INSTALL_RESULT,
                HELPER6_RECONCILIATION_SOURCE, HELPER6_FAILED_INSTALL_RESULT):
        need(type(pin) is dict and set(pin) == {"path", "bytes", "sha256"}
             and type(pin["path"]) is str and Path(pin["path"]).is_absolute()
             and BASE in Path(pin["path"]).parents
             and type(pin["bytes"]) is int and 0 < pin["bytes"] <= 8 << 20
             and type(pin["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", pin["sha256"]),
             "actual final helper6 source/install receipt is still required")
    need(HELPER6_UPGRADE_SOURCE["path"] == str(BASE / "install_helper6_idle_r1.py")
         and HELPER6_INSTALL_RESULT["path"] == str(BASE / "v55-web-helper-code6-reconcile-r1/RESULT.json")
         and HELPER6_FAILED_INSTALL_RESULT["path"] == str(BASE / "v55-web-helper-code6-upgrade-r1/RESULT.json")
         and HELPER6_RECONCILIATION_SOURCE["path"] == str(BASE / "reconcile_helper6_postinstall_r1.py"),
         "only the exact failed original and independently completed read-only reconciliation are covered")
    need(type(HELPER6_EXPECTED_IDENTITY) is dict
         and set(HELPER6_EXPECTED_IDENTITY) == {"package", "uid", "apks"}
         and HELPER6_EXPECTED_IDENTITY["package"] == HELPER_PACKAGE
         and type(HELPER6_EXPECTED_IDENTITY["uid"]) is int
         and HELPER6_EXPECTED_IDENTITY["uid"] == HELPER_UID
         and type(HELPER6_EXPECTED_IDENTITY["apks"]) is list
         and len(HELPER6_EXPECTED_IDENTITY["apks"]) == 1,
         "actual installed helper6 identity remains unknown")
    apk = HELPER6_EXPECTED_IDENTITY["apks"][0]
    need(type(apk) is dict and set(apk) == {"path", "sha256"}
         and type(apk["path"]) is str and apk["path"].startswith("/data/app/")
         and apk["path"].endswith("/base.apk")
         and type(apk["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", apk["sha256"])
         and apk["sha256"] != HISTORICAL_CURRENT["helper_identity"]["apks"][0]["sha256"],
         "actual helper6 PM base path/full SHA must differ from old helper5")
    need(type(HELPER6_INSTALL_EXPECTED) is dict
         and set(HELPER6_INSTALL_EXPECTED) == {
             "schema", "revision", "current_terminal_reference", "formal_artifact_proof",
             "installed_identity_before", "observer_installed_identity",
             "main_identity_before", "main_identity_preserved",
             "diagnostics_before_upgrade", "diagnostics_after_upgrade",
             "focus_before", "focus_after", "formal_binding_before", "formal_binding_after"},
         "actual helper6 installation projection must be sealed from its original receipt")


def typed_projection(actual, expected, label):
    need(type(actual) is dict and type(expected) is dict
         and all(key in actual and same_json_types(actual[key], value)
                 for key, value in expected.items()), label + ": actual typed projection differs")


def verified_historical_helper6_install(observed):
    require_helper6_install_pins()
    source = host_original(HELPER6_UPGRADE_SOURCE, observed, 256 << 10)
    path = Path(HELPER6_UPGRADE_SOURCE["path"])
    spec = importlib.util.spec_from_file_location("frozen_actual_helper6_installer", path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(source, str(path), "exec"), module.__dict__)
    need(same_json_types(module.CURRENT, HISTORICAL_CURRENT),
         "helper6 current Flight reference must be the same exact original")
    artifact = module.verify_helper6_artifacts(observed)
    reference = module.verify_current_reference(observed)
    recovery_source = host_original(HELPER6_RECONCILIATION_SOURCE, observed, 256 << 10)
    recovery_path = Path(HELPER6_RECONCILIATION_SOURCE["path"])
    recovery_spec = importlib.util.spec_from_file_location("frozen_actual_helper6_reconciliation", recovery_path)
    recovery = importlib.util.module_from_spec(recovery_spec)
    exec(compile(recovery_source, str(recovery_path), "exec"), recovery.__dict__)
    need(same_json_types(recovery.FAILED_INSTALL_SOURCE, HELPER6_UPGRADE_SOURCE)
         and same_json_types(recovery.FAILED_INSTALL_RESULT, HELPER6_FAILED_INSTALL_RESULT)
         and same_json_types(recovery.CURRENT, HISTORICAL_CURRENT)
         and same_json_types(recovery.HELPER6_RELEASE, module.HELPER6_RELEASE),
         "exact reconciliation source/prior install/release binding differs")
    failure = strict_json(host_original(HELPER6_FAILED_INSTALL_RESULT, observed, 256 << 10))
    need(failure.get("schema") == "hepta.helper6.clean-idle-same-signer-upgrade.v1"
         and failure.get("revision") == "independent-helper6-from-main54-preservation-r1"
         and failure.get("completed") is False and failure.get("installed_verified") is False
         and failure.get("install_submitted") is True and failure.get("install_success_returned") is True
         and failure.get("error") == "RuntimeError: helper-only upgrade changed the Main accessibility binding"
         and failure.get("same_signer_actually_verified") is True
         and failure.get("old_actual_signer_certificate_sha256") == CERT
         and failure.get("new_actual_signer_certificate_sha256") == CERT
         and same_json_types(failure.get("current_terminal_reference"), reference)
         and same_json_types(failure.get("formal_artifact_proof"), artifact)
         and same_json_types(failure.get("installed_identity_before"), HISTORICAL_CURRENT["helper_identity"]),
         "original failed install/successful package replacement evidence differs")
    expected_binding = recovery.formal_binding_identity(failure["formal_binding_before"])
    need(same_json_types(expected_binding, recovery.formal_binding_identity(failure["formal_binding_after"])),
         "original failure includes a substantive binding identity change")
    for label in ("before", "after"):
        dump = host_original(recovery.FAILED_FORMAL[label], observed, 256 << 10)
        need(sha(dump) == failure["formal_binding_" + label]["service_dump_sha256"],
             "complete original failed-install dump evidence changed")
    raw = host_original(HELPER6_INSTALL_RESULT, observed, 8 << 20)
    receipt = strict_json(raw)
    predecessor = receipt.get("original_install_failure")
    typed_projection(predecessor, {
        "original_source":HELPER6_UPGRADE_SOURCE, "original_result":HELPER6_FAILED_INSTALL_RESULT,
        "original_completed":False, "original_installed_verified":False, "original_error":failure["error"],
        "original_install_submitted":True, "original_install_success_returned":True,
        "original_formal_dumps":recovery.FAILED_FORMAL, "original_binding_identity":expected_binding,
        "only_dump_digest_differs":True, "original_failure_retained":True,
        "model_inventory_hash_first_observed_at_reconciliation":True,
        "model_inventory_hash_claimed_in_original_result":False},
        "independent reconciliation must retain the exact failed original")
    need(same_json_types(receipt.get("formal_binding_before"), failure["formal_binding_before"])
         and same_json_types(receipt.get("diagnostics_before_upgrade"), failure["diagnostics_before_upgrade"])
         and same_json_types(recovery.formal_binding_identity(receipt.get("formal_binding_at_reconciliation_start")), expected_binding),
         "historical evidence or current reconciliation-start binding differs")
    typed_projection(receipt, HELPER6_INSTALL_EXPECTED, "actual helper6 installation")
    need(receipt.get("schema") == "hepta.helper6.postinstall-reconciliation.v1"
         and receipt.get("revision") == "binding-identity-excludes-raw-dump-digest-r1"
         and receipt.get("error") is None
         and receipt.get("completed") is True and receipt.get("installed_verified") is True
         and receipt.get("reconciliation_verified") is True and receipt.get("binding_identity_unchanged") is True
         and receipt.get("original_failure_retained") is True
         and receipt.get("install_submitted") is False and receipt.get("install_success_returned") is False
         and receipt.get("installation_performed_here") is False and receipt.get("signer_executed_here") is False
         and receipt.get("signer_verification_reused_from_original_install") is True
         and type(receipt.get("expected_helper_version")) is int and receipt["expected_helper_version"] == 6
         and type(receipt.get("expected_helper_uid")) is int and receipt["expected_helper_uid"] == HELPER_UID
         and type(receipt.get("expected_main_uid")) is int and receipt["expected_main_uid"] == 10481
         and type(receipt.get("helper_diagnostic_count_expected")) is int and receipt["helper_diagnostic_count_expected"] == 37
         and receipt.get("expected_terminal_task_id") == HISTORICAL_CURRENT["task_id"],
         "independent read-only helper6 reconciliation did not complete")
    need(all(receipt.get(key) is True for key in (
             "same_signer_actually_verified", "all37_diagnostics_preserved_byte_for_byte",
             "runtime_config_preserved_byte_for_byte", "terminal_journals_preserved_byte_for_byte",
             "ui_preferences_preserved_byte_for_byte", "selected_model_full_sha_preserved",
             "model_cache_inventory_preserved", "no_new_tasks_or_model_runs", "host_originals_unchanged"))
         and receipt.get("old_actual_signer_certificate_sha256") == CERT
         and receipt.get("new_actual_signer_certificate_sha256") == CERT,
         "helper6 predecessor did not preserve the exact signed state")
    need(all(receipt.get(key) is False for key in (
             "site_opened", "main_activity_launched", "task_started", "model_invoked",
             "app_data_cleared", "journals_deleted", "uninstall_used", "automatic_retry",
             "rollback_attempted", "permission_authorization_changed", "private_key_accessed",
             "business_verified", "qualified", "unstarted_is_five_flag_close",
             "formal_lease_cleanup_verified"))
         and receipt.get("historical_task_status") == "failed"
         and type(receipt.get("historical_task_model_runs")) is int
         and receipt["historical_task_model_runs"] == 0
         and receipt.get("historical_task_business_verified") is False,
         "helper6 predecessor is preserving installation evidence, not successful Flight/ordinary-close evidence")
    need(same_json_types(receipt.get("current_terminal_reference"), reference)
         and same_json_types(receipt.get("formal_artifact_proof"), artifact)
         and same_json_types(receipt.get("installed_identity_before"), HISTORICAL_CURRENT["helper_identity"])
         and same_json_types(receipt.get("observer_installed_identity"), HELPER6_EXPECTED_IDENTITY)
         and same_json_types(receipt.get("installed_identity_at_reconciliation_start"), HELPER6_EXPECTED_IDENTITY)
         and HELPER6_EXPECTED_IDENTITY["apks"][0]["sha256"] == artifact["apk"]["sha256"]
         and same_json_types(receipt.get("main_identity_before"), dict(HISTORICAL_CURRENT["main_identity"], version_code=54))
         and same_json_types(receipt.get("main_identity_preserved"), dict(HISTORICAL_CURRENT["main_identity"], version_code=54))
         and same_json_types(recovery.formal_binding_identity(receipt.get("formal_binding_after")), expected_binding),
         "actual helper6 installation/source/main54 identity differs")
    before = receipt.get("diagnostics_before_upgrade")
    after = receipt.get("diagnostics_after_upgrade")
    need(type(before) is dict and type(after) is dict
         and set(before) == set(after) == set(reference["diagnostics"])
         and len(before) == 37 and same_json_types(before, after),
         "helper6 must preserve the complete same37 original record identities")
    for name, expected in reference["diagnostics"].items():
        need(type(before[name]) is dict and set(before[name]) == set(expected) | {"stat"},
             "exact helper diagnostic preservation row required")
        typed_projection(before[name], expected, "preserved helper diagnostic")
        facts = before[name]["stat"]
        need(type(facts) is dict and set(facts) ==
             {"device", "inode", "uid", "bytes", "links", "mode", "mtime_s", "ctime_s"}
             and all(type(value) is int for value in facts.values())
             and facts["uid"] == HELPER_UID and facts["bytes"] == expected["bytes"]
             and facts["links"] == 1 and stat.S_ISREG(facts["mode"]),
             "actual helper file stat evidence differs")
    host_original(HELPER6_UPGRADE_SOURCE, observed, 256 << 10)
    host_original(HELPER6_RECONCILIATION_SOURCE, observed, 256 << 10)
    host_original(HELPER6_FAILED_INSTALL_RESULT, observed, 256 << 10)
    return {"identity": HELPER6_EXPECTED_IDENTITY, "diagnostics": reference["diagnostics"],
            "actual_helper_install_failure": dict(HELPER6_FAILED_INSTALL_RESULT),
            "actual_helper_install_reconciliation": dict(HELPER6_INSTALL_RESULT),
            "helper6_reconciliation_source": dict(HELPER6_RECONCILIATION_SOURCE),
            "original_install_completed": False, "original_install_installed_verified": False,
            "reconciliation_completed": True,
            "helper6_source": dict(HELPER6_UPGRADE_SOURCE), "helper6_artifacts": artifact,
            "original_flight_reference": reference, "historical_task_status": "failed",
            "historical_model_runs": 0, "unstarted_is_five_flag_close": False,
            "formal_lease_cleanup_verified": False, "business_verified": False}


def require_v55_release_pins():
    need(all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v)
             for v in (V55_APK_SHA, V55_BUILD_SHA, V55_INVENTORY))
         and isinstance(V55_SOURCE, str) and re.fullmatch(r"[0-9a-f]{40}", V55_SOURCE),
         "actual v55 signed release pins are still required; no phone operation")
    need(isinstance(V55_BUILD_SCHEMA, str) and V55_BUILD_SCHEMA
         and type(V55_APK_BYTES) is int and 0 < V55_APK_BYTES <= (256 << 20),
         "actual v55 schema/APK size required")
    need(isinstance(V55_VERSION_NAME, str) and V55_VERSION_NAME.startswith("0.55."),
         "actual final v55 version name required")
    for raw_path in (V55_BUILD_PATH, V55_APK_PATH):
        need(isinstance(raw_path, str) and Path(raw_path).is_absolute()
             and BASE in Path(raw_path).parents, "exact actual v55 host path required")
    names = {"source_file_count", "actual_compiler_source_inputs",
             "host_check_records", "host_input_count", "packaged_library_count"}
    need(isinstance(V55_COUNTS, dict) and set(V55_COUNTS) == names
         and all(type(v) is int and v > 0 for v in V55_COUNTS.values()),
         "actual v55 source/compiler/host counts required")
    need(isinstance(V55_LIBRARY_PINS, dict)
         and len(V55_LIBRARY_PINS) == V55_COUNTS["packaged_library_count"]
         and "libhepta_local_runner.so" in V55_LIBRARY_PINS
         and all(re.fullmatch(r"lib[A-Za-z0-9_+.-]+\.so", k)
                 and isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v)
                 for k, v in V55_LIBRARY_PINS.items()),
         "complete actual v55 native library map required")
    need(isinstance(V55_NATIVE_FIELDS, dict) and V55_NATIVE_FIELDS
         and any(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v)
                 for v in V55_NATIVE_FIELDS.values()),
         "reviewed actual v55 native provenance binding required")
    need(type(V55_BUILD_BYTES) is int and 0 < V55_BUILD_BYTES <= 8 << 20,
         "actual signed Main55 receipt byte count required")
    need(V55_COUNTS["packaged_library_count"] == 17
         and same_json_types(V55_LIBRARY_PINS, HISTORICAL_LIBRARY_PINS)
         and V55_NATIVE_FIELDS.get("native_recompiled_here") is False,
         "Main55 must preserve all17 actual54 native payloads without a new native compilation claim")
    require_helper6_install_pins()


def verify_v55_build_identity(build):
    require_v55_release_pins()
    need(build.get("schema") == V55_BUILD_SCHEMA
         and build.get("source_commit") == V55_SOURCE
         and build.get("source_inventory_sha256") == V55_INVENTORY
         and type(build.get("version_code")) is int and build["version_code"] == 55
         and build.get("version_name") == V55_VERSION_NAME
         and build.get("apk_sha256") == V55_APK_SHA and build.get("apk_bytes") == V55_APK_BYTES,
         "exact signed v55 source/version/APK binding required")
    need(all(type(build.get(k)) is int and build[k] == v for k, v in V55_COUNTS.items()),
         "v55 source/compiler/host counts differ")
    need(build.get("all_pass") is True and build.get("actual_compiler_inputs_bound_to_signed_asset") is True
         and build.get("matches_previously_recorded_signer") is True
         and build.get("source_files_unchanged") is True
         and build.get("permissions") == V55_PERMISSIONS and build.get("abi") == ["arm64-v8a"]
         and build.get("new_key_created") is False and build.get("existing_key_metadata_unchanged") is True,
         "v55 actual same-signer/provenance/permission gates differ")
    need(same_json_types(build.get("library_pins"), V55_LIBRARY_PINS)
         and all(k in build and same_json_types(build[k], v)
                 for k, v in V55_NATIVE_FIELDS.items()),
         "actual v55 native libraries/provenance differ; actual v54 native baseline remains separately bound")

def require_v56_release_pins():
    need(all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v)
             for v in (V56_APK_SHA, V56_BUILD_SHA, V56_INVENTORY))
         and isinstance(V56_SOURCE, str) and re.fullmatch(r"[0-9a-f]{40}", V56_SOURCE),
         "actual v56 signed release pins are still required; no phone operation")
    need(isinstance(V56_BUILD_SCHEMA, str) and V56_BUILD_SCHEMA
         and type(V56_APK_BYTES) is int and 0 < V56_APK_BYTES <= (256 << 20),
         "actual v56 schema/APK size required")
    need(isinstance(V56_VERSION_NAME, str) and V56_VERSION_NAME.startswith("0.56."),
         "actual final v56 version name required")
    for raw_path in (V56_BUILD_PATH, V56_APK_PATH):
        need(isinstance(raw_path, str) and Path(raw_path).is_absolute()
             and BASE in Path(raw_path).parents, "exact actual v56 host path required")
    names = {"source_file_count", "actual_compiler_source_inputs",
             "host_check_records", "host_input_count", "packaged_library_count"}
    need(isinstance(V56_COUNTS, dict) and set(V56_COUNTS) == names
         and all(type(v) is int and v > 0 for v in V56_COUNTS.values()),
         "actual v56 source/compiler/host counts required")
    need(isinstance(V56_LIBRARY_PINS, dict)
         and len(V56_LIBRARY_PINS) == V56_COUNTS["packaged_library_count"]
         and "libhepta_local_runner.so" in V56_LIBRARY_PINS
         and all(re.fullmatch(r"lib[A-Za-z0-9_+.-]+\.so", k)
                 and isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v)
                 for k, v in V56_LIBRARY_PINS.items()),
         "complete actual v56 native library map required")
    need(isinstance(V56_NATIVE_FIELDS, dict) and V56_NATIVE_FIELDS
         and any(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v)
                 for v in V56_NATIVE_FIELDS.values()),
         "reviewed actual v56 native provenance binding required")
    need(type(V56_BUILD_BYTES) is int and 0 < V56_BUILD_BYTES <= 8 << 20,
         "actual signed Main56 receipt byte count required")
    need(V56_COUNTS["packaged_library_count"] == 17
         and same_json_types(V56_LIBRARY_PINS, HISTORICAL_LIBRARY_PINS)
         and V56_NATIVE_FIELDS.get("native_recompiled_here") is False,
         "Main56 must preserve all17 actual54 native payloads without a new native compilation claim")
    require_helper6_install_pins()


def verify_v56_build_identity(build):
    require_v56_release_pins()
    need(build.get("schema") == V56_BUILD_SCHEMA
         and build.get("source_commit") == V56_SOURCE
         and build.get("source_inventory_sha256") == V56_INVENTORY
         and type(build.get("version_code")) is int and build["version_code"] == 56
         and build.get("version_name") == V56_VERSION_NAME
         and build.get("apk_sha256") == V56_APK_SHA and build.get("apk_bytes") == V56_APK_BYTES,
         "exact signed v56 source/version/APK binding required")
    need(all(type(build.get(k)) is int and build[k] == v for k, v in V56_COUNTS.items()),
         "v56 source/compiler/host counts differ")
    need(build.get("all_pass") is True and build.get("actual_compiler_inputs_bound_to_signed_asset") is True
         and build.get("matches_previously_recorded_signer") is True
         and build.get("source_files_unchanged") is True
         and build.get("permissions") == V56_PERMISSIONS and build.get("abi") == ["arm64-v8a"]
         and build.get("new_key_created") is False and build.get("existing_key_metadata_unchanged") is True,
         "v56 actual same-signer/provenance/permission gates differ")
    need(same_json_types(build.get("library_pins"), V56_LIBRARY_PINS)
         and all(k in build and same_json_types(build[k], v)
                 for k, v in V56_NATIVE_FIELDS.items()),
         "actual v56 native libraries/provenance differ; actual v54 native baseline remains separately bound")

def require_v57_release_pins():
    need(all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v)
             for v in (V57_APK_SHA, V57_BUILD_SHA, V57_INVENTORY))
         and isinstance(V57_SOURCE, str) and re.fullmatch(r"[0-9a-f]{40}", V57_SOURCE),
         "actual v57 signed release pins are still required; no phone operation")
    need(isinstance(V57_BUILD_SCHEMA, str) and V57_BUILD_SCHEMA
         and type(V57_APK_BYTES) is int and 0 < V57_APK_BYTES <= (256 << 20),
         "actual v57 schema/APK size required")
    need(isinstance(V57_VERSION_NAME, str) and V57_VERSION_NAME.startswith("0.57."),
         "actual final v57 version name required")
    for raw_path in (V57_BUILD_PATH, V57_APK_PATH):
        need(isinstance(raw_path, str) and Path(raw_path).is_absolute()
             and BASE in Path(raw_path).parents, "exact actual v57 host path required")
    names = {"source_file_count", "actual_compiler_source_inputs",
             "host_check_records", "host_input_count", "packaged_library_count"}
    need(isinstance(V57_COUNTS, dict) and set(V57_COUNTS) == names
         and all(type(v) is int and v > 0 for v in V57_COUNTS.values()),
         "actual v57 source/compiler/host counts required")
    need(isinstance(V57_LIBRARY_PINS, dict)
         and len(V57_LIBRARY_PINS) == V57_COUNTS["packaged_library_count"]
         and "libhepta_local_runner.so" in V57_LIBRARY_PINS
         and all(re.fullmatch(r"lib[A-Za-z0-9_+.-]+\.so", k)
                 and isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v)
                 for k, v in V57_LIBRARY_PINS.items()),
         "complete actual v57 native library map required")
    need(isinstance(V57_NATIVE_FIELDS, dict) and V57_NATIVE_FIELDS
         and any(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v)
                 for v in V57_NATIVE_FIELDS.values()),
         "reviewed actual v57 native provenance binding required")
    need(type(V57_BUILD_BYTES) is int and 0 < V57_BUILD_BYTES <= 8 << 20,
         "actual signed Main57 receipt byte count required")
    need(V57_COUNTS["packaged_library_count"] == 17
         and same_json_types(V57_LIBRARY_PINS, HISTORICAL_LIBRARY_PINS)
         and V57_NATIVE_FIELDS.get("native_recompiled_here") is False,
         "Main57 must preserve all17 actual54 native payloads without a new native compilation claim")
    require_helper6_install_pins()

def verify_v57_build_identity(build):
    require_v57_release_pins()
    need(build.get("schema") == V57_BUILD_SCHEMA
         and build.get("source_commit") == V57_SOURCE
         and build.get("source_inventory_sha256") == V57_INVENTORY
         and type(build.get("version_code")) is int and build["version_code"] == 57
         and build.get("version_name") == V57_VERSION_NAME
         and build.get("apk_sha256") == V57_APK_SHA and build.get("apk_bytes") == V57_APK_BYTES,
         "exact signed v57 source/version/APK binding required")
    need(all(type(build.get(k)) is int and build[k] == v for k, v in V57_COUNTS.items()),
         "v57 source/compiler/host counts differ")
    need(build.get("all_pass") is True and build.get("actual_compiler_inputs_bound_to_signed_asset") is True
         and build.get("matches_previously_recorded_signer") is True
         and build.get("source_files_unchanged") is True
         and build.get("permissions") == V57_PERMISSIONS and build.get("abi") == ["arm64-v8a"]
         and build.get("new_key_created") is False and build.get("existing_key_metadata_unchanged") is True,
         "v57 actual same-signer/provenance/permission gates differ")
    need(same_json_types(build.get("library_pins"), V57_LIBRARY_PINS)
         and all(k in build and same_json_types(build[k], v)
                 for k, v in V57_NATIVE_FIELDS.items()),
         "actual v57 native libraries/provenance differ; actual v54 native baseline remains separately bound")
def verified_previous_main56(observed, helper_history):
    host_original(MAIN56_INSTALL_SOURCE, observed, 256 << 10)
    prior = strict_json(host_original(MAIN56_INSTALL_RESULT, observed, 8 << 20))
    signed_pin = {"path": V56_BUILD_PATH, "bytes": V56_BUILD_BYTES, "sha256": V56_BUILD_SHA}
    verify_v56_build_identity(strict_json(host_original(signed_pin, observed, 8 << 20)))
    need(prior.get("schema") == "hepta.v56.clean-idle-same-signer-upgrade.v1"
         and prior.get("helper_revision") == "main56-current55-helper6-failed-flight-preservation-r1"
         and prior.get("error") is None
         and all(prior.get(k) is True for k in (
             "completed", "installed_verified", "install_submitted", "install_success_returned",
             "same_signer_actually_verified", "ui_preferences_preserved_byte_for_byte",
             "helper_package_and_diagnostics_preserved", "helper_was_not_launched_or_modified",
             "runtime_config_preserved_byte_for_byte", "terminal_journals_preserved_byte_for_byte",
             "selected_model_full_sha_preserved", "model_cache_inventory_preserved",
             "no_new_tasks_or_model_runs", "host_originals_unchanged")),
         "the actual Main56 preserving installation did not complete")
    need(all(prior.get(k) is False for k in (
             "expired_lease_exception_allowed", "journals_deleted", "app_data_cleared", "uninstall_used",
             "automatic_retry", "rollback_attempted", "task_replayed_or_started", "start_tapped",
             "target_app_operated", "model_invoked", "private_key_accessed", "business_verified",
             "qualified", "native_recompiled_here")),
         "Main56 predecessor includes an unapproved change or business claim")
    typed_projection(prior, {
        "expected_version": 56, "expected_uid": 10481,
        "expected_old_apk_sha256": V55_APK_SHA, "expected_new_apk_sha256": V56_APK_SHA,
        "expected_source_commit": V56_SOURCE, "expected_source_inventory_sha256": V56_INVENTORY,
        "expected_terminal_task_id": PREVIOUS_FLIGHT55["task_id"],
        "expected_config_sha256": CURRENT["config_sha256"],
        "old_actual_signer_certificate_sha256": CERT, "new_actual_signer_certificate_sha256": CERT,
        "helper_diagnostic_count_preserved": 46}, "actual Main56 historical installation")
    historical = prior.get("actual_main55_helper6_current_flight_prerequisite")
    need(type(historical) is dict
         and same_json_types(historical.get("historical_helper6_installation"), helper_history)
         and same_json_types(prior.get("installed_identity_before"),
                             dict(PREVIOUS_FLIGHT55["main_identity"], version_code=55))
         and same_json_types(prior.get("installed_identity_after"),
                             dict(CURRENT["main_identity"], version_code=56))
         and same_json_types(prior.get("selected_model_before"), prior.get("selected_model_after"))
         and prior["ui_preferences_before"]["bytes"] == MAIN55_SAVED_PREFS["bytes"]
         and prior["ui_preferences_before"]["sha256"] == CURRENT["prefs_sha256"],
         "actual predecessor identity, exact helper history, preferences or model differs")
    return {"source": dict(MAIN56_INSTALL_SOURCE), "result": dict(MAIN56_INSTALL_RESULT),
            "signed": signed_pin, "installed_identity": prior["installed_identity_after"],
            "historical_helper_count": 46, "historical_task_id": PREVIOUS_FLIGHT55["task_id"],
            "current_task_proved_by_this_historical_install": False}



def verified_retained_flight56(observed, helper_history):
    # Historical helper baseline, distinct from the current successful Notes task.
    CURRENT = HELPER_CURRENT
    receipt = strict_json(host_original(CURRENT["result"], observed, 8 << 20))
    collection = strict_json(host_original(CURRENT["collection"], observed, 8 << 20))
    index = strict_json(host_original(CURRENT["capture_index"], observed, 8 << 20))
    task = CURRENT["task_id"]
    root = Path(CURRENT["evidence_directory"])
    need(root == BASE / "background-web-v56-lfm3-flight-r1/evidence"
         and receipt.get("schema") == "hepta.v56-background-web-observation.v1"
         and receipt.get("driver_revision") == "web-helper6-natural-owner-automatic-target-two-lease-r1"
         and receipt.get("case") == "flight" and type(receipt.get("lease_number")) is int
         and receipt["lease_number"] == 1 and receipt.get("task_id") == task
         and receipt.get("error") is None and receipt.get("collection_complete") is True
         and receipt.get("ready_for_next_lease") is True
         and receipt.get("qualified") is False and receipt.get("business_verified") is False
         and receipt.get("sdk_teardown_verified") is False
         and receipt.get("input_outcome_unknown") is False
         and receipt.get("automatic_retry") is False
         and receipt.get("native_input_or_model_outputs_synthesized") is False,
         "current Flight56 collection must remain its actual failed business run")
    need(same_json_types(receipt.get("collection"), {
             "path": CURRENT["collection"]["path"], "sha256": CURRENT["collection"]["sha256"]})
         and same_json_types(receipt.get("capture_raw_index"), CURRENT["capture_index"])
         and receipt.get("controller_session_after_sha256") == CURRENT["session_sha256"]
         and receipt.get("runtime_config_sha256") == CURRENT["config_sha256"]
         and receipt.get("ui_preferences_before_sha256") == CURRENT["prefs_sha256"]
         and receipt.get("ui_preferences_after_sha256") == CURRENT["prefs_sha256"]
         and receipt.get("ui_preferences_unchanged") is True
         and receipt.get("release_artifacts_unchanged") is True,
         "current collection/controller/preferences release binding differs")
    installed = {"hepta": CURRENT["main_identity"], "helper": CURRENT["helper_identity"]}
    need(same_json_types(receipt.get("installed_identity_before"), installed)
         and same_json_types(receipt.get("installed_identity_after"), installed)
         and same_json_types(installed["helper"], HELPER6_EXPECTED_IDENTITY),
         "actual Main56/Helper6 installation changed during Flight56")
    lock = receipt.get("operation_lock")
    need(type(lock) is dict and lock.get("acquired") is True and lock.get("released") is True
         and lock.get("continuity_verified") is True and lock.get("reacquisition_attempted") is False,
         "independent Flight56 operation lock did not close normally")
    markers = receipt.get("markers_present_after")
    need(type(markers) is dict and set(markers) == {
             "qualification-scope.json", "web-helper.active.json", "background-session.active.json",
             "control-session.interrupted.json", "background-permission-interrupted.json"}
         and all(v is False for v in markers.values())
         and receipt.get("system_resources_absent") is True,
         "current Flight56 resources or interruption markers remain")
    need(collection.get("schema") == "hepta.original-web-task-file-index.v2"
         and collection.get("task_id") == task and collection.get("collection_is_business_verdict") is False
         and same_json_types(collection.get("capture_raw_index"), CURRENT["capture_index"]),
         "exact original Flight56 collection required")
    groups = (("task_files", CURRENT["task_file_count"]), ("model_run_files", CURRENT["model_file_count"]),
              ("helper_files", CURRENT["helper_count"]))
    originals, rows, main_rows, diagnostics, request_members = {}, {}, [], {}, {}
    for group, count in groups:
        members = collection.get(group)
        need(type(members) is list and len(members) == count, "complete current original inventory required")
        for row in members:
            need(type(row) is dict and set(row) == {
                     "path", "bytes", "sha256", "package", "device_path", "relative_path"}
                 and type(row["path"]) is str and type(row["relative_path"]) is str
                 and type(row["device_path"]) is str
                 and re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", row["relative_path"])
                 and all(part not in (".", "..") for part in row["relative_path"].split("/")),
                 "exact bounded original collection row required")
            relative = row["relative_path"]
            if group == "task_files":
                need(row["package"] == PKG and row["path"] == str(root / "task" / relative)
                     and row["device_path"] == "files/control-tasks/" + task + "/" + relative,
                     "current task original path differs")
            elif group == "helper_files":
                need("/" not in relative and row["package"] == HELPER_PACKAGE
                     and row["path"] == str(root / "helper" / relative)
                     and row["device_path"] == "files/web-evidence-v1/" + relative,
                     "current helper original path differs")
                diagnostics[relative] = {"bytes": row["bytes"], "sha256": row["sha256"], "uid": HELPER_UID}
            else:
                parts = row["device_path"].split("/")
                need(len(parts) == 4 and parts[:2] == ["files", "runs"]
                     and parts[2] in CURRENT["request_ids"] + [CURRENT["parent_generation"]]
                     and parts[3] == relative and "/" not in relative and row["package"] == PKG
                     and row["path"] == str(root / "runs" / parts[2] / relative),
                     "current model original path differs")
                request_members.setdefault(parts[2], set()).add(relative)
            need(row["path"] not in rows, "duplicate current original path")
            pin = {k: row[k] for k in ("path", "bytes", "sha256")}
            empty_stdout = row["path"] == str(root / "runs" / CURRENT["parent_generation"] / "stdout.log")
            originals[row["path"]] = host_original(pin, observed, 2 << 20, allow_empty=empty_stdout)
            rows[row["path"]] = row
            if group != "helper_files":
                main_rows.append(dict(row))
    need(type(collection.get("file_count")) is int and collection["file_count"] == len(rows) == 104
         and type(collection.get("raw_bytes")) is int
         and collection["raw_bytes"] == sum(len(raw) for raw in originals.values()) == 13431957
         and len(diagnostics) == CURRENT["helper_count"]
         and len(main_rows) == CURRENT["task_file_count"] + CURRENT["model_file_count"],
         "current original count or complete byte accounting differs")
    request_names = {"app-receipt.json", "formatted-input-ids.le32", "formatted-prompt.txt", "grammar.gbnf",
                     "native-result.json", "prompt-evidence.json", "prompt.txt", "raw-text.txt", "system.txt"}
    need(set(request_members) == set(CURRENT["request_ids"] + [CURRENT["parent_generation"]])
         and all(request_members[run] == request_names for run in CURRENT["request_ids"])
         and request_members[CURRENT["parent_generation"]] == {
             "app-session-receipt.json", "native-session-result.json", "stderr.log", "stdout.log"}
         and receipt.get("original_model_run_directories") == sorted(request_members),
         "one request and one distinct parent session must remain separate")
    for name, expected in helper_history["diagnostics"].items():
        need(name in diagnostics and same_json_types(diagnostics[name], expected),
             "historical37 helper records changed during Flight56")
    need(set(diagnostics) - set(helper_history["diagnostics"]) == set(CURRENT["formal_helper_record_names"])
         and len(CURRENT["formal_helper_record_names"]) == 13,
         "only the exact thirteen indexed formal records may extend historical37")
    web = root / "task" / "web-helper"
    expected_web = {Path(row["path"]).name for row in collection["task_files"]
                    if row["relative_path"].startswith("web-helper/")}
    need(set(p.name for p in web.iterdir()) == expected_web
         and set(p.name for p in (root / "helper").iterdir()) == set(diagnostics),
         "frozen lifecycle reader may use only indexed current originals")
    def original_json(relative):
        return strict_json(originals[str(root / relative)])
    terminal = original_json("task/result.json")
    need(sha(originals[str(root / "task/result.json")]) == CURRENT["task_result_sha256"],
         "current terminal original differs")
    session = receipt["last_session"]
    require_terminal(session, terminal, task, 10481)
    need(session.get("status") == CURRENT["expected_status"]
         and session.get("state") == CURRENT["expected_state"]
         and type(session.get("steps")) is int and session["steps"] == CURRENT["expected_steps"]
         and session.get("web_helper_lease_unreleased") is False
         and type(terminal.get("steps")) is int and terminal["steps"] == CURRENT["expected_steps"]
         and terminal.get("summary") == CURRENT["expected_state"]
         and terminal.get("completion_verified") is False and terminal.get("model_reported_success") is False
         and terminal.get("completion_evidence", {}).get("web_query_dispatched") is False,
         "current failed Flight56 must not become a business/query success")
    support_raw = host_original(WEB56_SUPPORT, observed, 256 << 10)
    spec = importlib.util.spec_from_file_location("frozen_actual_web55_original_links", WEB56_SUPPORT["path"])
    support = importlib.util.module_from_spec(spec)
    exec(compile(support_raw, WEB56_SUPPORT["path"], "exec"), support.__dict__)
    plan, plan_raw = support.plan_for("flight")
    need(same_json_types(receipt.get("plan"), plan) and receipt.get("plan_sha256") == sha(plan_raw)
         and receipt.get("instruction") == plan["instruction"]
         and receipt.get("instruction_sha256") == plan["instruction_sha256"]
         and receipt.get("support_sha256") == WEB56_SUPPORT["sha256"],
         "current frozen natural OWNER/plan/support binding differs")
    prefs = host_original(MAIN55_SAVED_PREFS, observed, 65536)
    choice = receipt["background_selection_from_preparation"]
    recomputed = support.background_choice_evidence(plan, prefs, choice["observed_app_labels"],
                                                     choice["automatic_target_text"], choice["initial_spinner_hidden"])
    need(same_json_types(recomputed, choice), "actual dual UI selection provenance differs")
    selection = {"mode": "background", "allowed_packages": [HELPER_PACKAGE], "bootstrap_package": HELPER_PACKAGE,
                 "bootstrap_source": "owner_intent_within_explicit_ui_selection", "bootstrap_model_issued": False,
                 "main_display_fallback": False, "home_allowed": False,
                 "owner_task_selection": recomputed["expected_owner_task_selection"]}
    owner = original_json("task/owner.json")
    need(owner.get("schema") == "hepta.local-owner.v1" and owner.get("task_id") == task
         and owner.get("instruction") == plan["instruction"]
         and owner.get("instruction_utf8_sha256") == plan["instruction_sha256"]
         and owner.get("external_model") is False and owner.get("automatic_resume") is False
         and same_json_types(owner.get("background_request"), selection)
         and same_json_types(session.get("background_request"), selection)
         and same_json_types(owner.get("task_authorization"), session.get("task_authorization"))
         and same_json_types(owner.get("completion_contract"), session["completion_evidence"]["contract"]),
         "full original OWNER/Selection must independently match saved dual UI preferences")
    bootstrap = original_json("task/background-bootstrap.json")
    cleanup = original_json("task/background-cleanup.json")
    for value in (bootstrap, cleanup, terminal["background_session"], terminal["background_cleanup"]):
        typed_projection(value, {"schema": "hepta.background-session.v1", "task_id": task, "app_uid": 10481,
             "owner_sha256": plan["instruction_sha256"], "generation": receipt["web_lifecycle"]["generation"],
             "display_id": receipt["web_lifecycle"]["display_id"], "selection": selection,
             "spawn_attempted": True, "bootstrap_dispatched": True, "bootstrap_model_issued": False},
             "current actual background lease")
    need(bootstrap["state"] == "ACTIVE" and bootstrap["retired"] is False
         and cleanup["state"] == "RELEASED" and cleanup["retired"] is True
         and cleanup["cleanup_known"] is True and cleanup["cleanup_error"] is None
         and cleanup["broker_process_exit_observed"] is True
         and type(cleanup["broker_process_exit_code"]) is int and cleanup["broker_process_exit_code"] == 0
         and same_json_types(cleanup, terminal["background_cleanup"])
         and same_json_types({k: v for k, v in cleanup.items() if k not in ("cleanup_known", "cleanup_error")},
                             terminal["background_session"]),
         "actual dispatched background lease must be normally released, not unstarted")
    parent = CURRENT["parent_generation"]
    app_raw = originals[str(root / "runs" / parent / "app-session-receipt.json")]
    app = strict_json(app_raw)
    native = original_json("runs/" + parent + "/native-session-result.json")
    typed_projection(terminal["model_session"], {
        "worker_generation": parent, "task_id": task, "process_started": True,
        "process_exit_observed": True, "exit_code": 0, "receipt_valid": True,
        "app_receipt_sha256": sha(app_raw)}, "current terminal native-parent binding")
    typed_projection(app, {"schema": "hepta.local-model.task-session.v1",
        "worker_generation": parent, "task_id": task, "app_uid": 10481,
        "process_started": True, "process_exit_observed": True, "exit_code": 0,
        "force_destroy_sent": False, "requests_sent": 1, "requests_accepted": 1,
        "cleanup_known": True, "native_session_binding_valid": True, "cancel_requested": False,
        "cancellation_sdk_cleanup_binding_valid": False, "cleanup_classification": "normal_close_with_observed_sdk_cleanup",
        "automatic_restart": False, "cross_task_reuse": False}, "current actual app parent receipt")
    typed_projection(native, {"schema": "hepta.geniex-task-session.result.v1",
        "worker_generation": parent, "task_id": task, "process_exit_observed": False,
        "requests_received": 1, "requests_completed": 1, "model_hash_count": 1,
        "sdk_init_count": 1, "model_create_count": 1, "model_reset_count": 1,
        "model_metadata_unchanged_before_close": True, "close_requested": True,
        "signal_observed": 0, "last_request_status": 0, "sdk_destroy_attempted": True, "sdk_destroy_rc": 0,
        "sdk_deinit_attempted": True, "sdk_deinit_rc": 0, "control_done_attempts": 1,
        "control_done_delivered": 1, "control_channel_write_failed": False,
        "control_channel_last_errno": 0, "last_request_return_status": 0}, "current actual native parent receipt")
    need(same_json_types(app.get("native_session_receipt"), native),
         "native parent must equal the app receipt's exact nested original")
    cancellation = app["owned_worker_cancellation"]
    typed_projection(cancellation, {"schema": "hepta.owned-worker-cancellation.v1",
        "task_id": task, "worker_generation": parent, "requested": False,
        "termination_started": False, "term_destroy_attempts": 0, "force_destroy_attempts": 0,
        "process_exit_observed": True, "exit_code": 0, "sdk_cleanup_proven_by_this_object": False},
        "normal close must not be upgraded into cancellation proof")
    journal_raw = originals[str(root / "helper/lease-journal.json")]
    need(sha(journal_raw) == receipt["helper_journal_after_sha256"],
         "current helper journal digest differs")
    lifecycle = support.original_web_summary(root, task, plan, installed, journal_raw, True)
    need(same_json_types(lifecycle, receipt["web_lifecycle"])
         and lifecycle["bound_capture_present"] is True and len(lifecycle["captures"]) == 2
         and lifecycle["ordinary_close_verified"] is True and lifecycle["missing"] == []
         and lifecycle["business_verified"] is False and lifecycle["sdk_teardown_verified"] is False
         and lifecycle["display_id"] == session["completion_evidence"]["display_id"]
         and lifecycle["generation"] == session["completion_evidence"]["background_generation"],
         "frozen original helper lifecycle replay differs from the retained failed-run receipt")
    need(index.get("schema") == "hepta.v56-original-capture-fd-index.v1" and index.get("task_id") == task
         and index.get("index_is_capture_or_business_verdict") is False and index.get("business_verified") is False
         and type(index.get("raw_fd_file_count")) is int and index["raw_fd_file_count"] == 2
         and type(index.get("files")) is list and len(index["files"]) == 2,
         "original raw FD index must remain a two-file provenance index")
    for item in index["files"]:
        path = str(root / item["relative_path"])
        need(path in rows and item["bytes"] == rows[path]["bytes"] and item["sha256"] == rows[path]["sha256"]
             and item["business_verified"] is False, "raw FD index-to-original binding differs")
    return {"identity": installed["helper"], "diagnostics": diagnostics, "current_original_files": main_rows,
            "original_flight_result": dict(CURRENT["result"]), "original_collection": dict(CURRENT["collection"]),
            "original_capture_index": dict(CURRENT["capture_index"]), "support": dict(WEB56_SUPPORT),
            "expected_session": session, "expected_terminal_model_session": terminal["model_session"],
            "full_original_owner_and_selection_verified": True, "saved_ui_preferences_sha256": sha(prefs),
            "expected_selection": selection, "current_task_id": task, "current_task_status": "failed",
            "model_request_ids": list(CURRENT["request_ids"]), "parent_generation": parent,
            "parent_app_receipt_sha256": sha(app_raw), "native_normal_close_verified_from_originals": True,
            "native_self_process_exit_observed": False, "app_process_exit_observed": True,
            "outer_sdk_teardown_verified_retained": False, "web_lifecycle": lifecycle,
            "historical_helper_records_preserved": 37, "current_helper_records": len(diagnostics),
            "unstarted_is_five_flag_close": False, "formal_lease_cleanup_verified": True,
            "business_verified": False, "qualified": False,
            "collection_is_atomic_device_snapshot": False}

def verified_current_recovery56(observed, retained_helper):
    receipt = strict_json(host_original(CURRENT["result"], observed, 8 << 20))
    task, parent = CURRENT["task_id"], CURRENT["parent_generation"]
    root = Path(CURRENT["evidence_directory"])
    need(root == BASE / "background-notes-v56-lfm3-recovery-r1/evidence"
         and receipt.get("schema") == "hepta.background-notes-acceptance.v1"
         and receipt.get("driver_revision") == "notes-background-v56-dual-ui-actual-signed-comma-r1"
         and receipt.get("test_mode") == "background_only"
         and receipt.get("task_id") == task and receipt.get("qualified") is False
         and receipt.get("infrastructure_checks_passed") is True
         and receipt.get("runtime_config_sha256") == CURRENT["config_sha256"]
         and receipt.get("ui_preferences_original_sha256") == CURRENT["prefs_sha256"]
         and receipt.get("ui_preferences_unchanged") is True,
         "exact current Recovery56 collector original required without changing its false qualification")
    need(same_json_types(receipt.get("actual_build_binding"), {
             "build_receipt_sha256": V56_BUILD_SHA, "source_commit": V56_SOURCE,
             "source_inventory_sha256": V56_INVENTORY, "version_code": 56,
             "apk_sha256": V56_APK_SHA, "same_signer_verified_by_actual_receipt": True})
         and same_json_types(receipt.get("installed_identity_before"), receipt.get("installed_identity_after"))
         and same_json_types(receipt["installed_identity_after"]["hepta"], CURRENT["main_identity"])
         and same_json_types(receipt.get("recomputed_effective_background_request"), CURRENT["selection"]),
         "actual signed Main56 identity or exact Notes-only Selection differs")
    lock = receipt.get("operation_lock")
    need(type(lock) is dict and lock.get("acquired") is True and lock.get("released") is True
         and lock.get("continuity_verified") is True and lock.get("reacquisition_attempted") is False,
         "actual recovery independent owner lock must have been released normally")
    acceptance = receipt.get("acceptance")
    need(type(acceptance) is dict and all(acceptance.get(k) is True for k in (
             "cleanup_confirmed_by_app_broker_and_system", "journal_absent", "broker_process_exit_observed"))
         and type(acceptance.get("broker_process_exit_code")) is int
         and acceptance["broker_process_exit_code"] == 0
         and acceptance.get("generation") == CURRENT["generation"]
         and type(acceptance.get("display_id")) is int
         and acceptance["display_id"] == CURRENT["display_id"],
         "actual recovery background resources are not normally retired")
    collection = receipt.get("collection")
    need(type(collection) is dict and collection.get("task_id") == task
         and collection.get("errors") == [] and collection.get("omitted_screenshots") == 0
         and collection.get("task_model_sessions_valid") is True
         and type(collection.get("files")) is list and len(collection["files"]) == CURRENT["task_file_count"]
         and type(collection.get("associated_runs")) is list and len(collection["associated_runs"]) == 1
         and type(collection.get("task_model_sessions")) is list and len(collection["task_model_sessions"]) == 1,
         "complete actual recovery task, one request and one parent inventory required")
    request = collection["associated_runs"][0]
    parent_index = collection["task_model_sessions"][0]
    need(request.get("run_id") == CURRENT["request_ids"][0]
         and request.get("worker_generation") == parent and request.get("task_request_binding_valid") is True
         and parent_index.get("worker_generation") == parent and parent_index.get("binding_valid") is True
         and parent_index.get("process_exit_observed") is True
         and type(parent_index.get("exit_code")) is int and parent_index["exit_code"] == 0
         and type(parent_index.get("requests_received")) is int and parent_index["requests_received"] == 1,
         "actual request and distinct normally exited parent generation required")
    members = list(collection["files"]) + list(request["files"]) + list(parent_index["files"])
    originals, main_rows = {}, []
    for row in members:
        need(type(row) is dict and set(row) == {"path", "bytes", "sha256"}
             and type(row["path"]) is str
             and re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", row["path"])
             and all(part not in (".", "..") for part in row["path"].split("/")),
             "fixed original recovery path required")
        relative = row["path"]
        parts = relative.split("/")
        if parts[0] == "task":
            need(row in collection["files"] and len(parts) >= 2, "actual task inventory membership")
            device_path = "files/control-tasks/" + task + "/" + "/".join(parts[1:])
        else:
            need(len(parts) == 3 and parts[0] == "runs"
                 and parts[1] in CURRENT["request_ids"] + [parent], "actual request or parent file only")
            device_path = "files/" + relative
        need(relative not in originals, "duplicate recovery original")
        pin = {"path": str(root / relative), "bytes": row["bytes"], "sha256": row["sha256"]}
        empty_stdout = relative == "runs/" + parent + "/stdout.log"
        originals[relative] = host_original(pin, observed, 2 << 20, allow_empty=empty_stdout)
        main_rows.append({**pin, "package": PKG, "device_path": device_path, "relative_path": relative})
    need(len(members) == CURRENT["task_file_count"] + CURRENT["model_file_count"] == 56
         and sum(len(raw) for raw in originals.values()) == 1051558
         and {row["path"] for row in request["files"]} == {
             "runs/" + CURRENT["request_ids"][0] + "/" + name for name in
             ("app-receipt.json", "formatted-prompt.txt", "grammar.gbnf", "native-result.json",
              "prompt-evidence.json", "prompt.txt", "raw-text.txt", "system.txt")}
         and {row["path"] for row in parent_index["files"]} == {
             "runs/" + parent + "/" + name for name in
             ("app-session-receipt.json", "native-session-result.json", "stderr.log", "stdout.log")},
         "all56 actual recovery originals must be preserved; no synthesized LE32 or extra model call")
    def original_json(relative):
        return strict_json(originals[relative])
    terminal, session = original_json("task/result.json"), receipt["last_session"]
    need(sha(originals["task/result.json"]) == CURRENT["task_result_sha256"],
         "actual recovery terminal original SHA differs")
    require_terminal(session, terminal, task, 10481, receipt)
    need(session.get("status") == CURRENT["expected_status"] and session.get("state") == CURRENT["expected_state"]
         and type(session.get("steps")) is int and session["steps"] == CURRENT["expected_steps"]
         and session.get("web_helper_lease_unreleased") is False
         and session.get("completion_verified") is True and session.get("goal_independently_verified") is True
         and session.get("model_reported_success") is False
         and type(terminal.get("steps")) is int and terminal["steps"] == CURRENT["expected_steps"]
         and terminal.get("summary") == CURRENT["expected_state"]
         and terminal.get("completion_verified") is True and terminal.get("model_reported_success") is False,
         "current controller-verified Notes terminal must remain its original success and cleanup")
    owner, selection = original_json("task/owner.json"), CURRENT["selection"]
    plan = receipt["plan"]
    need(plan.get("instruction") == receipt.get("instruction")
         and plan.get("instruction_sha256") == receipt.get("instruction_sha256") == CURRENT["owner_sha256"]
         and sha(receipt["instruction"].encode("utf-8")) == CURRENT["owner_sha256"]
         and owner.get("schema") == "hepta.local-owner.v1" and owner.get("task_id") == task
         and owner.get("instruction") == plan["instruction"]
         and owner.get("instruction_utf8_sha256") == CURRENT["owner_sha256"]
         and owner.get("external_model") is False and owner.get("automatic_resume") is False
         and same_json_types(owner.get("background_request"), selection)
         and same_json_types(session.get("background_request"), selection)
         and same_json_types(owner.get("task_authorization"), session.get("task_authorization"))
         and same_json_types(owner.get("completion_contract"), session["completion_evidence"]["contract"]),
         "actual Recovery56 OWNER, complete Selection and terminal contract differ")
    prefs = host_original(MAIN55_SAVED_PREFS, observed, 65536)
    need(sha(prefs) == CURRENT["prefs_sha256"]
         and receipt["original_ui_selection"]["allowed_packages"] ==
             ["com.motorola.stylus", HELPER_PACKAGE]
         and receipt["original_ui_selection"]["bootstrap_package"] == "com.motorola.stylus"
         and selection["owner_task_selection"]["original_ui_allowed_packages"] ==
             receipt["original_ui_selection"]["allowed_packages"]
         and selection["owner_task_selection"]["original_ui_initial_package"] ==
             receipt["original_ui_selection"]["bootstrap_package"],
         "actual saved dual UI scope and current Notes-only scope must remain separate")
    bootstrap = original_json("task/background-bootstrap.json")
    cleanup = original_json("task/background-cleanup.json")
    for value in (bootstrap, cleanup, terminal["background_session"], terminal["background_cleanup"]):
        typed_projection(value, {"schema": "hepta.background-session.v1", "task_id": task, "app_uid": 10481,
             "owner_sha256": CURRENT["owner_sha256"], "generation": CURRENT["generation"],
             "display_id": CURRENT["display_id"], "selection": selection,
             "spawn_attempted": True, "bootstrap_dispatched": True, "bootstrap_model_issued": False},
             "current actual Notes background lease")
    need(bootstrap["state"] == "ACTIVE" and bootstrap["retired"] is False
         and cleanup["state"] == "RELEASED" and cleanup["retired"] is True
         and cleanup["cleanup_known"] is True and cleanup["cleanup_error"] is None
         and cleanup["broker_process_exit_observed"] is True
         and type(cleanup["broker_process_exit_code"]) is int and cleanup["broker_process_exit_code"] == 0
         and same_json_types(cleanup, terminal["background_cleanup"])
         and same_json_types({k: v for k, v in cleanup.items() if k not in ("cleanup_known", "cleanup_error")},
                             terminal["background_session"]),
         "actual recovery background lease must be normally released")
    app_raw = originals["runs/" + parent + "/app-session-receipt.json"]
    app, native = strict_json(app_raw), original_json("runs/" + parent + "/native-session-result.json")
    typed_projection(terminal["model_session"], {
        "worker_generation": parent, "task_id": task, "process_started": True,
        "process_exit_observed": True, "exit_code": 0, "receipt_valid": True,
        "app_receipt_sha256": sha(app_raw)}, "current terminal native-parent binding")
    typed_projection(app, {"schema": "hepta.local-model.task-session.v1",
        "worker_generation": parent, "task_id": task, "app_uid": 10481,
        "process_started": True, "process_exit_observed": True, "exit_code": 0,
        "force_destroy_sent": False, "requests_sent": 1, "requests_accepted": 1,
        "cleanup_known": True, "native_session_binding_valid": True, "cancel_requested": False,
        "cancellation_sdk_cleanup_binding_valid": False, "cleanup_classification": "normal_close_with_observed_sdk_cleanup",
        "automatic_restart": False, "cross_task_reuse": False}, "current actual app parent receipt")
    typed_projection(native, {"schema": "hepta.geniex-task-session.result.v1",
        "worker_generation": parent, "task_id": task, "process_exit_observed": False,
        "requests_received": 1, "requests_completed": 1, "model_hash_count": 1,
        "sdk_init_count": 1, "model_create_count": 1, "model_reset_count": 1,
        "model_metadata_unchanged_before_close": True, "close_requested": True,
        "signal_observed": 0, "last_request_status": 0, "sdk_destroy_attempted": True, "sdk_destroy_rc": 0,
        "sdk_deinit_attempted": True, "sdk_deinit_rc": 0, "control_done_attempts": 1,
        "control_done_delivered": 1, "control_channel_write_failed": False,
        "control_channel_last_errno": 0, "last_request_return_status": 0}, "current actual native parent receipt")
    need(same_json_types(app.get("native_session_receipt"), native),
         "native parent must equal the app receipt's exact nested original")
    typed_projection(app["owned_worker_cancellation"], {"schema": "hepta.owned-worker-cancellation.v1",
        "task_id": task, "worker_generation": parent, "requested": False,
        "termination_started": False, "term_destroy_attempts": 0, "force_destroy_attempts": 0,
        "process_exit_observed": True, "exit_code": 0, "sdk_cleanup_proven_by_this_object": False},
        "normal recovery close must not be relabelled as the earlier cancellation")
    request_id = CURRENT["request_ids"][0]
    app_request = original_json("runs/" + request_id + "/app-receipt.json")
    native_request = original_json("runs/" + request_id + "/native-result.json")
    typed_projection(app_request, {"schema": "hepta.local-model.task-request.v1",
        "task_id": task, "worker_generation": parent, "run_id": request_id, "request_sequence": 1,
        "app_uid": 10481, "package_name": PKG, "compute_requested": "npu", "context_tokens": 8192,
        "request_committed": True, "inference_completed": True, "native_result_binding_valid": True,
        "process_exit_observed": False, "status": "request_completed"}, "current one actual native request")
    typed_projection(native_request, {"schema": "hepta.geniex-task-request.result.v1",
        "task_id": task, "worker_generation": parent, "request_id": request_id, "request_sequence": 1,
        "generation_complete": True, "request_status": 0, "worker_outcome": "completed",
        "compute_requested": "npu", "device_resolved": "HTP0", "process_exit_observed": False},
        "current native request outcome, distinct from parent process exit")
    need(same_json_types(app_request.get("native_receipt"), native_request),
         "current request app and native original must be exactly bound")
    return {"identity": retained_helper["identity"], "diagnostics": retained_helper["diagnostics"],
            "current_original_files": main_rows, "current_recovery_result": dict(CURRENT["result"]),
            "expected_session": session, "expected_terminal_model_session": terminal["model_session"],
            "controller_terminal_proof": {k: receipt[k] for k in (
                "schema", "driver_revision", "qualified", "task_id", "actual_build_binding", "last_session")},
            "controller_terminal_proof_is_original_projection": True, "expected_selection": selection,
            "current_task_id": task, "current_task_status": CURRENT["expected_status"],
            "full_original_owner_and_selection_verified": True, "saved_ui_preferences_sha256": sha(prefs),
            "model_request_ids": list(CURRENT["request_ids"]), "parent_generation": parent,
            "parent_app_receipt_sha256": sha(app_raw), "native_normal_close_verified_from_originals": True,
            "native_self_process_exit_observed": False, "app_process_exit_observed": True,
            "control_session_sha256_presealed": False, "control_session_typed_actual_receipt_bound": True,
            "original_collector_qualified_retained": False, "current_helper_records": 50,
            "retained_helper_flight56": retained_helper, "formal_lease_cleanup_verified": True,
            "unstarted_is_five_flag_close": False, "business_verified": False, "qualified": False,
            "collection_is_atomic_device_snapshot": False}



def verified_helper6_install(observed):
    history = verified_historical_helper6_install(observed)
    previous = verified_previous_main56(observed, history)
    retained = verified_retained_flight56(observed, history)
    current = verified_current_recovery56(observed, retained)
    current["historical_helper6_installation"] = history
    current["previous_main56_installation"] = previous
    return current



def execute(args, report, helper, notes, r7, profiles, pa, receipts, binder, helper_prerequisite):
    check_owner, owner_fd = notes.owner_guard(args)
    report["owner_guard"] = {"pid": args.owner_pid, "start_ticks": args.owner_start_ticks, "boot_id": args.owner_boot_id, "root": str(args.owner_root)}
    enabled_before = global_before = None
    sequence = 0

    class GuardedAdb(pa.Adb):
        def command(self, *values, **options):
            check_owner()
            result = super().command(*values, **options)
            check_owner()
            return result

    adb = GuardedAdb(args, args.out)
    r7.bounded_private_reader(adb)
    mobi_source = args.source_tools.parent / MOBI_PIN_SOURCE
    mobi_pins = mobimind_cache_pins(helper.local_file(mobi_source, MOBI_PIN_SOURCE_SHA))
    report["model_cache_contract"] = {"mobi_pin_source_sha256": MOBI_PIN_SOURCE_SHA,
        "mobi_directory": MOBI_DIRECTORY, "mobi_file_count": len(mobi_pins),
        "inactive_import_residue": {"path": OLD_IMPORT_PART, "bytes": OLD_IMPORT_BYTES, "sha256": OLD_IMPORT_SHA,
                                    "enabled_or_deleted": False},
        "unknown_large_files_allowed": False, "other_gguf_scope": "pinned size plus complete stat continuity; selected model fully hashed"}
    save = lambda path, raw: r7.write_new(args.out / path, raw, binary=True)
    text = lambda command, label, timeout=None: adb.command(command, label=label, timeout=timeout)[1].decode("utf-8", errors="strict")
    host_env = dict(os.environ)
    host_env["JAVA_HOME"] = str(args.java_home)
    host_env["PATH"] = str(args.java_home / "bin") + os.pathsep + host_env.get("PATH", "")

    def host_command(label, argv, timeout=45):
        nonlocal sequence
        check_owner()
        sequence += 1
        began = time.time()
        try:
            completed = subprocess.run(argv, capture_output=True, timeout=timeout, env=host_env)
            code, stdout, stderr, timed_out = completed.returncode, completed.stdout, completed.stderr, False
        except subprocess.TimeoutExpired as error:
            code, stdout, stderr, timed_out = None, error.stdout or b"", error.stderr or b"", True
        stem = "host-commands/%03d-%s" % (sequence, label)
        save(stem + ".stdout", stdout)
        save(stem + ".stderr", stderr)
        r7.write_new(args.out / (stem + ".json"), {"argv": argv, "exit_code": code, "client_timed_out": timed_out,
                     "started_wall_s": began, "elapsed_s": time.time() - began, "stdout_sha256": sha(stdout), "stderr_sha256": sha(stderr)})
        check_owner()
        need(code == 0, label + ": host command failed/timed out; phone-side outcome may be unknown, no retry")
        return stdout

    def identity(label, expected_sha, expected_version=None):
        value = r7.package_identity(adb, PKG, label)
        need(value["uid"] == args.expected_uid and len(value["apks"]) == 1 and value["apks"][0]["sha256"] == expected_sha, "exact installed APK/UID differs")
        need(text(["run-as", PKG, "id", "-u"], label + "-run-as-uid").strip() == str(args.expected_uid), "run-as identity differs")
        package = text(["dumpsys", "package", PKG], label + "-package")
        save(label + "-package.txt", package.encode())
        return {**value, "version_code": installed_version(package, expected_version)}

    def formal(label, wait=False):
        last = None
        for index in range(16 if wait else 1):
            raw = text(["dumpsys", "activity", "services", PKG + "/.HeptaAccessibilityService"], label + "-formal")
            try:
                value = r7.formal_service_binding(raw, args.expected_uid)
                save(label + "-formal.txt", raw.encode())
                return value
            except RuntimeError as error:
                last = error
                if wait and index < 15:
                    time.sleep(.5)
        raise RuntimeError("formal accessibility binding unavailable: " + str(last))

    def restore(label):
        current = text(["settings", "get", "secure", "enabled_accessibility_services"], label + "-services").strip()
        target = helper.restoration_allowed(enabled_before, current)
        global_now = text(["settings", "get", "secure", "accessibility_enabled"], label + "-global").strip()
        need(global_before == "1" and global_now in ("0", "1"), "unsupported accessibility global state")
        if current != target:
            adb.command(["settings", "put", "secure", "enabled_accessibility_services", target], label=label + "-restore-prior-formal")
        if global_now != global_before:
            adb.command(["settings", "put", "secure", "accessibility_enabled", global_before], label=label + "-restore-prior-global")
        need(text(["settings", "get", "secure", "enabled_accessibility_services"], label + "-verify-services").strip() == enabled_before
             and text(["settings", "get", "secure", "accessibility_enabled"], label + "-verify-global").strip() == global_before, "prior accessibility state did not restore exactly")
        report["accessibility_restored_exactly"] = True

    def idle(label):
        raw_session = adb.app_bytes("files/control-session.json")
        result_path = "files/control-tasks/" + CURRENT["task_id"] + "/result.json"
        raw_result = adb.app_bytes(result_path)
        session, terminal = pa.strict_json(raw_session), pa.strict_json(raw_result)
        need(sha(raw_result) == CURRENT["task_result_sha256"]
             and same_json_types(session, helper_prerequisite["expected_session"])
             and session.get("status") == CURRENT["expected_status"]
             and session.get("state") == CURRENT["expected_state"]
             and session.get("web_helper_lease_unreleased") is False,
             "current actual Recovery56 typed session or original terminal changed")
        require_terminal(session, terminal, CURRENT["task_id"], args.expected_uid,
                         helper_prerequisite["controller_terminal_proof"])
        if label == "before":
            report["current_session_first_observed_sha256"] = sha(raw_session)
            report["current_session_sha256_presealed"] = False
            report["current_session_raw_preserved_for_all_subsequent_checks"] = True
        need(type(terminal.get("steps")) is int and terminal["steps"] == CURRENT["expected_steps"]
             and terminal.get("summary") == CURRENT["expected_state"]
             and same_json_types(terminal.get("model_session"), helper_prerequisite["expected_terminal_model_session"])
             and terminal.get("completion_verified") is True
             and session.get("completion_verified") is True
             and terminal.get("model_reported_success") is False,
             "current Notes recovery must retain one request and its observed normal native close")
        require_no_barriers(text(["run-as", PKG, "find", "files", "-mindepth", "1", "-maxdepth", "1"], label + "-state-files").splitlines())
        snapshots = {"files/control-session.json": raw_session, result_path: raw_result}
        for item in helper_prerequisite["current_original_files"]:
            need(item["package"] == PKG and (
                 item["device_path"].startswith("files/control-tasks/" + CURRENT["task_id"] + "/")
                 or any(item["device_path"].startswith("files/runs/" + run + "/")
                        for run in CURRENT["request_ids"] + [CURRENT["parent_generation"]])),
                 "fixed current task/model original")
            raw = adb.app_bytes(item["device_path"])
            need(len(raw) == item["bytes"] and sha(raw) == item["sha256"],
                 "original current task/model member changed")
            snapshots[item["device_path"]] = raw
        for journal, schema in helper.DIAGNOSTICS.items():
            raw = adb.app_bytes("files/" + journal, optional=True)
            if raw is not None:
                helper.diagnostic_clean(pa.strict_json(raw), schema, args.expected_uid)
            snapshots["files/" + journal] = raw
        permission_raw = adb.app_bytes("files/background-permission-session.json", optional=True)
        snapshots["files/background-permission-session.json"] = permission_raw
        if permission_raw is not None:
            value = pa.strict_json(permission_raw)
            helper.permission_clean(value, args.expected_uid)
            need(value.get("result_file") in ("result.json", "late-exit.json"), "unrecognized old permission receipt")
            path = "files/background-permission-runs/" + value["request_id"] + "/" + value["result_file"]
            raw = adb.app_bytes(path)
            need(sha(raw) == value["result_sha256"] and same_json_types(pa.strict_json(raw),
                 {key: value for key, value in value.items() if key not in ("result_sha256", "result_file")}),
                 "permission history receipt differs")
            snapshots[path] = raw
        processes = adb.command(["ps", "-A", "-o", "UID,PID,PPID,ARGS"], label=label + "-processes")[1]
        helper.process_rows(processes, args.expected_uid)
        save(label + "-processes.txt", processes)
        displays = text(["cmd", "display", "get-displays"], label + "-displays")
        parsed = r7.parse_displays(displays)
        need(not any(row["name"].startswith("hepta-bg-") for row in parsed.values()), "background display still exists")
        save(label + "-displays.txt", displays.encode())
        sockets = text(["cat", "/proc/net/unix"], label + "-unix-sockets")
        need("hepta-bg-" not in sockets, "background broker socket still exists")
        save(label + "-unix-sockets.txt", sockets.encode())
        for path, raw in snapshots.items():
            if raw is not None:
                save(label + "/" + path.replace("/", "__"), raw)
        return snapshots

    def preferences(label):
        script = ("test -d shared_prefs && test ! -L shared_prefs && test -f " + PREFERENCES_PATH
                  + " && test ! -L " + PREFERENCES_PATH
                  + " && stat -c '%d %i %u %s %h %f %Y %Z' " + PREFERENCES_PATH)
        before = parse_cache_stat(text(["run-as", PKG, "sh", "-c", script], label + "-preferences-before"), args.expected_uid)
        need(0 < before["bytes"] <= 65536, "bounded existing UI preferences required")
        raw = adb.command(["run-as", PKG, "head", "-c", "65537", PREFERENCES_PATH], label=label + "-preferences-read", raw=True)[1]
        after = parse_cache_stat(text(["run-as", PKG, "sh", "-c", script], label + "-preferences-after"), args.expected_uid)
        need(before == after and len(raw) == before["bytes"], "UI preferences changed during bounded read")
        save(label + "-background-ui-choice.xml", raw)
        return raw

    def helper_preservation(label, prerequisite):
        observed = r7.package_identity(adb, HELPER_PACKAGE, label + "-helper-identity")
        need(same_json_types(observed, prerequisite["identity"])
             and text(["run-as", HELPER_PACKAGE, "id", "-u"], label + "-helper-uid").strip() == str(HELPER_UID),
             "actual helper package or UID changed")
        listing_script = ("test -d files && test ! -L files && test -d files/web-evidence-v1"
                          " && test ! -L files/web-evidence-v1 && ls -1 files/web-evidence-v1")
        names_raw = text(["run-as", HELPER_PACKAGE, "sh", "-c", listing_script], label + "-helper-inventory")
        names = names_raw.splitlines()
        need(len(names_raw.encode()) <= 32768 and 0 < len(names) <= 256 and len(set(names)) == len(names)
             and set(names) == set(prerequisite["diagnostics"]), "helper inventory changed after actual helper6 preserving installation")
        rows = {}
        for index, name in enumerate(sorted(names)):
            need(re.fullmatch(r"(?:diagnostic-[0-9a-f]{64}|diagnostic-(?:close|unstarted)-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})\.json", name)
                 or name in CURRENT["formal_helper_record_names"],
                 "unknown helper private record outside exact retained50; lease or orphan may remain")
            relative = "files/web-evidence-v1/" + name
            quoted = shlex.quote(relative)
            command = ("test -f " + quoted + " && test ! -L " + quoted
                       + " && stat -c '%d %i %u %s %h %f %Y %Z' " + quoted
                       + " && sha256sum " + quoted
                       + " && stat -c '%d %i %u %s %h %f %Y %Z' " + quoted)
            lines = text(["run-as", HELPER_PACKAGE, "sh", "-c", command], label + "-helper-original-%03d" % index).splitlines()
            need(len(lines) == 3, "actual helper stat/hash/stat triplet required")
            before = parse_cache_stat(lines[0], HELPER_UID)
            after = parse_cache_stat(lines[2], HELPER_UID)
            expected = prerequisite["diagnostics"][name]
            need(before == after and before["bytes"] == expected["bytes"]
                 and lines[1] == expected["sha256"] + "  " + relative,
                 "original helper diagnostic bytes/type/UID changed")
            rows[name] = {**expected, "stat": before}
        again = text(["run-as", HELPER_PACKAGE, "sh", "-c", listing_script], label + "-helper-inventory-after").splitlines()
        need(len(again) == len(names) and set(again) == set(names), "helper membership changed during preservation check")
        r7.write_new(args.out / (label + "-helper-diagnostics.json"), rows)
        return rows

    def current_main_focus(label):
        raw = text(["dumpsys", "window", "displays"], label + "-focus")
        save(label + "-window-displays.txt", raw.encode())
        focus = notes.display0_focus(r7, raw)
        need(focus["focus_package"] == PKG and re.search(
             r"/(?:\.MainActivity|org\.trillionnium\.hepta\.local\.MainActivity)\}$", focus["focus_line"]),
             "current physical display must be ordinary main activity; no manual helper page may be active")
        return focus

    def run_inventory():
        return {path: adb.list_children(path, directories=True) for path in ("files/runs", "files/control-tasks", "files/mobi-runs", "files/ui-venus-runs")}

    def cache_stat(path, label, directory=False):
        parents = ["files", "files/model"]
        if path.startswith(MOBI_DIRECTORY + "/"):
            parents.append(MOBI_DIRECTORY)
        guards = ["test -d {p} && test ! -L {p}".format(p=shlex.quote(parent)) for parent in parents]
        guards.append(("test -d " if directory else "test -f ") + shlex.quote(path) + " && test ! -L " + shlex.quote(path))
        guards.append("stat -c '%d %i %u %s %h %f %Y %Z' " + shlex.quote(path))
        raw = text(["run-as", PKG, "sh", "-c", " && ".join(guards)], label)
        return parse_cache_stat(raw, args.expected_uid, directory)

    def cache_hash(path, label, expected=None):
        line = text(["run-as", PKG, "sha256sum", path], label, timeout=60).strip()
        match = re.fullmatch(r"([0-9a-f]{64})\s+(.+)", line)
        need(match is not None and match.group(2) == path and (expected is None or match.group(1) == expected),
             "full cached file SHA differs: " + path)
        return match.group(1)

    def model_inventory(label):
        adb.command(["run-as", PKG, "sh", "-c", "test -d files && test ! -L files && test -d files/model && test ! -L files/model"], label=label + "-model-directory")
        listing = text(["run-as", PKG, "find", "files/model", "-mindepth", "1", "-maxdepth", "1"], label + "-model-list").splitlines()
        need(0 < len(listing) <= 128 and len(set(listing)) == len(listing)
             and all(re.fullmatch(r"files/model/[A-Za-z0-9_.-]+", p) for p in listing), "unsupported model cache inventory")
        rows = {}
        def file_row(path, tag):
            before_stat = cache_stat(path, tag + "-stat")
            contract = cache_file_contract(path, before_stat["bytes"], profiles, mobi_pins)
            row = {"stat": before_stat, **contract}
            if contract["hash_content"]:
                row["sha256"] = cache_hash(path, tag + "-sha", contract["pin_sha256"])
                need(cache_stat(path, tag + "-stat-after-hash") == before_stat, "cache file changed during full hash: " + path)
            return row
        for index, path in enumerate(sorted(listing)):
            tag = label + "-model-%03d" % index
            if path == MOBI_DIRECTORY:
                before_stat = cache_stat(path, tag + "-directory-stat", directory=True)
                members = text(["run-as", PKG, "find", path, "-mindepth", "1", "-maxdepth", "1"], tag + "-members").splitlines()
                require_mobi_members(members, mobi_pins)
                rows[path] = {"kind": "pinned_mobimind_directory", "stat": before_stat}
                for child, member in enumerate(sorted(members)):
                    rows[member] = file_row(member, tag + "-file-%02d" % child)
                after_members = text(["run-as", PKG, "find", path, "-mindepth", "1", "-maxdepth", "1"], tag + "-members-after").splitlines()
                require_mobi_members(after_members, mobi_pins)
                need(cache_stat(path, tag + "-directory-stat-after", directory=True) == before_stat,
                     "MobiMind directory changed during inventory")
            else:
                rows[path] = file_row(path, tag)
        after_listing = text(["run-as", PKG, "find", "files/model", "-mindepth", "1", "-maxdepth", "1"], label + "-model-list-after").splitlines()
        need(len(after_listing) == len(listing) and set(after_listing) == set(listing), "model cache membership changed during inventory")
        r7.write_new(args.out / (label + "-model-inventory.json"), rows)
        return rows

    def selected_model_hash(label, selected, expected_stat):
        path = "files/model/" + selected["file"]
        need(cache_stat(path, label + "-selected-stat") == expected_stat, "selected model stat changed before full hash")
        cache_hash(path, label + "-selected-model-sha", selected["sha256"])
        need(cache_stat(path, label + "-selected-stat-after-hash") == expected_stat, "selected model changed during full hash")
        return {"path": path, "bytes": selected["bytes"], "sha256": selected["sha256"]}

    try:
        build_raw = helper.local_file(args.build_receipt, args.build_receipt_sha256)
        build = pa.strict_json(build_raw)
        need(build.get("all_pass") is True and build.get("apk_sha256") == args.new_apk_sha256
             and type(build.get("version_code")) is int and build["version_code"] == args.expected_version
             and build.get("signer_certificate_sha256") == CERT and build.get("signer_proof_sha256") == helper.SIGNER_PROOF_SHA
             and build.get("actual_compiler_inputs_bound_to_signed_asset") is True
             and helper.hex_value(build.get("source_commit"), 40), "new v57 build receipt is not the exact reviewed build")
        verify_v57_build_identity(build)
        historical_raw = helper.local_file(args.historical_build_receipt, HISTORICAL_BUILD_SHA)
        historical_build = pa.strict_json(historical_raw)
        old_installer_raw = helper.local_file(HISTORICAL_INSTALLER, HISTORICAL_INSTALLER_SHA, maximum=128 << 10)
        old_spec = importlib.util.spec_from_file_location("frozen_actual54_installer_identity", HISTORICAL_INSTALLER)
        old_installer = importlib.util.module_from_spec(old_spec)
        exec(compile(old_installer_raw, str(HISTORICAL_INSTALLER), "exec"), old_installer.__dict__)
        old_installer.verify_v54_build_identity(historical_build)
        need(helper.local_file(HISTORICAL_INSTALLER, HISTORICAL_INSTALLER_SHA, maximum=128 << 10) == old_installer_raw,
             "original historical identity verifier changed")
        need(historical_build.get("all_pass") is True and historical_build.get("apk_sha256") == HISTORICAL_APK_SHA
             and historical_build.get("signer_certificate_sha256") == CERT
             and historical_build.get("actual_compiler_inputs_bound_to_signed_asset") is True,
             "historical v54 signed build binding differs")
        save("historical-v54-build-receipt.json", historical_raw)
        new_apk = helper.local_file(args.new_apk, args.new_apk_sha256, maximum=256 << 20)
        need(build.get("apk_bytes") == len(new_apk), "new APK size differs from build receipt")
        save("reviewed-build-receipt.json", build_raw)
        report["new_build"] = {"receipt_sha256": sha(build_raw), "source_commit": build["source_commit"], "apk_path": str(args.new_apk), "apk_sha256": args.new_apk_sha256, "apk_bytes": len(new_apk), "version_code": args.expected_version}
        need(text(["am", "get-current-user"], "android-current-user").strip() == "0", "only Android user 0 covered")
        before = identity("before", args.old_apk_sha256)
        need(before["version_code"] == 56 and args.expected_version == 57
             and same_json_types({key: before[key] for key in ("package", "uid", "apks")}, CURRENT["main_identity"]),
             "this driver only upgrades the exact currently installed Main56 to actual signed Main57")
        report["installed_identity_before"] = before
        report["focus_before"] = current_main_focus("before")
        baseline = idle("before")
        report["actual_main56_helper6_current_recovery_prerequisite"] = helper_prerequisite
        helper_before = helper_preservation("before", helper_prerequisite)
        preferences_before = preferences("before")
        need(sha(preferences_before) == CURRENT["prefs_sha256"], "actual current dual-UI preferences changed")
        report["ui_preferences_before"] = {"file": "before-background-ui-choice.xml",
            "bytes": len(preferences_before), "sha256": sha(preferences_before), "modified_by_installer": False}
        config_raw = adb.app_bytes(helper.CONFIG_PATH)
        need(sha(config_raw) == args.expected_config_sha256, "exact current runtime configuration differs")
        configuration = pa.strict_json(config_raw)
        need(set(configuration) == {"schema", "model_profile", "compute", "context_tokens", "threads"}
             and configuration.get("schema") == "hepta.local-runtime.v2" and configuration.get("compute") in ("npu", "gpu")
             and type(configuration.get("context_tokens")) is int and configuration["context_tokens"] in (4096, 8192)
             and type(configuration.get("threads")) is int and 1 <= configuration["threads"] <= 8, "runtime configuration unsupported")
        selected = profiles.profile(configuration.get("model_profile"))
        save("runtime-config.before.json", config_raw)
        inventory = model_inventory("before")
        path = "files/model/" + selected["file"]
        need(path in inventory and inventory[path]["stat"]["bytes"] == selected["bytes"], "selected cached model size differs")
        report["selected_model_before"] = selected_model_hash("before", selected, inventory[path]["stat"])
        runs = run_inventory()
        enabled_before = text(["settings", "get", "secure", "enabled_accessibility_services"], "before-authorized-services").strip()
        global_before = text(["settings", "get", "secure", "accessibility_enabled"], "before-authorized-global").strip()
        helper.restoration_allowed(enabled_before, enabled_before)
        need(global_before == "1", "formal accessibility was not previously enabled")
        report["accessibility_before"] = {"services": enabled_before, "global": global_before}
        report["formal_binding_before"] = formal("before")
        pulled = args.out / "installed-before.apk"
        host_command("pull-installed-before-apk", adb.base + ["pull", before["apks"][0]["path"], str(pulled)], timeout=60)
        helper.local_file(pulled, args.old_apk_sha256, maximum=256 << 20)
        for label, apk in (("old", pulled), ("new", args.new_apk)):
            output = host_command(label + "-actual-apksigner-verify", [str(args.apksigner), "verify", "--print-certs", str(apk)]).decode("utf-8", errors="strict")
            report[label + "_actual_signer_certificate_sha256"] = signed_certificate(output)
        report["same_signer_actually_verified"] = True
        need(idle("preinstall-one") == baseline and adb.app_bytes(helper.CONFIG_PATH) == config_raw and run_inventory() == runs, "app state changed before upgrade")
        time.sleep(.5)
        need(idle("preinstall-two") == baseline, "app state is not quiescent")
        need(text(["settings", "get", "secure", "enabled_accessibility_services"], "preinstall-authorized-services").strip() == enabled_before
             and text(["settings", "get", "secure", "accessibility_enabled"], "preinstall-authorized-global").strip() == global_before, "accessibility authorization changed before install")
        helper.local_file(args.new_apk, args.new_apk_sha256, maximum=256 << 20)
        need(preferences("preinstall") == preferences_before
             and helper_preservation("preinstall", helper_prerequisite) == helper_before,
             "preferences or preserved helper6 data changed before the one install")
        current_main_focus("preinstall")
        r7.write_new(args.out / "INSTALL-INTENT.json", {"old_apk_sha256": args.old_apk_sha256, "new_apk_sha256": args.new_apk_sha256,
                     "expected_version": args.expected_version, "expected_terminal_task_id": args.expected_terminal_task_id,
                     "config_sha256": sha(config_raw), "same_signer_sha256": CERT, "lease_exception_allowed": False,
                     "data_clear_allowed": False, "task_start_allowed": False,
                     "helper6_install_failure_result_sha256": HELPER6_FAILED_INSTALL_RESULT["sha256"],
                     "helper6_install_reconciliation_result_sha256": HELPER6_INSTALL_RESULT["sha256"],
                     "previous_main56_install_result_sha256": MAIN56_INSTALL_RESULT["sha256"],
                     "current_recovery56_result_sha256": CURRENT["result"]["sha256"],
                     "retained_flight56_result_sha256": HELPER_CURRENT["result"]["sha256"],
                     "retained_helper50_collection_sha256": HELPER_CURRENT["collection"]["sha256"],
                     "helper_diagnostic_count_preserved": CURRENT["helper_count"]})
        report["install_submitted"] = True
        output = host_command("install-replace-preserving-data", adb.base + ["install", "-r", str(args.new_apk)], timeout=60)
        need(re.search(rb"(?m)^Success\r?$", output) is not None, "install did not return exact Success; no retry")
        report["install_success_returned"] = True
        after = identity("after-install", args.new_apk_sha256, args.expected_version)
        report["installed_identity_after"] = after
        need(adb.app_bytes(helper.CONFIG_PATH) == config_raw and idle("after-install") == baseline, "runtime or terminal journals changed at upgrade")
        need(model_inventory("after-install") == inventory, "model cache inventory/metadata changed at upgrade")
        report["selected_model_after"] = selected_model_hash("after-install", selected, inventory[path]["stat"])
        need(run_inventory() == runs, "upgrade created a task/model run")
        need(preferences("after-install") == preferences_before
             and helper_preservation("after-install", helper_prerequisite) == helper_before,
             "upgrade changed saved UI preferences or preserved helper6 data")
        adb.command(["am", "start", "-a", "android.intent.action.MAIN", "-c", "android.intent.category.LAUNCHER", "-n", PKG + "/.MainActivity"], label="normal-v57-main-no-task-extras")
        report["normal_main_launch_returned"] = True
        restore("after-launch")
        report["formal_binding_after"] = formal("after-launch", wait=True)
        need(idle("final") == baseline and adb.app_bytes(helper.CONFIG_PATH) == config_raw and run_inventory() == runs, "normal launch changed terminal/config/task state")
        need(identity("final", args.new_apk_sha256, args.expected_version) == after, "final installed identity changed")
        focus_raw = text(["dumpsys", "window", "displays"], "final-display0-focus")
        save("final-window-displays.txt", focus_raw.encode())
        focus = notes.display0_focus(r7, focus_raw)
        need(focus["focus_package"] == PKG and re.search(r"/(?:\.MainActivity|org\.trillionnium\.hepta\.local\.MainActivity)\}$", focus["focus_line"]), "normal MainActivity is not current on display 0")
        save("runtime-config.after.json", adb.app_bytes(helper.CONFIG_PATH))
        need(preferences("final") == preferences_before
             and helper_preservation("final", helper_prerequisite) == helper_before,
             "ordinary MAIN changed saved preferences or preserved helper bytes")
        report["ui_preferences_preserved_byte_for_byte"] = True
        report["helper_package_and_diagnostics_preserved"] = True
        report["helper_diagnostic_count_preserved"] = len(helper_before)
        report["helper_was_not_launched_or_modified"] = True
        report["retained_failed_flight56_is_not_reinterpreted"] = True
        report["unstarted_is_five_flag_close"] = False
        report["formal_lease_cleanup_verified"] = helper_prerequisite["formal_lease_cleanup_verified"]
        report["native_normal_close_verified_from_originals"] = helper_prerequisite["native_normal_close_verified_from_originals"]
        report["retained_flight56_outer_sdk_teardown_verified_retained"] = False
        report.update(installed_verified=True, final_focus=focus, runtime_config_preserved_byte_for_byte=True,
                      terminal_journals_preserved_byte_for_byte=True, selected_model_full_sha_preserved=True,
                      model_cache_inventory_preserved=True, no_new_tasks_or_model_runs=True)
    finally:
        try:
            if report.get("install_submitted") and not report.get("accessibility_restored_exactly"):
                try:
                    # After an uncertain install, only a settled old/new exact APK
                    # with the original clean journals may receive this restoration.
                    settled = r7.package_identity(adb, PKG, "failure-restoration-identity")
                    need(settled["uid"] == args.expected_uid and len(settled["apks"]) == 1
                         and settled["apks"][0]["sha256"] in (args.old_apk_sha256, args.new_apk_sha256), "install identity is unsettled; do not restore settings")
                    need(idle("failure-restoration-idle") == baseline, "task state is not original clean idle; do not restore settings")
                    restore("failure-restore")
                except Exception as error:
                    report["accessibility_restore_error"] = type(error).__name__ + ": " + str(error)
        finally:
            os.close(owner_fd)



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("profile-helper", "notes-helper", "r7-driver", "source-tools", "owner-root",
                 "out", "new-apk", "build-receipt", "historical-build-receipt", "java-home", "apksigner"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("owner-start-ticks", "owner-boot-id", "old-apk-sha256", "new-apk-sha256",
                 "expected-config-sha256", "build-receipt-sha256", "expected-terminal-task-id",
                 "adb", "adb-host", "serial"):
        parser.add_argument("--" + name, required=True)
    for name in ("owner-pid", "expected-uid", "adb-port", "expected-version"):
        parser.add_argument("--" + name, type=int, required=True)
    parser.add_argument("--command-timeout", type=int, default=12)
    args = parser.parse_args()
    require_v57_release_pins()
    need(str(args.owner_root) == OWNER["root"] and args.owner_pid == OWNER["pid"]
         and args.owner_start_ticks == OWNER["start_ticks"] and args.owner_boot_id == OWNER["boot_id"],
         "actual cooperative owner must be sealed and checked again at execution")
    need(args.expected_version == 57 and args.old_apk_sha256 == V56_APK_SHA
         and args.new_apk_sha256 == V57_APK_SHA and args.build_receipt_sha256 == V57_BUILD_SHA
         and args.build_receipt == Path(V57_BUILD_PATH) and args.new_apk == Path(V57_APK_PATH)
         and args.historical_build_receipt == HISTORICAL_BUILD_PATH
         and args.source_tools == BASE / "v51-build-r2/source/tools"
         and args.profile_helper == BASE / "phone-adapters-v51-r2/configure_local_profile_v51_helper_r2.py"
         and args.notes_helper == BASE / "phone-adapters-v46/moto_note_legacy_v46_r2.py"
         and args.r7_driver == BASE / "phone-adapters-v46/background_helpers_r7_v46.py"
         and args.expected_terminal_task_id == CURRENT["task_id"]
         and args.expected_config_sha256 == CURRENT["config_sha256"] and args.expected_uid == 10481
         and args.out == BASE / "phone-install-v57-r1"
         and args.old_apk_sha256 != args.new_apk_sha256
         and 1 <= args.adb_port <= 65535 and 1 <= args.command_timeout <= 30,
         "only exact installed Main56/helper6/current Recovery56 to signed Main57 is covered")
    observed = {}
    helper_prerequisite = verified_helper6_install(observed)
    build_pin = {"path": V57_BUILD_PATH, "bytes": V57_BUILD_BYTES, "sha256": V57_BUILD_SHA}
    apk_pin = {"path": V57_APK_PATH, "bytes": V57_APK_BYTES, "sha256": V57_APK_SHA}
    build_raw = host_original(build_pin, observed, 8 << 20)
    verify_v57_build_identity(strict_json(build_raw))
    host_original(apk_pin, observed, 256 << 20)
    historical_pin = {"path": str(HISTORICAL_BUILD_PATH), "bytes": HISTORICAL_BUILD_BYTES,
                      "sha256": HISTORICAL_BUILD_SHA}
    historical_source_pin = {"path": str(HISTORICAL_INSTALLER), "bytes": HISTORICAL_INSTALLER_BYTES,
                             "sha256": HISTORICAL_INSTALLER_SHA}
    historical_raw = host_original(historical_pin, observed)
    old_raw = host_original(historical_source_pin, observed, 128 << 10)
    spec = importlib.util.spec_from_file_location("frozen_actual54_installer_admission", HISTORICAL_INSTALLER)
    prior = importlib.util.module_from_spec(spec)
    exec(compile(old_raw, str(HISTORICAL_INSTALLER), "exec"), prior.__dict__)
    prior.verify_v54_build_identity(strict_json(historical_raw))
    need(same_json_types(strict_json(historical_raw)["library_pins"], HISTORICAL_LIBRARY_PINS),
         "full actual54 native baseline differs")
    profile_pin = {"path": str(args.profile_helper), "bytes": None, "sha256": PROFILE_HELPER_SHA}
    need(all(not item.is_symlink() for item in (args.profile_helper, *args.profile_helper.parents)),
         "profile helper path differs")
    descriptor = os.open(str(args.profile_helper), os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        facts = os.fstat(descriptor)
        need(stat.S_ISREG(facts.st_mode) and facts.st_nlink == 1 and 0 < facts.st_size <= 256 << 10,
             "bounded exact profile source required")
        profile_pin["bytes"] = facts.st_size
    finally:
        os.close(descriptor)
    helper_raw = host_original(profile_pin, observed, 256 << 10)
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("frozen_idle_profile_helper", args.profile_helper)
    helper = importlib.util.module_from_spec(spec)
    exec(compile(helper_raw, str(args.profile_helper), "exec"), helper.__dict__)
    notes, r7, profiles, pa, receipts, binder = helper.load_helpers(args)
    for executable in (args.apksigner, args.java_home / "bin/java"):
        need(executable.is_absolute() and executable.is_file() and os.access(executable, os.X_OK),
             "existing host signer/JDK executable unavailable")
    need(args.out.is_absolute() and not args.out.exists()
         and all(not item.is_symlink() for item in args.out.parents), "new absolute output required")
    # FIRST MUTATION, outside handler. Late or duplicate entrants cannot overwrite receipts.
    args.out.mkdir(mode=0o700)
    report = {"schema": "hepta.v57.clean-idle-same-signer-upgrade.v1",
              "helper_revision": "main57-current56-helper6-recovery-preservation-r1",
              "source_provenance": "Actual Main56 preservation/action chain; current Recovery56 originals and separate retained Flight56 Helper50 with normal native close.",
              "completed": False, "installed_verified": False, "install_submitted": False,
              "expired_lease_exception_allowed": False, "journals_deleted": False,
              "app_data_cleared": False, "uninstall_used": False, "automatic_retry": False,
              "rollback_attempted": False, "task_replayed_or_started": False, "start_tapped": False,
              "target_app_operated": False, "model_invoked": False, "private_key_accessed": False,
              "business_verified": False, "qualified": False,
              "historical_task_id": HISTORICAL_CURRENT["task_id"],
              "historical_task_status": "failed", "historical_task_model_runs": 0,
              "current_task_id": CURRENT["task_id"], "current_task_status": CURRENT["expected_status"],
              "current_model_request_count": len(CURRENT["request_ids"]),
              "current_parent_session_generation": CURRENT["parent_generation"],
              "current_recovery56_result_sha256": CURRENT["result"]["sha256"],
              "retained_flight56_task_id": HELPER_CURRENT["task_id"],
              "retained_flight56_result_sha256": HELPER_CURRENT["result"]["sha256"],
              "retained_helper50_collection_sha256": HELPER_CURRENT["collection"]["sha256"],
              "unstarted_is_five_flag_close": False, "formal_lease_cleanup_verified": False,
              "expected_old_apk_sha256": args.old_apk_sha256, "expected_new_apk_sha256": args.new_apk_sha256,
              "expected_uid": args.expected_uid, "expected_version": args.expected_version,
              "expected_source_commit": V57_SOURCE, "expected_source_inventory_sha256": V57_INVENTORY,
              "historical_source_commit": HISTORICAL_SOURCE, "historical_source_inventory_sha256": HISTORICAL_INVENTORY,
              "historical_apk_sha256": HISTORICAL_APK_SHA, "historical_build_receipt_sha256": HISTORICAL_BUILD_SHA,
              "native_recompiled_here": False,
              "expected_terminal_task_id": CURRENT["task_id"], "expected_config_sha256": CURRENT["config_sha256"],
              "profile_helper_sha256": PROFILE_HELPER_SHA, "notes_helper_sha256": helper.NOTES_SHA,
              "r7_helper_sha256": notes.R7_SHA, "helper_pins": r7.PINS, "started_wall_s": time.time()}
    try:
        execute(args, report, helper, notes, r7, profiles, pa, receipts, binder, helper_prerequisite)
        need(same_json_types(verified_helper6_install(observed), helper_prerequisite),
             "host helper6 installation/release/reference originals changed")
        need(host_original(build_pin, observed, 8 << 20) == build_raw,
             "signed Main57 receipt changed during installation")
        host_original(apk_pin, observed, 256 << 20)
        host_original(historical_pin, observed)
        host_original(historical_source_pin, observed, 128 << 10)
        host_original(profile_pin, observed, 256 << 10)
        report["host_originals_unchanged"] = True
        report["completed"] = report["installed_verified"] is True
    except Exception as error:
        report.update(completed=False, installed_verified=False, error=type(error).__name__ + ": " + str(error))
        if report.get("install_submitted") and not report.get("install_success_returned"):
            report["install_outcome"] = "UNKNOWN; inspect exact installed bytes/receipts, no automatic install retry or rollback"
    report["finished_wall_s"] = time.time()
    r7.write_new(args.out / "RESULT.json", report)
    raw = helper.local_file(args.out / "RESULT.json")
    need(same_json_types(pa.strict_json(raw), report), "exact typed installation receipt readback differs")
    print(json.dumps({"completed": report["completed"], "installed_verified": report["installed_verified"],
                      "error": report.get("error"), "result": str(args.out / "RESULT.json"),
                      "result_sha256": sha(raw)}, ensure_ascii=False))
    return 0 if report["completed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
