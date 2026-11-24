#!/usr/bin/env python3
"""Execute the actual observer with independent screenshot-mismatch seed cases.

All original event cases and assertions run first, with the reviewed before-accept
scheduling repair and its one added precondition assertion. Current fixture hashes
and exact proof-copy inverses preserve the original bodies and every old assertion.
Exact fail-only form/AX ports and diagnostic changes remain separately pinned.
Android traversal, pixels, Session issuance and device success remain
outside this host boundary. An optional final manifest/map pair binds a frozen
reviewed source; every run records the complete source inventory before/after.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode = True
TEST = Path('tests/native-observation-screenshot-seed')
PKG = Path('src/org/trillionnium/hepta/local')
PINNED_FIXTURES = {
    'tests/native-observation-events/run_host.py': 'f55e730baa3869ef1fe7110d658a809dfc901628141140c28a508878995dab38',
    'tests/native-observation-events/EventChecks.java': 'b8b8c1302af4a19643e6dda64702e49f887bb5613a6bb0ddc298941b00fccc0a',
    'tests/native-observation-events/EventPipelineCases.fragment': 'c6f71fab64f76e1e8285eb6c82bfd79ec05cc4d737878fad80a6f37a69f6d243',
    'tests/native-observation-events/SavedGraphSeedCases.fragment': '39f8b1060264a291e5e1575e18039cafccc63a49eba29d1af3f0c3094a01af18',
    'tests/native-observation-events/PublicationRecheckCases.fragment': 'a194335ea6ebee1bb5830190ef46645d84a2cd672b6ef0977aceb642b8a6d32b',
    'tests/observation-pipeline/ObserverPipelineHost.template': 'c13a2152891f7f7a4373421b8060f683c1d7d6dd92725bee86081cda9c660799',
    'tests/observation-diagnostics/run_host.py': '153a9edece2f275adc7276dcd40dea8bb7480db692a3f7dd622792ebb4399b74',
}


def need(value, message):
    if not value:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


# Exact Calendar type-carrier inverses are proof copies only; compilation imports the current files.
CALENDAR_HELPER_INVERSES = {'tests/observation-diagnostics/run_host.py': {'current_bytes': 29181, 'current_sha256': '3939e2037c34d2b36ea84cea988a385963315ab4de02fdea7ce516512334c808', 'prior_bytes': 19672, 'prior_sha256': '3f764b22fa2173f5985423eaa39119ee38edc6e69c1ee9481c74d8572d743815', 'operations': [{'start': 103, 'end': 420, 'current_chunk_sha256': '67a80d1731eefd34164ee627d7be6c22c753e802e3726b92c39251c2722738ea', 'restore_hex': '54686520636f6d706c6574652061637475616c2053657276696365206f62736572766174696f6e20626c6f636b2c20646961676e6f7374696320666163746f72792f736e617073686f742c0a616c72656164792d6f627365727665642d726f772070726f6a656374696f6e20616e6420616374696f6e20726563656970742068656c706572732c20616e6420636f6d706c6574652061637475616c0a436f6e74726f6c6c65722061776169744f62736572766174696f6e526177206172652065787472616374656420776974686f75742065646974696e6720746865697220626f646965732e0a', 'restore_sha256': '367e3b4d3c1e7a77d70ac3cf69924a84e85fc1a487fbbf61dbbc6210915d2bba'}, {'start': 3123, 'end': 10037, 'current_chunk_sha256': '81b21af2e0593afa967174ae9895906ec121f7520d432ceab625b63548ae8617', 'restore_hex': '', 'restore_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, {'start': 11210, 'end': 11293, 'current_chunk_sha256': '1dd4563ba690efd6562f3a4d9559f3c62fd890216b9b65f416a3de94d01c7acc', 'restore_hex': '', 'restore_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, {'start': 11386, 'end': 11432, 'current_chunk_sha256': '5bbab8d7114f7bdfd93957f0e9ece2313193c322e4d29a647282a083722abbf6', 'restore_hex': '20202020666f72206e616d652c76616c756520696e2070617274732e6974656d7328293a0a', 'restore_sha256': '7aa176b5e2b2bc903a9ec29b735b83cff0dc36187955287105fd225634dd81a9'}, {'start': 13172, 'end': 13450, 'current_chunk_sha256': 'a0da0d85782f0242cd6794e6e64a7a22aea45df66d6767caad1d89d53e4f3d7b', 'restore_hex': '20202020202020202761776169745f6f62736572766174696f6e5f72657175657374273a626f647928636f6e74726f6c6c65722c2720202020707269766174652050686f6e654f62736572766174696f6e2061776169744f62736572766174696f6e52617728537472696e672069642c46696c65206469726563746f72792c5461736b417574686f72697a6174696f6e2e4761746520617574686f72697a6174696f6e2c6c6f6e6720646561646c696e652c5c6e27292c0a', 'restore_sha256': '7d8efaf26267cbd47b9046d2740d70c40194eb2fa63815a5b0bd93abbc338486'}, {'start': 13895, 'end': 14343, 'current_chunk_sha256': 'c9a4ffa93a438d9603f1e198eec78b5a3f3d1fd938e21f94f54f0dd19fa28d18', 'restore_hex': '', 'restore_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, {'start': 14791, 'end': 15981, 'current_chunk_sha256': 'a5ea1fcbc779639e7a6928b5bead26fef02444c4c621cb7a7ba794da7e233ea9', 'restore_hex': '', 'restore_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, {'start': 16121, 'end': 16184, 'current_chunk_sha256': '8f690c33942d5a0ee1dbf38bbe9c9eb7b27d09ad3331df77e63bcccf5c7d3054', 'restore_hex': '202020202020202020202020746578743d746578742e7265706c616365286d61726b65722c6d6574686f64735b6e616d655d2c31290a', 'restore_sha256': '20f103698a86054cac05936fd7368d85cd8a52f5206523748f65f19f710bda5d'}, {'start': 18290, 'end': 18482, 'current_chunk_sha256': '906b0153c90ba1536fbf06ac77c5bc3aeec68c02943c34292bfa7146bae26013', 'restore_hex': '2020202061776169745f626f64793d6d6574686f64735b2761776169745f6f62736572766174696f6e5f72657175657374275d3b66696e616c6c795f626f64793d61776169745f626f64795b61776169745f626f64792e696e646578282720202020202020207d66696e616c6c797b5c6e2020202020202020202020206162616e646f6e65642e7365742874727565293b27293a5d0a', 'restore_sha256': 'c5bea9fd0ec34bd8942d7fbf530ef7cb64f41b0aee8868d8be34b356034b8173'}, {'start': 19685, 'end': 20059, 'current_chunk_sha256': '176fe242c3d010289070bfc39041d0cd029f72713f0d5563907a32fd1c6545a9', 'restore_hex': '2020202065787472616374696f6e3d7b27736368656d61273a2768657074612e6f62736572766174696f6e2d646961676e6f73746963732d65787472616374696f6e2e7631272c27626f646965735f766572626174696d273a547275652c0a', 'restore_sha256': 'a5930bad487bbb89475ea26c2486b04c4d1de75e834beebd9f10dcdfc66138bf'}, {'start': 27514, 'end': 28015, 'current_chunk_sha256': '26627b2cd846cbf3867b23da6b3b0d6632af87b903f01ab3e437b43bdf7b50e4', 'restore_hex': '20202020202020207265706f72745b2761637475616c5f536572766963655f6f62736572766174696f6e5f616e645f63616c6c6261636b5f636f6d70696c65645f766572626174696d275d3d547275650a20202020202020207265706f72745b2761637475616c5f436f6e74726f6c6c65725f61776169745f636f6d70696c65645f766572626174696d275d3d547275650a', 'restore_sha256': '6412abc3359319ea8c5331edea0aa04746b66a4523e2f8f4199815b5c5c449aa'}]}, 'tests/native-observation-events/run_host.py': {'current_bytes': 18582, 'current_sha256': '3b4bb719baac8da0ac668f344e250dcfabded603136cd090aa1f98f9fba9628f', 'prior_bytes': 18303, 'prior_sha256': 'acc08946e27093f36defb5d4e304131d66062e230399cdec5bb98620b25ef446', 'operations': [{'start': 2714, 'end': 2799, 'current_chunk_sha256': 'd1a811b7cbe869ca57f3cb46ffbc4fcbd87f80e7ce0f0587440cb1d29369be2d', 'restore_hex': '', 'restore_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, {'start': 2892, 'end': 2938, 'current_chunk_sha256': '5bbab8d7114f7bdfd93957f0e9ece2313193c322e4d29a647282a083722abbf6', 'restore_hex': '20202020666f72206e616d652c76616c756520696e2070617274732e6974656d7328293a0a', 'restore_sha256': '7aa176b5e2b2bc903a9ec29b735b83cff0dc36187955287105fd225634dd81a9'}, {'start': 3276, 'end': 3377, 'current_chunk_sha256': 'a3aef0ae1e4b72a4ccd37434c622e07c40c04db53ed78b4779d48ba7e44db12a', 'restore_hex': '2020202023204578706c6963697420494f206361727269657273206f6e6c792e2050726f64756374696f6e20626f646965732061626f766520617265206e657665722072657772697474656e2e0a', 'restore_sha256': 'c4c778ec4fd5502a54525fa680e6b167c2d27792efdef654425cb96c13d2c7e1'}, {'start': 7753, 'end': 8008, 'current_chunk_sha256': 'a7364401a21707b020d7e72de6df4d959077639accf5465e2b9fbf0f7c25bce9', 'restore_hex': '2020202072657475726e207b27736368656d61273a2768657074612e6e61746976652d6f62736572766174696f6e2d6576656e74732d65787472616374696f6e2e7631272c27626f646965735f766572626174696d273a547275652c0a', 'restore_sha256': '25176b41de1d9ebc90b79a87c7c24519ffbf0bb3b86e6046137a2d5a1a9cd237'}]}}

# Exact input-history fixture wiring inverse; no generated production body is replaced.
INPUT_HISTORY_HELPER_INVERSES = {'tests/observation-diagnostics/run_host.py': {'current_bytes': 30333, 'current_sha256': 'd70aee4bdb21724d9a0c88bca02b5653bd60b02cfe9931be964b085f44bb3d0c', 'prior_bytes': 29181, 'prior_sha256': '3939e2037c34d2b36ea84cea988a385963315ab4de02fdea7ce516512334c808', 'operations': [{'start': 1049, 'end': 1220, 'current_chunk_sha256': '6bfe8b7085f2327a55d3ef04ed50b1236357c80b636b13475be2f20ef5e4578e', 'restore_hex': '2020202020202020274e6174697665416374696f6e536e617073686f74436865636b2e6a617661272c274f627365727665644368696c64546578742e6a617661272c274f627365727665645461726765744c6162656c732e6a617661272c274e61746976654374726970466f726d4f62736572766174696f6e2e6a617661275d0a', 'restore_sha256': 'ae9b6e8a72c7e14bcaf45bff870b277c4c0ccb9fafe3a76d4c5ca70553b1305c'}, {'start': 17160, 'end': 17921, 'current_chunk_sha256': 'c53528e3d054ac5a3b21872152eb028320d62f8edae0a78681e2310a300dd2c3', 'restore_hex': '20202020232054686520726576696577656420686973746f727920736f75726365206e6f77207265717569726573207468652073616d65206e6174697665206775617264206576656e207768656e0a20202020232069747320686973746f726963616c2077686f6c652d74726565206469676573742068617070656e7320746f206d617463682e2050726f766520746865206f6e6c792063616c6c2d736974650a2020202023206368616e676520616761696e73742074686520636f6d706c657465206c6567616379206272616e63682061626f76653b20657865637574652061637475616c20626f646965732e0a', 'restore_sha256': 'eb399b42dcfd31d04eaa407c35ce498ccc01f0899b50b95f01a88dd308fa91bc'}, {'start': 17988, 'end': 18237, 'current_chunk_sha256': 'f2b9c189b92a09d5deb3cfbbb2405d17c9904470f02ea0e57e683aabd463dd76', 'restore_hex': '20202020686973746f72795f636f6e646974696f6e3d277d656c73652069662865787065637465642e63617074757265213d6e756c6c262665787065637465642e636170747572652e666f726d486973746f727928297c7c2167726170682e6469676573742e657175616c73286e6f772e64696765737429297b270a', 'restore_sha256': '7ee47daface2558fd8c96efb9e770c95055cdea0f713af1acd59887fde6d9374'}, {'start': 18338, 'end': 18694, 'current_chunk_sha256': '8b0e2484f0cffa00e0b7715f57a679a4d01f256e9c7b74e20ae7595285f7ab88', 'restore_hex': '2020202061637475616c5f6272616e63683d6272616e63682e7265706c616365286c65676163795f636f6e646974696f6e2c686973746f72795f636f6e646974696f6e2c31290a2020202069662061637475616c5f6272616e63682e636f756e7428686973746f72795f636f6e646974696f6e29213d31206f722061637475616c5f6272616e63682e7265706c61636528686973746f72795f636f6e646974696f6e2c6c65676163795f636f6e646974696f6e2c3129213d6272616e63683a0a', 'restore_sha256': '348516511d1276d97c91d8320dc9df9f5225ce1262d30044598b978a358cfe4c'}, {'start': 21412, 'end': 21711, 'current_chunk_sha256': '8d7fceca5281f6ad18286bfd143da232b50f707b35bf389b3281ba6ea04f50b1', 'restore_hex': '', 'restore_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}]}, 'tests/native-observation-events/run_host.py': {'current_bytes': 19438, 'current_sha256': '70b3abf2899f84f59ae09b2324c7b3581551c426005ecb6d629a859659984dc2', 'prior_bytes': 18582, 'prior_sha256': '3b4bb719baac8da0ac668f344e250dcfabded603136cd090aa1f98f9fba9628f', 'operations': [{'start': 6736, 'end': 7497, 'current_chunk_sha256': 'c53528e3d054ac5a3b21872152eb028320d62f8edae0a78681e2310a300dd2c3', 'restore_hex': '20202020232054686520726576696577656420686973746f727920736f75726365206e6f77207265717569726573207468652073616d65206e6174697665206775617264206576656e207768656e0a20202020232069747320686973746f726963616c2077686f6c652d74726565206469676573742068617070656e7320746f206d617463682e2050726f766520746865206f6e6c792063616c6c2d736974650a2020202023206368616e676520616761696e73742074686520636f6d706c657465206c6567616379206272616e63682061626f76653b20657865637574652061637475616c20626f646965732e0a', 'restore_sha256': 'eb399b42dcfd31d04eaa407c35ce498ccc01f0899b50b95f01a88dd308fa91bc'}, {'start': 7564, 'end': 7813, 'current_chunk_sha256': 'f2b9c189b92a09d5deb3cfbbb2405d17c9904470f02ea0e57e683aabd463dd76', 'restore_hex': '20202020686973746f72795f636f6e646974696f6e3d277d656c73652069662865787065637465642e63617074757265213d6e756c6c262665787065637465642e636170747572652e666f726d486973746f727928297c7c2167726170682e6469676573742e657175616c73286e6f772e64696765737429297b270a', 'restore_sha256': '7ee47daface2558fd8c96efb9e770c95055cdea0f713af1acd59887fde6d9374'}, {'start': 7914, 'end': 8270, 'current_chunk_sha256': '8b0e2484f0cffa00e0b7715f57a679a4d01f256e9c7b74e20ae7595285f7ab88', 'restore_hex': '2020202061637475616c5f6272616e63683d6272616e63682e7265706c616365286c65676163795f636f6e646974696f6e2c686973746f72795f636f6e646974696f6e2c31290a2020202069662061637475616c5f6272616e63682e636f756e7428686973746f72795f636f6e646974696f6e29213d31206f722061637475616c5f6272616e63682e7265706c61636528686973746f72795f636f6e646974696f6e2c6c65676163795f636f6e646974696f6e2c3129213d6272616e63683a0a', 'restore_sha256': '348516511d1276d97c91d8320dc9df9f5225ce1262d30044598b978a358cfe4c'}, {'start': 16297, 'end': 16451, 'current_chunk_sha256': 'e7d56c7aa58fa1662539713bb78f5609ca678aedfd1ff52fd59e2fe836d959a2', 'restore_hex': '20202020696e707574733d5b736f757263652f504b472f274e617469766541707045766964656e63652e6a617661275d2b5b736f757263652f504b472f6e20666f72206e20696e204a4156415d2b5b736f757263652f544553542f6e20666f72206e20696e204f574e5d2b5b0a', 'restore_sha256': 'f648bb77200a416e5600b106ccb6c41ffe90b637ce42d520656be0d02817cb21'}]}}

def reverse_input_history_helper(path, raw):
    spec = INPUT_HISTORY_HELPER_INVERSES[path]
    need(len(raw) == spec['current_bytes'] and sha(raw) == spec['current_sha256'],
         'exact current input-history helper bytes required: ' + path)
    restored = raw
    for operation in reversed(spec['operations']):
        start, end = operation['start'], operation['end']
        need(0 <= start <= end <= len(restored)
             and sha(restored[start:end]) == operation['current_chunk_sha256'],
             'exact input-history inverse chunk required: ' + path)
        prior = bytes.fromhex(operation['restore_hex'])
        need(sha(prior) == operation['restore_sha256'], 'exact input-history replacement required')
        restored = restored[:start] + prior + restored[end:]
    need(len(restored) == spec['prior_bytes'] and sha(restored) == spec['prior_sha256'],
         'complete pre-input-history helper bytes must be restored: ' + path)
    return restored, {'actual_current_sha256': sha(raw), 'whole_prior_sha256': sha(restored),
                      'inverse_operation_count': len(spec['operations']),
                      'complete_prior_bytes_restored': True, 'proof_copy_only': True,
                      'actual_compilation_uses_unmodified_current_helper': True}



# Exact PNG type/compile closure inverse; historical proof only, never the compiled source.
PNG_CLOSURE_INVERSES = {'tests/observation-pipeline/ObserverPipelineHost.template': {'current_sha256': '7f78539e600115f929a743b0e36e4399227faaae2701af64ba2482c122634b6f', 'prior_sha256': '1c6df78b51e766282001d5f4b0233efd31a82dc3f04b1182072eaa769aa6a7d2', 'operations': [['        int getWidth(){return 1080;}int getHeight(){return 2400;}\n', '        // Unknown pixel color metadata keeps all legacy IO/scheduling fixtures on the original encoder.\n        android.graphics.ColorSpace getColorSpace(){return null;}\n        Config getConfig(){return Config.ARGB_8888;}\n        boolean isMutable(){return false;}\n        boolean hasGainmap(){return false;}\n        int getGenerationId(){return 1;}\n        void getPixels(int[] out,int offset,int stride,int x,int y,int width,int height){\n            throw new AssertionError("legacy fixture has no qualified sRGB pixel plane");\n        }\n        int getWidth(){return 1080;}int getHeight(){return 2400;}\n']]}, 'tests/observation-diagnostics/run_host.py': {'current_sha256': '0c0610d43854b188e0da3861009a4efda978cc27405b9171d107ee523ef6827f', 'prior_sha256': 'd70aee4bdb21724d9a0c88bca02b5653bd60b02cfe9931be964b085f44bb3d0c', 'operations': [['def sha(raw):', "def png_sources(source):\n    # Exact production encoder plus explicit Android metadata type ports; no graph/owner authority.\n    return [source/PKG/'ObservationPngEncoder.java',\n            source/'tests/observation-png/stubs/android/graphics/ColorSpace.java',\n            source/'tests/observation-png/stubs/android/os/Build.java']\n\ndef sha(raw):"], ['    before=[meta(x) for x in paths];tools_before=[meta(x) for x in tools]\n', '    paths += png_sources(source)\n    before=[meta(x) for x in paths];tools_before=[meta(x) for x in tools]\n'], ["        command=[str(javac),'--release','8','-encoding','UTF-8','-Xlint:all','-Werror','-cp',str(jar),'-d',str(classes)]+list(map(str,sources))\n", "        sources += png_sources(source)\n        command=[str(javac),'--release','8','-encoding','UTF-8','-Xlint:all','-Werror','-cp',str(jar),'-d',str(classes)]+list(map(str,sources))\n"]]}, 'tests/native-observation-events/run_host.py': {'current_sha256': 'd47a7dc865b678a5cd5c4d49c45635886ae0e49da0b90749bc6e7401d9536a27', 'prior_sha256': '70b3abf2899f84f59ae09b2324c7b3581551c426005ecb6d629a859659984dc2', 'operations': [['    before=[h.meta(p) for p in inputs];tool_before=[h.meta(p) for p in tools]\n', '    inputs += h.png_sources(source)\n    before=[h.meta(p) for p in inputs];tool_before=[h.meta(p) for p in tools]\n'], ["        argv=[str(javac),'--release','8','-encoding','UTF-8','-Xlint:all','-Werror','-cp',str(jar),'-d',str(classes)]+list(map(str,sources))\n", "        sources += h.png_sources(source)\n        argv=[str(javac),'--release','8','-encoding','UTF-8','-Xlint:all','-Werror','-cp',str(jar),'-d',str(classes)]+list(map(str,sources))\n"]]}}

def reverse_png_closure(path, raw):
    spec=PNG_CLOSURE_INVERSES[path]
    need(sha(raw)==spec['current_sha256'],'exact current PNG closure source required: '+path)
    restored=raw
    for prior,current in reversed(spec['operations']):
        prior=prior.encode();current=current.encode()
        need(restored.count(current)==1,'unique exact PNG closure inverse required: '+path)
        restored=restored.replace(current,prior,1)
    need(sha(restored)==spec['prior_sha256'],'complete pre-PNG closure bytes must be restored: '+path)
    return restored,{'current_sha256':sha(raw),'prior_sha256':sha(restored),
                     'operations':len(spec['operations']),'proof_copy_only':True,
                     'compilation_uses_actual_current_source':True}

# These exact additions are reversed only in the historical proof copy.
# Compilation and execution keep the current runner and all ten additional cases.
POSTCAPTURE_EVENT_INVERSE = {'current_sha256': 'ae53f1a9506ba7ff1c04d03a46f45edc64a59813a1647af93c79e1fbbdf24c83', 'prior_sha256': 'd47a7dc865b678a5cd5c4d49c45635886ae0e49da0b90749bc6e7401d9536a27', 'operations': [("OWN=['run_host.py','EventChecks.java','EventPipelineCases.fragment','SavedGraphSeedCases.fragment','PublicationRecheckCases.fragment']\n", "OWN=['run_host.py','EventChecks.java','EventPipelineCases.fragment','SavedGraphSeedCases.fragment','PublicationRecheckCases.fragment','PostCaptureSettleCases.fragment']\n"), ("    case_source=(source/TEST/'SavedGraphSeedCases.fragment').read_text()+'\\n'+(source/TEST/'PublicationRecheckCases.fragment').read_text()\n", "    case_source=(source/TEST/'SavedGraphSeedCases.fragment').read_text()+'\\n'+(source/TEST/'PublicationRecheckCases.fragment').read_text()+'\\n'+(source/TEST/'PostCaptureSettleCases.fragment').read_text()\n"), ("        '        savedGraphSeedCases();\\n        savedGraphSeedAdditionalCases();\\n        savedGraphSeedProfileCases();\\n        publicationRecheckCases();\\n        observationIo.executor.shutdown();EventChecks.finish(args[0]);')\n", "        '        savedGraphSeedCases();\\n        savedGraphSeedAdditionalCases();\\n        savedGraphSeedProfileCases();\\n        publicationRecheckCases();\\n        postCaptureSettleCases();\\n        observationIo.executor.shutdown();EventChecks.finish(args[0]);')\n"), ('', "        'post_capture_settle_cases':h.meta(source/TEST/'PostCaptureSettleCases.fragment'),\n")]}
POSTCAPTURE_CASE_NAMES = ['post_capture_settle_no_new_read_at_11277', 'post_capture_settle_no_new_read_at_10000', 'post_capture_settle_no_new_read_at_10001', 'post_capture_settle_no_new_read_at_11800', 'post_capture_settle_no_new_read_at_11999', 'post_capture_settle_does_not_grant_new_authority_before_expiry', 'post_capture_settle_preserves_unknown_event_refusal', 'post_capture_settle_preserves_cancel_refusal', 'post_capture_settle_preserves_owner_refusal', 'post_capture_settle_preserves_window_refusal']
LEGACY_EVENT_CASE_NAMES_SHA256 = '92278b7f6dfa081f4eb83cd02aec19841802387dc71a67242109a25e5e2b51e5'

def reverse_postcapture_event_helper(raw):
    spec = POSTCAPTURE_EVENT_INVERSE
    need(sha(raw) == spec['current_sha256'], 'exact current postcapture event runner required')
    restored = raw
    for prior, current in reversed(spec['operations']):
        prior, current = prior.encode(), current.encode()
        need(restored.count(current) == 1, 'unique exact postcapture test addition required')
        restored = restored.replace(current, prior, 1)
    need(sha(restored) == spec['prior_sha256'], 'complete pre-postcapture event runner must be restored')
    return restored, {'actual_current_sha256': sha(raw), 'whole_prior_sha256': sha(restored),
                      'inverse_operation_count': len(spec['operations']), 'proof_copy_only': True,
                      'actual_compilation_uses_unmodified_current_helper': True}


def reverse_calendar_helper(path, raw):
    raw, png_inverse = reverse_png_closure(path, raw)
    raw, input_history_inverse = reverse_input_history_helper(path, raw)
    spec = CALENDAR_HELPER_INVERSES[path]
    need(len(raw) == spec['current_bytes'] and sha(raw) == spec['current_sha256'],
         'exact current Calendar helper bytes required: ' + path)
    restored = raw
    for operation in reversed(spec['operations']):
        start, end = operation['start'], operation['end']
        need(0 <= start <= end <= len(restored)
             and sha(restored[start:end]) == operation['current_chunk_sha256'],
             'exact Calendar inverse chunk required: ' + path)
        prior = bytes.fromhex(operation['restore_hex'])
        need(sha(prior) == operation['restore_sha256'], 'exact Calendar inverse replacement required')
        restored = restored[:start] + prior + restored[end:]
    need(len(restored) == spec['prior_bytes'] and sha(restored) == spec['prior_sha256'],
         'whole historical helper bytes must be restored: ' + path)
    return restored, {'actual_current_sha256': png_inverse['current_sha256'], 'png_closure_inverse': png_inverse,
                      'input_history_inverse': input_history_inverse, 'whole_prior_sha256': sha(restored),
                      'inverse_operation_count': len(spec['operations']),
                      'complete_prior_bytes_restored': True, 'proof_copy_only': True,
                      'actual_compilation_uses_unmodified_current_helper': True}


def verify_original_fixtures(source, before):
    template = 'tests/observation-pipeline/ObserverPipelineHost.template'
    port = b'''    /** Explicit fail-only port: legacy scheduling fixtures cannot admit scoped form pairs.
     * The dedicated form-observation gate substitutes both actual production helpers. */
    private Map<String,Object> nativeCtripFormPair(ObservationRequest request,CaptureIdentity identity,Graph after){return null;}
'''
    raw = (source / template).read_bytes()
    need(before[template]['sha256']==sha(raw),'actual current template inventory differs')
    raw, png_inverse = reverse_png_closure(template, raw)
    current_sha = '1c6df78b51e766282001d5f4b0233efd31a82dc3f04b1182072eaa769aa6a7d2'
    need(sha(raw) == current_sha,
         'reviewed fail-only fixture template differs')
    # Proof copy only: the actual generator still reads the current typed-failure port.
    typed_child_port = b'''    // Explicit Android read-failure port. Existing one-argument callers remain untyped.
    static final class StaleObservation extends IllegalStateException {
        private static final long serialVersionUID=1L;final boolean backgroundChildUnavailable;
        StaleObservation(String message){this(message,false);}
        StaleObservation(String message,boolean childUnavailable){super(message);backgroundChildUnavailable=childUnavailable;}
    }
'''
    prior_stale_port = b'''    static final class StaleObservation extends IllegalStateException {private static final long serialVersionUID=1L;StaleObservation(String message){super(message);}}
'''
    prior_template_sha = '662c99d5b7703907b40d18f55b716c2ab0660abac3d67f556d5b881dfde2a333'
    need(raw.count(typed_child_port) == 1, 'exact reviewed typed child-failure port required')
    raw = raw.replace(typed_child_port, prior_stale_port, 1)
    need(sha(raw) == prior_template_sha,
         'typed child-failure port must reverse to the complete prior observer fixture')
    # Proof copy only: actual observer compilation retains every current port.
    business_port = "    // Observer-only fixture has no business recovery flight or receipt.\n    // Actual held/drained recovery queues are covered by the dedicated lifecycle gate.\n    static final class PublicProfileBusinessRecoveryClient {\n        private PublicProfileBusinessRecoveryClient(){throw new AssertionError(\"no business recovery authority in observer fixture\");}\n        static boolean workPending(){return false;}\n    }\n".encode()
    need(raw.count(business_port) == 1, 'exact absent business-recovery queue carrier required')
    before_business = raw.replace(business_port, b'', 1)
    need(sha(before_business) == '1bd38ed61ce94adbb1b85c8ccd099c1b45c268c62c66b3aebca4d574f9ffdc57',
         'business queue port must reverse to the complete prior observer fixture')
    search_ports = b'    // No native search Session is bound in these original observer fixtures.\n    // Unexpected binding is refused; these ports cannot create planning or an Offer.\n    private final Object nativeSearchSession=null,activeNativeSearchObservation=null;\n    private void noteNativeSearchEvent(int display,int window,String pkg,boolean content,boolean typed){\n        if(nativeSearchSession!=null||activeNativeSearchObservation!=null)\n            throw new AssertionError("legacy observer cannot route a bound native search event");\n    }\n    private boolean nativeSearchAllowsLegacyObservation(String taskId){\n        return nativeSearchSession==null&&activeNativeSearchObservation==null;\n    }\n'
    need(raw.count(search_ports) == 1, 'exact unbound native-search fixture ports required')
    legacy_search = before_business.replace(search_ports, b'', 1)
    need(sha(legacy_search) == '2fedec818e4fb21c0260580658e225da5cc34443ec8928988f34b80f6cbb9a01',
         'complete pre-search AX fixture bytes differ')
    need(raw.count(port) == 1, 'exact single fail-only form port required')
    ax_ports = b'    // Legacy scheduling fakes never bind a text-native model. The AX gate substitutes\n    // the actual production mode admission, worker and publisher at these three ports.\n    private void bindNativeAxObservationRequest(ObservationRequest request){}\n    private boolean nativeTextObservationAllowed(ObservationRequest request,Graph graph){return false;}\n    private void captureNativeAxObservation(ObservationRequest request){throw new AssertionError("legacy fixture cannot enter AX capture");}\n'
    need(raw.count(ax_ports) == 1, 'exact reviewed fail-only AX ports required')
    legacy = legacy_search.replace(ax_ports, b'', 1)
    need(sha(legacy) == '50b7d239c4e76334894082dd01ecad1a7a207eb1e776f82f9916d3ea1e62de1d', 'original form-port fixture bytes differ')
    original_sha = sha(legacy.replace(port, b'', 1))
    need(original_sha == PINNED_FIXTURES[template],
         'original complete fixture body differs after exact port removal')
    diagnostic = 'tests/observation-diagnostics/run_host.py'
    diagnostic_current = (source / diagnostic).read_bytes()
    need(before[diagnostic]['sha256'] == sha(diagnostic_current), 'actual current diagnostic inventory differs')
    diagnostic_raw, diagnostic_calendar_inverse = reverse_calendar_helper(diagnostic, diagnostic_current)
    need(sha(diagnostic_raw) == '3f764b22fa2173f5985423eaa39119ee38edc6e69c1ee9481c74d8572d743815',
         'exact reviewed diagnostic source and search-retirement anchor required')
    # These fixed reversals affect only the historical proof; actual tests keep all
    # AX publication cases and the real Controller retirement/finalization block.
    diagnostic_legacy = diagnostic_raw
    # Proof only: actual dependency list and exact history-guard source contract
    # are retained by the real generator. Preserve every earlier full-file pin.
    form_history_replacements = [(b"        'NativeActionSnapshotCheck.java','ObservedChildText.java','ObservedTargetLabels.java']\n", b"        'NativeActionSnapshotCheck.java','ObservedChildText.java','ObservedTargetLabels.java','NativeCtripFormObservation.java']\n"), (b"    if service.count(branch)!=1:raise RuntimeError('exact separately guarded native branch and original fallback required')\n", b"    # The reviewed history source now requires the same native guard even when\n    # its historical whole-tree digest happens to match. Prove the only call-site\n    # change against the complete legacy branch above; execute actual bodies.\n    legacy_condition='}else if(!graph.digest.equals(now.digest)){'\n    history_condition='}else if(expected.capture!=null&&expected.capture.formHistory()||!graph.digest.equals(now.digest)){'\n    if branch.count(legacy_condition)!=1:raise RuntimeError('exact legacy guard condition required')\n    actual_branch=branch.replace(legacy_condition,history_condition,1)\n    if actual_branch.count(history_condition)!=1 or actual_branch.replace(history_condition,legacy_condition,1)!=branch:\n        raise RuntimeError('history call-site inverse must preserve the original native guard and fallback')\n    if service.count(actual_branch)!=1:raise RuntimeError('exact separately guarded native branch and original fallback required')\n"), (b"        'stale_refusal_callsite':{'bytes':len(branch.encode()),'sha256':sha(branch.encode())},\n", b"        'stale_refusal_callsite':{'bytes':len(actual_branch.encode()),'sha256':sha(actual_branch.encode())},\n        'stale_refusal_legacy_inverse':{'bytes':len(branch.encode()),'sha256':sha(branch.encode()),'exact_inverse':True},\n")]
    for prior, revised in form_history_replacements:
        need(diagnostic_legacy.count(revised) == 1, 'unique reviewed form-history diagnostic runner delta required')
        diagnostic_legacy = diagnostic_legacy.replace(revised, prior, 1)
    need(sha(diagnostic_legacy) == 'a8db4f43d84235c8af729415a37e1c696057498517b00e2d90a03db373432637',
         'complete pre-form-history diagnostic runner bytes differ')
    search_anchor_replacements = [(b"    finalization=section(controller,'        finally{\\n            service.retireActionWork(taskId,', '    private static NotesCompletionEvidence.Frame completionFrame(')\n", b"    finalization=section(controller,'        finally{\\n            if(activeNativeSearch!=null)activeNativeSearch.retire();\\n            service.retireActionWork(taskId,', '    private static NotesCompletionEvidence.Frame completionFrame(')\n")]
    for prior, revised in search_anchor_replacements:
        need(diagnostic_legacy.count(revised) == 1, 'unique actual search-retirement anchor required')
        diagnostic_legacy = diagnostic_legacy.replace(revised, prior, 1)
    need(sha(diagnostic_legacy) == 'f15d8aab75c26e0e4dc9da87a326fbca54de54e63596bedc0592629139937f5d',
         'complete pre-search diagnostic runner bytes differ')
    ax_publication_replacements = [(b"       'DiagnosticPipelineCases.fragment','DiagnosticGraphHost.template','DiagnosticControllerHost.template','CompactCensusDiagnosticsHostTest.java','PrivateCensusDiagnosticsHostTest.java','PrivateCensusFileHost.template']\n", b"       'DiagnosticPipelineCases.fragment','DiagnosticGraphHost.template','DiagnosticControllerHost.template','CompactCensusDiagnosticsHostTest.java','PrivateCensusDiagnosticsHostTest.java','PrivateCensusFileHost.template','AxPublicationDiagnosticsHostTest.java']\n"), (b"        sources += [source/TEST/'DiagnosticChecks.java',source/TEST/'ObservationDiagnosticsHostTest.java',source/TEST/'CompactCensusDiagnosticsHostTest.java',source/TEST/'PrivateCensusDiagnosticsHostTest.java']+sorted(generated.glob('*.java'))\n", b"        sources += [source/TEST/'DiagnosticChecks.java',source/TEST/'ObservationDiagnosticsHostTest.java',source/TEST/'CompactCensusDiagnosticsHostTest.java',source/TEST/'PrivateCensusDiagnosticsHostTest.java',source/TEST/'AxPublicationDiagnosticsHostTest.java']+sorted(generated.glob('*.java'))\n"), (b'', b"        ax=stage('ax-publication-cases',[str(java),'-cp',str(classes)+os.pathsep+str(jar),'org.trillionnium.hepta.local.AxPublicationDiagnosticsHostTest',str(output/'AX-PUBLICATION-CASES.json')],output);report['stages'].append(ax)\n        if ax['exit_code']!=0:raise RuntimeError('actual AX publication diagnostic cases failed')\n        ax_cases=json.loads((output/'AX-PUBLICATION-CASES.json').read_text())\n        if ax_cases['all_pass'] is not True or ax_cases['cases']!=18 or len(ax_cases['case_names'])!=18 or len(set(ax_cases['case_names']))!=18 or ax_cases['assertions']<=0:\n            raise RuntimeError('complete unique AX publication diagnostic case identity required')\n        if ax_cases['actual_tracker_and_Service_serializers'] is not True or ax_cases['deadline_or_sampling_changed'] is not False or ax_cases['android_execution'] is not False or ax_cases['phone_operations']!=0 or ax_cases['business_completion_verified'] is not False:\n            raise RuntimeError('AX publication diagnostic boundary changed')\n        report['ax_publication_cases']=ax_cases;report['ax_publication_cases_file']=meta(output/'AX-PUBLICATION-CASES.json')\n")]
    for prior, revised in ax_publication_replacements:
        need(diagnostic_legacy.count(revised) == 1, 'unique reviewed AX diagnostic test addition required')
        diagnostic_legacy = diagnostic_legacy.replace(revised, prior, 1)
    need(sha(diagnostic_legacy) == '8bc73b57369ffedd8681101c86ba096856f36b6dcba08d3a973f1cb72720209e',
         'complete pre-AX-publication diagnostic runner bytes differ')
    diagnostic_replacements = [(b"JAVA = ['HeptaAccessibilityService.java','LocalTaskController.java','ObservationDiagnostics.java',\n", b"JAVA = ['ObservationCaptureEvidence.java', 'HeptaAccessibilityService.java','LocalTaskController.java','ObservationDiagnostics.java',\n"), (b"       'DiagnosticPipelineCases.fragment','DiagnosticGraphHost.template','DiagnosticControllerHost.template','CompactCensusDiagnosticsHostTest.java']\n", b"       'DiagnosticPipelineCases.fragment','DiagnosticGraphHost.template','DiagnosticControllerHost.template','CompactCensusDiagnosticsHostTest.java','PrivateCensusDiagnosticsHostTest.java','PrivateCensusFileHost.template']\n"), (b'', b"        'private_census_holder':body(controller,'    private static final class FailedCensusDiagnostic {'),\n        'persist_private_census':body(controller,'    private JSONObject persistFailedCensusDiagnostic(String task,String status,boolean verified,File directory){'),\n        'private_census_write':body(controller,'    private static void recordPrivateCensus(File directory,String name,byte[] bytes)throws Exception{'),\n"), (b"    for fixture,names in [('DiagnosticGraphHost',['native_stamp','native_census','stale_record','action_evidence']),('DiagnosticControllerHost',['await_observation','await_observation_request','read_retry_failure','initial_read_failure','post_effect_read_failure','take_diagnostics'])]:\n", b"    for fixture,names in [('DiagnosticGraphHost',['native_stamp','native_census','stale_record','action_evidence']),('DiagnosticControllerHost',['await_observation','await_observation_request','read_retry_failure','initial_read_failure','post_effect_read_failure','take_diagnostics','private_census_holder','persist_private_census']),('PrivateCensusFileHost',['private_census_write'])]:\n"), (b'    positions=[finalization.index(token) for token in [\'backgroundCleanup=background.close();\',\'modelCleanup=inference.endTask(taskId);\',\'terminalDecisionSealed=true;\',\'record(evidence,"result.json"\',\'takeObservationDiagnostics(taskId)\',\'if(cleanup)service.releaseTask(taskId);\',\'running=false;\',\'selected.onFinished(result)\']]\n', b'    positions=[finalization.index(token) for token in [\'backgroundCleanup=background.close();\',\'modelCleanup=inference.endTask(taskId);\',\'terminalDecisionSealed=true;\',\'persistFailedCensusDiagnostic(taskId,finalStatus,completionVerified,evidence)\',\'record(evidence,"result.json"\',\'takeObservationDiagnostics(taskId)\',\'if(cleanup)service.releaseTask(taskId);\',\'running=false;\',\'selected.onFinished(result)\']]\n'), (b"        'diagnostic_finally_has_no_IO_or_wait':True,'terminal_diagnostic_uses_only_existing_result_write':True,\n", b"        'diagnostic_finally_has_no_IO_or_wait':True,'terminal_summary_uses_only_existing_result_write':True,'private_failure_artifact_after_original_cleanup_and_terminal':True,\n"), (b"        sources += [source/TEST/'DiagnosticChecks.java',source/TEST/'ObservationDiagnosticsHostTest.java',source/TEST/'CompactCensusDiagnosticsHostTest.java']+sorted(generated.glob('*.java'))\n", b"        sources += [source/TEST/'DiagnosticChecks.java',source/TEST/'ObservationDiagnosticsHostTest.java',source/TEST/'CompactCensusDiagnosticsHostTest.java',source/TEST/'PrivateCensusDiagnosticsHostTest.java']+sorted(generated.glob('*.java'))\n")]
    restored = diagnostic_legacy
    for prior, revised in diagnostic_replacements:
        need(restored.count(revised) == 1, 'unique reversible diagnostic fixture change required')
        restored = restored.replace(revised, prior, 1)
    need(sha(restored) == PINNED_FIXTURES[diagnostic], 'original diagnostic runner bytes not restored')
    event_runner = 'tests/native-observation-events/run_host.py'
    event_current = (source / event_runner).read_bytes()
    need(before[event_runner]['sha256'] == sha(event_current), 'actual current event inventory differs')
    postcapture = 'tests/native-observation-events/PostCaptureSettleCases.fragment'
    need(before[postcapture]['sha256'] == sha((source / postcapture).read_bytes()) ==
         '681aad0b44a8dc2460d947efe3ab6ccc9cb8f533614cf96938f5af5ad95e5b7d',
         'exact current postcapture cases required')
    event_prior, event_postcapture_inverse = reverse_postcapture_event_helper(event_current)
    event_raw, event_calendar_inverse = reverse_calendar_helper(event_runner, event_prior)
    need(sha(event_raw) == 'acc08946e27093f36defb5d4e304131d66062e230399cdec5bb98620b25ef446',
         'exact reviewed event-generator history guard required')
    event_guard_current = b"    # The reviewed history source now requires the same native guard even when\n    # its historical whole-tree digest happens to match. Prove the only call-site\n    # change against the complete legacy branch above; execute actual bodies.\n    legacy_condition='}else if(!graph.digest.equals(now.digest)){'\n    history_condition='}else if(expected.capture!=null&&expected.capture.formHistory()||!graph.digest.equals(now.digest)){'\n    if branch.count(legacy_condition)!=1:raise RuntimeError('exact legacy guard condition required')\n    actual_branch=branch.replace(legacy_condition,history_condition,1)\n    if actual_branch.count(history_condition)!=1 or actual_branch.replace(history_condition,legacy_condition,1)!=branch:\n        raise RuntimeError('history call-site inverse must preserve the original native guard and fallback')\n    if service.count(actual_branch)!=1:raise RuntimeError('exact separately guarded native branch and original fallback required')"
    event_guard_legacy = b"    if service.count(branch)!=1:raise RuntimeError('exact separately guarded native branch and original fallback required')"
    need(event_raw.count(event_guard_current) == 1, 'unique exact event-generator history guard delta required')
    event_original = event_raw.replace(event_guard_current, event_guard_legacy, 1)
    need(sha(event_original) == PINNED_FIXTURES[event_runner], 'complete original event generator bytes differ')
    # Root's reviewed before-accept scheduling repair is reversed only in this proof copy.
    seed_fixture = 'tests/native-observation-events/SavedGraphSeedCases.fragment'
    seed_current = (source / seed_fixture).read_bytes()
    seed_current_sha = '2f427a6221011b52d3781201f6b98652600d3d7a09e8c7fb1fc9bc1efe6fb446'
    need(len(seed_current) == 85702 and before[seed_fixture]['sha256'] == sha(seed_current) == seed_current_sha,
         'exact reviewed current saved-seed schedule required')
    seed_inverse_operations = [
        (b'''            ObserverPipelineHost f=seedFixture((x,g,n)->{if(n==5&&"unknown_during_read".equals(reason))x.noteObservationEvent(-1);});
''', b'''            final Block beforeAccept="unknown_before_accept".equals(reason)?new Block():null;
            ObserverPipelineHost f=seedFixture((x,g,n)->{
                if(n==5&&"unknown_during_read".equals(reason))x.noteObservationEvent(-1);
                if(n==5&&beforeAccept!=null)beforeAccept.run();
            });
'''),
        (b'''            SystemClock.now+=200;f.main.drain();await(()->!observationIoBusy.get()&&observationIo.active.get()==0,"next seed read");
            if("unknown_before_accept".equals(reason))f.noteObservationEvent(-1);
''', b'''            // Hold the actual next read until the test main has stopped draining.
            // Otherwise a fast worker can post and deliver acceptSample during
            // this same drain, before the intended before-accept event is sent.
            SystemClock.now+=200;f.main.drain();
            if(beforeAccept!=null){beforeAccept.entered();beforeAccept.open();}
            await(()->!observationIoBusy.get()&&observationIo.active.get()==0,"next seed read");
            if("unknown_before_accept".equals(reason)){
                check(r.resampleSeed!=null&&count(r,"SAMPLE_READY")==1&&f.shots.size()==1,"before-accept event must precede sample acceptance");
                f.noteObservationEvent(-1);
            }
'''),
    ]
    seed_prior = seed_current
    for prior_block, current_block in reversed(seed_inverse_operations):
        need(seed_prior.count(current_block) == 1, 'unique exact saved-seed scheduling block required')
        seed_prior = seed_prior.replace(current_block, prior_block, 1)
    need(len(seed_prior) == 85000 and sha(seed_prior) == PINNED_FIXTURES[seed_fixture],
         'saved-seed scheduling inverse must restore the complete original fixture')
    need(all(before[name]['sha256'] == digest for name, digest in PINNED_FIXTURES.items() if name not in (template, diagnostic, event_runner, seed_fixture)),
         'original reviewed fixture bytes differ')
    return {'template': template, 'current_sha256': png_inverse['current_sha256'], 'png_closure_inverse': png_inverse,
            'typed_child_port_inverse': {'prior_complete_sha256': prior_template_sha,
                'exact_current_block_sha256': sha(typed_child_port), 'proof_copy_only': True,
                'actual_compilation_uses_current_template': True},
            'saved_seed_schedule_inverse': {'current_complete_sha256': seed_current_sha,
                'prior_complete_sha256': sha(seed_prior), 'exact_inverse_operations': 2,
                'reviewed_additional_assertions': 1, 'proof_copy_only': True,
                'actual_compilation_uses_current_fragment': True},
            'original_sha256': original_sha, 'exact_removed_bytes': len(port) + len(ax_ports) + len(search_ports) + len(business_port),
            'diagnostic_runner_current_sha256': sha(diagnostic_current),
            'diagnostic_calendar_inverse': diagnostic_calendar_inverse,
            'diagnostic_runner_original_sha256': sha(restored),
            'diagnostic_runner_reverse_original_byte_equality': True,
            'event_runner_current_sha256': sha(event_current), 'event_runner_original_sha256': sha(event_original),
            'event_postcapture_inverse': event_postcapture_inverse,
            'event_calendar_inverse': event_calendar_inverse,
            'event_runner_reverse_original_byte_equality': True,
            'fail_only_port': True, 'reverse_original_byte_equality': True}


def packed(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':')) + '\n').encode()


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def inventory(source):
    result = {}
    for directory, dirs, files in os.walk(source, followlinks=False):
        for name in dirs:
            need(not Path(directory, name).is_symlink(), 'source directory symlink refused')
        for name in files:
            path = Path(directory, name)
            relative = path.relative_to(source).as_posix()
            with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
                before = os.fstat(stream.fileno())
                need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'regular single-link source required: ' + relative)
                mode = stat.S_IMODE(before.st_mode)
                need(mode in (0o644, 0o755), 'canonical reviewed source mode required: ' + relative)
                digest = hashlib.sha256()
                blob = hashlib.sha1(('blob ' + str(before.st_size) + '\0').encode())
                size = 0
                for value in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(value)
                    blob.update(value)
                    size += len(value)
                after = os.fstat(stream.fileno())
            current = path.lstat()
            fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_nlink')
            need(size == before.st_size and all(getattr(before, key) == getattr(after, key) == getattr(current, key) for key in fields),
                 'source changed during read: ' + relative)
            result[relative] = {'bytes': size, 'sha256': digest.hexdigest(), 'mode': mode, 'git_blob_sha1': blob.hexdigest()}
    return dict(sorted(result.items()))


def component_tree(values):
    root = {}
    for name, value in values.items():
        branch = root
        parts = name.split('/')
        for part in parts[:-1]:
            branch = branch.setdefault(part, {})
        branch[parts[-1]] = value
    def tree(branch):
        entries = []
        for name, value in branch.items():
            leaf = 'git_blob_sha1' in value
            mode = ('100755' if value['mode'] == 0o755 else '100644') if leaf else '40000'
            digest = value['git_blob_sha1'] if leaf else tree(value)
            entries.append(((name + ('' if leaf else '/')).encode(), mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(digest)))
        raw = b''.join(value for _, value in sorted(entries))
        return hashlib.sha1(('tree ' + str(len(raw)) + '\0').encode() + raw).hexdigest()
    return tree(root)


def check_frozen(source, values, production, manifest_sha, map_sha):
    if manifest_sha is None and map_sha is None:
        return False
    need(manifest_sha is not None and map_sha is not None and all(re.fullmatch('[0-9a-f]{64}', value) for value in (manifest_sha, map_sha)),
         'both actual final manifest/map SHA256 values required')
    raw = (source / 'SOURCE-MANIFEST.json').read_bytes()
    need(sha(raw) == manifest_sha, 'final source manifest differs')
    manifest = json.loads(raw)
    need(manifest['schema'] == 'hepta.local-source.v3' and manifest['production_input_map_sha256'] == map_sha == sha(packed(production)),
         'actual compiler map differs from frozen manifest')
    declared = {row['path']: row for row in manifest['files']}
    need(len(declared) == len(manifest['files']) and set(declared) | {'SOURCE-MANIFEST.json'} == set(values), 'manifest must cover the full exact source set')
    for name, row in declared.items():
        need(row['bytes'] == values[name]['bytes'] and row['sha256'] == values[name]['sha256'], 'frozen file differs: ' + name)
    need(manifest['complete_source_files'] == len(values) and manifest['production_build_inputs_count'] == len(production)
         and manifest['main_java_sources'] == len(list((source / 'src').rglob('*.java'))), 'frozen source counts differ')
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--json-jar', type=Path, required=True)
    parser.add_argument('--manifest-sha')
    parser.add_argument('--map-sha')
    args = parser.parse_args()
    source = args.source.absolute()
    output = args.output.absolute()
    need(source.resolve(strict=True) == source and source.is_dir(), 'canonical explicit source directory required')
    need(source != output and source not in output.parents and not output.exists(), 'fresh output must be outside source')
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    events = module(source / 'tests/native-observation-events/run_host.py', 'original_observer_event_runner')
    helper = events.helper(source)
    jdk = args.java_home.resolve(strict=True)
    java, javac, jar = jdk / 'bin/java', jdk / 'bin/javac', args.json_jar.resolve(strict=True)
    tools = [java, javac, jdk / 'lib/modules', jdk / 'lib/ct.sym', jar]
    result = {'schema': 'hepta.native-observation-screenshot-seed-host-gate.v1', 'all_pass': False,
              'source': str(source), 'stages': [], 'phone_actions': 0, 'android_execution': False,
              'model_executed': False, 'business_completion_verified': False,
              'new_action_authority': False, 'action_replayed': False, 'read_permit_expanded': False,
              'deadline_expanded_by_this_candidate': False,
              'compiler_contract': 'JDK17 --release 8 -Xlint:all -Werror',
              'boundary': 'Actual complete observer, preserved original assertions, reviewed before-accept scheduling with one added assertion, and exact pinned fail-only form/AX ports; synthetic Android graph/window/clock/pixel IO and synthetic Session carrier. Device traversal, Session permit issuance, currentness and business completion are not proved.'}
    before = None
    tool_before = None
    try:
        before = inventory(source)
        helper.save(output / 'SOURCE-BEFORE.json', before)
        result['source_before'] = helper.meta(output / 'SOURCE-BEFORE.json')
        result['source_before_sha256'] = sha(packed(before))
        result['complete_source_files'] = len(before)
        result['component_git_tree_sha1'] = component_tree(before)
        result['source_manifest'] = helper.meta(source / 'SOURCE-MANIFEST.json')
        result['fixture_fail_only_port'] = verify_original_fixtures(source, before)
        result['original_fixture_pins'] = PINNED_FIXTURES
        identity = module(source / 'tools/build_identity.py', 'actual_seed_gate_build_identity')
        production = identity.source_inputs(source)
        helper.save(output / 'PRODUCTION-INPUTS.json', production)
        result['production_input_map_sha256'] = sha(packed(production))
        result['production_input_count'] = len(production)
        result['main_java_sources'] = len(list((source / 'src').rglob('*.java')))
        result['frozen_manifest_verified'] = check_frozen(source, before, production, args.manifest_sha, args.map_sha)
        need(all(path.is_file() for path in tools), 'JDK17 modules/API closure and JSON required')
        need(jar.stat().st_size == 78332 and sha(jar.read_bytes()) == '3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed', 'reviewed JSON pin differs')
        tool_before = [helper.meta(path) for path in tools]
        result['tools_before'] = tool_before
        generated = output / 'generated'
        generated.mkdir()
        extraction = events.generate(source, generated, helper)
        extraction = events.add_saved_graph_seed_cases(source, generated, helper, extraction)
        path = generated / 'ObserverPipelineHost.java'
        original = path.read_text()
        postcapture_call = '        postCaptureSettleCases();'
        postcapture_counted = '''        int legacyCases=EventChecks.names.size(),legacyAssertions=EventChecks.assertions;
        postCaptureSettleCases();
        int postcaptureCases=EventChecks.names.size()-legacyCases,postcaptureAssertions=EventChecks.assertions-legacyAssertions;'''
        counted = events.replace(original, postcapture_call, postcapture_counted)
        fragment = (source / TEST / 'ScreenshotGraphSeedCases.fragment').read_text()
        text = events.replace(counted, '    public static void main(String[] args)throws Exception{',
                              fragment + '\n    public static void main(String[] args)throws Exception{')
        marker = '        observationIo.executor.shutdown();EventChecks.finish(args[0]);'
        appended = '''        int originalCases=legacyCases,originalAssertions=legacyAssertions;
        int beforeSeedCases=EventChecks.names.size(),beforeSeedAssertions=EventChecks.assertions;
        screenshotGraphSeedCases();
        org.json.JSONObject seedResult=new org.json.JSONObject().put("schema","hepta.native-observation-screenshot-seed-cases.v1")
            .put("all_pass",true).put("original_cases",originalCases).put("original_assertions",originalAssertions)
            .put("postcapture_cases",postcaptureCases).put("postcapture_assertions",postcaptureAssertions)
            .put("postcapture_case_names",new java.util.ArrayList<String>(EventChecks.names.subList(originalCases,beforeSeedCases)))
            .put("new_cases",EventChecks.names.size()-beforeSeedCases).put("new_assertions",EventChecks.assertions-beforeSeedAssertions)
            .put("new_case_names",new java.util.ArrayList<String>(EventChecks.names.subList(beforeSeedCases,EventChecks.names.size())));
        Files.write(Paths.get(args[1]),seedResult.toString(2).getBytes(StandardCharsets.UTF_8));
        observationIo.executor.shutdown();EventChecks.finish(args[0]);'''
        text = events.replace(text, marker, appended)
        need(text.replace(fragment + '\n', '', 1).replace(appended, marker, 1)
             .replace(postcapture_counted, postcapture_call, 1) == original,
             'only independent new cases and statistics may be appended to generated fixture')
        path.write_text(text, encoding='utf-8')
        extraction['independent_screenshot_seed_cases'] = {'fragment': helper.meta(source / TEST / 'ScreenshotGraphSeedCases.fragment'),
                                                          'original_generated_fixture_sha256': sha(original.encode()),
                                                          'append_only_reverse_byte_equality': True,
                                                          'pre_append_generated_fixture_preserved_exactly': True,
                                                          'original_cases_and_assertions_preserved': True,
                                                          'saved_seed_scheduling_repaired': True,
                                                          'reviewed_before_accept_assertions_added': 1}
        helper.save(output / 'EXTRACTION.json', extraction)
        classes = output / 'classes'
        classes.mkdir()
        sources = [source / events.PKG / name for name in events.JAVA if name not in ('HeptaAccessibilityService.java', 'PhoneObservation.java')]
        sources += [source / 'tests/native-observation-events/EventChecks.java', path]
        sources += helper.png_sources(source)
        row = helper.stage('compile', [str(javac), '--release', '8', '-encoding', 'UTF-8', '-Xlint:all', '-Werror', '-cp', str(jar), '-d', str(classes)] + list(map(str, sources)), output)
        result['stages'].append(row)
        need(row['exit_code'] == 0, 'actual observer compilation failed')
        row = helper.stage('cases', [str(java), '-cp', str(classes) + os.pathsep + str(jar), 'org.trillionnium.hepta.local.ObserverPipelineHost',
                                    str(output / 'CASES.json'), str(output / 'SEED-CASES.json')], output)
        result['stages'].append(row)
        need(row['exit_code'] == 0, 'actual observer original or independent seed cases failed')
        cases = json.loads((output / 'CASES.json').read_text())
        new = json.loads((output / 'SEED-CASES.json').read_text())
        need(cases['all_pass'] is True and len(cases['case_names']) == len(set(cases['case_names'])) == cases['cases'], 'complete unique passing event cases required')
        need(new['all_pass'] is True and new['original_cases'] == 238 and new['original_assertions'] == 3671,
             'all original 238 cases and 3670 assertions plus the reviewed before-accept assertion must execute')
        need(sha(packed(cases['case_names'][:new['original_cases']])) == LEGACY_EVENT_CASE_NAMES_SHA256,
             'complete original 238 case names and order must be preserved')
        need(new['postcapture_cases'] == 10 and new['postcapture_assertions'] == 170
             and new['postcapture_case_names'] == POSTCAPTURE_CASE_NAMES,
             'all ten postcapture cases and 170 assertions must execute separately')
        need(new['new_cases'] == len(new['new_case_names']) == 35 and all(name.startswith('screenshot_seed_') for name in new['new_case_names'])
             and cases['cases'] == new['original_cases'] + new['postcapture_cases'] + new['new_cases']
             and cases['assertions'] == new['original_assertions'] + new['postcapture_assertions'] + new['new_assertions'],
             'independent seed case accounting differs')
        result.update(all_pass=True, cases=cases['cases'], assertions=cases['assertions'], original_cases=new['original_cases'],
                      original_assertions=new['original_assertions'], new_cases=new['new_cases'], new_assertions=new['new_assertions'],
                      postcapture_cases=new['postcapture_cases'], postcapture_assertions=new['postcapture_assertions'],
                      postcapture_case_names=new['postcapture_case_names'], original_case_names_sha256=LEGACY_EVENT_CASE_NAMES_SHA256,
                      original_cases_and_assertions_preserved=True, historical_original_assertions=3670,
                      reviewed_before_accept_assertions_added=1, cases_file=helper.meta(output / 'CASES.json'),
                      seed_cases_file=helper.meta(output / 'SEED-CASES.json'), extraction_file=helper.meta(output / 'EXTRACTION.json'),
                      generated_files={path.name: helper.meta(path) for path in generated.glob('*.java')})
    except Exception as error:
        result['error'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        try:
            after = inventory(source)
            helper.save(output / 'SOURCE-AFTER.json', after)
            result['source_after'] = helper.meta(output / 'SOURCE-AFTER.json')
            result['source_after_sha256'] = sha(packed(after))
            result['source_inputs_unchanged'] = before is not None and before == after
            result['component_git_tree_after_sha1'] = component_tree(after)
            result['tools_after'] = [helper.meta(path) for path in tools] if tool_before is not None else None
            result['tools_unchanged'] = tool_before is not None and tool_before == result['tools_after']
            result['all_pass'] = result['all_pass'] and result['source_inputs_unchanged'] and result['tools_unchanged']
        except Exception as error:
            result['all_pass'] = False
            result['finalization_error'] = {'type': type(error).__name__, 'message': str(error)}
        helper.save(output / 'RESULT.json', result)
    print(json.dumps({'all_pass': result['all_pass'], 'result': helper.meta(output / 'RESULT.json')}))
    return 0 if result['all_pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
