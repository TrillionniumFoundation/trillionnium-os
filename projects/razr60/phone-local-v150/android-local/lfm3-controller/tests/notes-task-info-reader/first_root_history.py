"""Exact inverse of reviewed first-launch additions for older whole-file integrity gates.
Only historical byte comparisons consume the projections. Test execution uses the current files.
"""
from hashlib import sha256

# Current SHA, parent SHA, and parent line replacements in current line coordinates.
CHANGES = {'BackgroundDisplayBroker.java': ('aa21168e02679425bac3d2d117fabad9ae33ac3825a2e300b59586ec5a0eb6fc',
                                  'a855ce737251e86f33a9bc849f07c5342edfe238a1c15f6ca79494883856aeba',
                                  [(586, 588, 'c18bcc496b7c197e7dd13c862d39fd26c58571d02910ff2ef25b588311ef9a2b', ''),
                                   (1123,
                                    1124,
                                    '04efd24b9cb3f2420d7732644a21c685a85d0721c90f75236b61da69efb8793a',
                                    '                    '
                                    'publicNotesCustody.observe(publicNotesReader.frame(),SystemClock.elapsedRealtime());\n')]),
 'NotesTaskInfoReaderHostTest.java': ('76dc48b6da29be78df43acbb94112bb4325e6746bcf72d4333c43362be138e47',
                                      '58e8222fc154eb4bb8ae69d64c19171587c24cea5124dbccd8c3f85854723c90',
                                      [(261, 317, 'c233e5f1c68c9e35e025e97192534284d8fdc6e6d7077b95d0d03796bd14f078', ''),
                                       (469, 470, '96799c8bb7569189bdd8b7ee481bb66fbc3e44bae18b165da59c7c5bc6e3ebf6', ''),
                                       (473,
                                        474,
                                        'ab3f04e8dec397f1926e63eeccb55e7c2997f63f7519f27fedea8fdbef8b2f03',
                                        '                .put("taskinfo_stability",stability)\n')]),
 'PublicPersonalNotesCustody.java': ('61b21582c5fbc147a3e67e5d81df0ce186ce9eb765b88c5d374d39d001fa9bd1',
                                     '31446d280230ca4f2b0512dea7de095a5ebc52d1e23a7ba0ffe75d240f4cbcee',
                                     [(54, 58, 'b4df16c2def38966ff3c29e65ddb3012517b7c44183400ba7c88f1efd719a912', ''),
                                      (96,
                                       114,
                                       '657e00c923128ccd85dfc59c02c7ddaa61fa9cfd4ebe26c77aa9ec6c3ff76361',
                                       '    synchronized void '
                                       'markLaunch(){need(attempted&&display>1&&!unknown&&!retiring&&!releasePrepared,"NOTES_LAUNCH_CUSTODY_RETIRED");launched=true;}\n')]),
 'PublicPersonalNotesReader.java': ('d988d18616fee3759aad614a8c246caad1e2e61189416be534cd6d898d9c92e4',
                                    'eb966bf1cb76822b6c694aa11d6f772158448abc3396f86152ec97ba28ab390c',
                                    [(45, 70, '9615b05efb2cf6aabe5fe5951bca9233f7c615b3ca0bc431365813ff387b64a1', ''),
                                     (105,
                                      107,
                                      '42443a6ecdb6a1f44de2727673b3f4bde3ee432ff031f51e93df3f9cb9c9ba81',
                                      '            out.put("actual_root_read_failure",error instanceof '
                                      'TaskInfoReadFailure?((TaskInfoReadFailure)error).evidence:JSONObject.NULL);\n'),
                                     (136,
                                      138,
                                      '923bd63dbe597311dc1565d187fdfe6f4209b78bc3709428ae712ca988c9616b',
                                      '    synchronized PublicPersonalNotesCustody.Frame frame()throws Exception{\n'),
                                     (144, 145, 'ca683f1e997ef6d6639e76155d32097cf5bb2d2ae6527fb545b8247aaf1b7961', ''),
                                     (152,
                                      169,
                                      '44e4d7fec0fc14ab070e99761c015daba8c7fc9402a054b1042897be253152cd',
                                      '            '
                                      'need(first.keySet().equals(middle.keySet())&&middle.keySet().equals(last.keySet()),"NOTES_ROOT_CENSUS_CHANGED");\n'),
                                     (170,
                                      177,
                                      '6fb87f864e0ebdd329ff69e7a6429937fd722325b07d2dcd0a4c7dc237a15250',
                                      '            '
                                      'need(identities.keySet().equals(first.keySet()),"NOTES_ROOT_CENSUS_CHANGED");\n'),
                                     (194, 195, '0cac5cc2b090ff4b94a4793b508ea31c2b43f386c794e4c6f9338667a250fdec', ''),
                                     (203, 217, '588265795c9273581aa09564ccb914d29fca4ef2bace53a17a2d83746711b406', '')]),
 'run_host.py': ('e1715ba4043e085fb3c8fd5f4a2fb1c65cb35d1bf543cd1ef003f676bc6f38eb',
                 'de2628ec0f35fdf945ef22e82527c4d51ff4496996400350225b32d2e14651d2',
                 [(22, 23, '4c50fd4db444d117ea7a9399e958a2e083f37412a443a9c704f459300b8b5419', ''),
                  (40,
                   58,
                   'd2f9efa277463e16923533a1975f86d89992c187b4a54e117b326c602263091c',
                   '    '
                   "tracked=list(dict.fromkeys(files+private_files+[own/'prepare_fixture.py',Path(__file__).resolve(),capture,jar,jdk/'bin/javac',jdk/'bin/java',jdk/'lib/ct.sym']))\n"),
                  (60,
                   61,
                   'db6ca206c754fa8d03353a0ab1370fd5792774f23d8900855d3efd28984bff03',
                   '    '
                   "need(pin(bg/'PublicPersonalNotesReader.java')['sha256']=='eb966bf1cb76822b6c694aa11d6f772158448abc3396f86152ec97ba28ab390c','approved "
                   "reader differs')\n"),
                  (72, 73, 'b1b27683c9bc1ddc423721def1b9085d6a513dbe0fe176930ced120d4be1fba7', ''),
                  (91, 93, '1de4568a47ef501ce65ca2048ca837f6e1a2aebd2491ce5bd51840c42a4e20ed', '')])}

def predecessor(name, text):
    current, parent, replacements = CHANGES[name]
    digest = lambda material: sha256(material.encode()).hexdigest()
    if digest(text) == parent:
        return text
    if digest(text) != current:
        raise ValueError("Unreviewed first-root change in " + name)
    lines = text.splitlines(True)
    for start, end, reviewed, old in reversed(replacements):
        if digest("".join(lines[start:end])) != reviewed:
            raise ValueError("First-root inverse span differs in " + name)
        lines[start:end] = [old]
    restored = "".join(lines)
    if digest(restored) != parent:
        raise ValueError("First-root inverse differs from the prior file " + name)
    return restored
