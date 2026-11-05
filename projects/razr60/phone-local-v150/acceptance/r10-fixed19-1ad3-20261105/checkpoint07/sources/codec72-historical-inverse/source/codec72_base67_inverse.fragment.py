CODEC72_BASE67_LATE = {'schema': 'hepta.codec72.exact-historical-byte-inverse.v1', 'parent': {'bytes': 74287, 'sha256': '396da713d4b7cab45d0eda80b65df82d7b570440a9c9ea1f74f342b81031ec97'}, 'result': {'bytes': 66996, 'sha256': 'c50a219efd992ce1353494ace2656af20c932cbc32530b0085e38a79975d8add'}, 'operations': [{'kind': 'copy', 'start': 0, 'bytes': 4336}, {'kind': 'replace', 'start': 4336, 'bytes': 115, 'literal_utf8': ''}, {'kind': 'copy', 'start': 4451, 'bytes': 277}, {'kind': 'replace', 'start': 4728, 'bytes': 133, 'literal_utf8': '               and sum(p == q or q in p.parents for q in paths) == 1,\n'}, {'kind': 'copy', 'start': 4861, 'bytes': 25182}, {'kind': 'replace', 'start': 30043, 'bytes': 6990, 'literal_utf8': ''}, {'kind': 'copy', 'start': 37033, 'bytes': 30}, {'kind': 'replace', 'start': 37063, 'bytes': 85, 'literal_utf8': '    """Raw-load the exact R7 reader and common under the old combination."""\n'}, {'kind': 'copy', 'start': 37148, 'bytes': 854}, {'kind': 'replace', 'start': 38002, 'bytes': 48, 'literal_utf8': ''}, {'kind': 'copy', 'start': 38050, 'bytes': 1485}, {'kind': 'replace', 'start': 39535, 'bytes': 88, 'literal_utf8': '        return old\n'}, {'kind': 'copy', 'start': 39623, 'bytes': 96}, {'kind': 'replace', 'start': 39719, 'bytes': 24, 'literal_utf8': '        if saved is None:\n'}, {'kind': 'copy', 'start': 39743, 'bytes': 34544}]}


def _codec72_base_late_bytes(parent_raw):
    """Recover exact c50a bytes from actual396d as data, without executing either.

    This is one reviewed contiguous byte-range recipe, not a general patch or
    source-normalization API. Both complete input and output identities bind it.
    """
    packet = CODEC72_BASE67_LATE
    _codec72_need(type(packet) is dict and set(packet) == {
        'schema', 'parent', 'result', 'operations'} and packet['schema'] ==
        'hepta.codec72.exact-historical-byte-inverse.v1', 'codec72 historical inverse packet differs')
    _codec72_pin(parent_raw, packet['parent'], 'actual396d complete source before historical inverse')
    _codec72_need(packet['parent'] == {'bytes': 74287, 'sha256':
        '396da713d4b7cab45d0eda80b65df82d7b570440a9c9ea1f74f342b81031ec97'}
        and type(packet['result']) is dict and set(packet['result']) == {'bytes', 'sha256'}
        and type(packet['result']['bytes']) is int and packet['result'] == {'bytes': 66996, 'sha256':
        'c50a219efd992ce1353494ace2656af20c932cbc32530b0085e38a79975d8add'},
        'codec72 fixed historical input/output identity differs')
    operations = packet['operations']
    _codec72_need(type(operations) is list and len(operations) == 15,
                  'codec72 exact historical operation count differs')
    cursor = 0; result = bytearray()
    for item in operations:
        _codec72_need(type(item) is dict and item.get('kind') in ('copy', 'replace')
            and set(item) == ({'kind', 'start', 'bytes'} if item['kind'] == 'copy' else
                             {'kind', 'start', 'bytes', 'literal_utf8'})
            and type(item['start']) is int and type(item['bytes']) is int
            and item['start'] == cursor and 0 <= item['bytes'] <= len(parent_raw) - cursor,
            'codec72 historical ranges are incomplete, overlapping, reordered or malformed')
        end = cursor + item['bytes']
        if item['kind'] == 'copy':
            _codec72_need(item['bytes'] > 0, 'codec72 empty historical copy range')
            piece = parent_raw[cursor:end]
        else:
            _codec72_need(type(item['literal_utf8']) is str,
                          'codec72 exact historical literal must be UTF-8 text')
            piece = item['literal_utf8'].encode('utf-8', 'strict')
            _codec72_need(len(piece) <= 192, 'codec72 historical literal exceeds fixed recipe budget')
        _codec72_need(len(result) + len(piece) <= 66996,
                      'codec72 historical reconstruction exceeds exact original size')
        result.extend(piece); cursor = end
    _codec72_need(cursor == len(parent_raw), 'codec72 historical inverse did not consume the complete source')
    return _codec72_pin(bytes(result), packet['result'], 'whole inverse to retained c50a proof-only bytes')
