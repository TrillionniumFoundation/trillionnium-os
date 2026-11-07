def inventory_value(value):
    """Validate complete topology; only elapsed wall-clock measurement is excluded."""
    C.need(isinstance(value, dict) and set(value) == {'schema', 'roots', 'entries',
        'file_bytes_hashed', 'elapsed_seconds', 'inventory_is_closure_or_retirement'}
        and value['schema'] == 'hepta.native-guard.complete-inventory.v1'
        and value['inventory_is_closure_or_retirement'] is False,
        'complete original inventory schema differs')
    roots, entries = value['roots'], value['entries']
    C.need(isinstance(roots, list) and 1 <= len(roots) <= 64
        and len(roots) == len(set(roots)) and isinstance(entries, dict)
        and 1 <= len(entries) <= 30000, 'bounded complete inventory required')
    paths = [Path(p) for p in roots]
    C.need(all(p.is_absolute() and str(p) == s and '..' not in p.parts
               for p, s in zip(paths, roots)), 'inventory root path differs')
    C.need(all(a == b or not (a in b.parents or b in a.parents) for a in paths for b in paths),
           'inventory roots overlap')
    C.need(all(p in entries and entries[p].get('kind') in ('directory', 'absent') for p in roots),
           'inventory root is absent or not a directory')
    root_parts = frozenset(p.parts for p in paths)
    root_depths = frozenset(len(parts) for parts in root_parts)
    children = {}
    for name in entries:
        p = Path(name)
        children.setdefault(str(p.parent), []).append(p.name)
    total = 0
    for name, row in entries.items():
        p = Path(name)
        C.need(p.is_absolute() and str(p) == name and '..' not in p.parts
               and sum(p.parts[:depth] in root_parts for depth in root_depths
                       if depth <= len(p.parts)) == 1,
               'inventory entry left its unique complete root')
        if row.get('kind') == 'absent':
            C.need(row == {'kind': 'absent', 'absence': 'ENOENT'} and name in roots
                   and re.fullmatch(r'/proc/1/root/data/local/tmp/hepta-native-guard-[0-9a-f]{32}', name)
                   and not children.get(name), 'only an explicit fixture-root ENOENT may be retained')
            continue
        m = row.get('metadata')
        C.need(isinstance(m, list) and len(m) == 9 and all(type(n) is int for n in m),
               'inventory original metadata differs')
        if row.get('kind') == 'directory':
            C.need(set(row) == {'kind', 'metadata', 'names'} and stat.S_ISDIR(m[2])
                   and isinstance(row['names'], list) and row['names'] == sorted(set(row['names']))
                   and all(isinstance(n, str) and n not in ('', '.', '..') and '/' not in n
                           and '\0' not in n for n in row['names']), 'inventory directory differs')
            actual = sorted(children.get(name, []))
            C.need(actual == row['names'], 'inventory omitted or fabricated a directory child')
        else:
            C.need(set(row) == {'kind', 'metadata', 'bytes', 'sha256'}
                   and row['kind'] == 'file' and stat.S_ISREG(m[2]) and m[5] == 1
                   and type(row['bytes']) is int and 0 <= row['bytes'] <= 64*1024*1024
                   and m[6] == row['bytes'] and isinstance(row['sha256'], str)
                   and C.HASH.fullmatch(row['sha256']), 'inventory original file differs')
            total += row['bytes']
        if str(p) not in roots:
            C.need(str(p.parent) in entries and entries[str(p.parent)]['kind'] == 'directory',
                   'inventory entry has no retained parent')
    C.need(type(value['file_bytes_hashed']) is int and total == value['file_bytes_hashed']
           and total <= 512*1024*1024, 'inventory byte accounting differs')
    return {k: v for k, v in value.items() if k != 'elapsed_seconds'}
