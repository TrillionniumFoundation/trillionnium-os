def source_reader(source_raw, material):
    # This caller reads the already selected 2,667,752-byte policy original.
    # Keep the complete reviewed read() body; change only its individual-file
    # envelope to the negative constructor's existing MAX_FILE (16 MiB).
    nodes = [node for node in ast.parse(source_raw).body
             if isinstance(node, ast.FunctionDef) and node.name == 'read']
    need(len(nodes) == 1, 'one reviewed complete source reader')
    node = nodes[0]
    original = b''.join(source_raw.splitlines(keepends=True)[node.lineno - 1:node.end_lineno])
    before, after = b'<=1048576', b'<=16777216'
    need(original.count(before) == 1 and after not in original, 'one source-reader size literal')
    candidate = original.replace(before, after, 1)
    need(candidate.replace(after, before, 1) == original, 'complete source-reader inverse')
    exec(compile(candidate, '<reviewed-source-reader-bound-only>', 'exec'), material.__dict__)
    return {'parent_function': pin(original), 'candidate_function': pin(candidate),
            'before': before.decode(), 'after': after.decode(), 'full_inverse': True,
            'individual_original_max_bytes': 16777216,
            'exact3_full9_single_link_no_follow_and_BOOK_body_unchanged': True}
