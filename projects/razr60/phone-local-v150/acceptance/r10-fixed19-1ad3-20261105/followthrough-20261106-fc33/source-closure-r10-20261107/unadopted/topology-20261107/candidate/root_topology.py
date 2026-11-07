"""Pure POSIX lexical root predicates for differential tests and benchmarks.

The inventory caller still rejects duplicate, noncanonical, relative, and '..'
roots before testing overlap.  Neither predicate touches the filesystem.
"""


def original_roots_disjoint(paths):
    """Exact R10 expression, including its equality exception."""
    return all(a == b or not (a in b.parents or b in a.parents)
               for a in paths for b in paths)


def candidate_roots_disjoint(paths):
    """Equivalent lexical POSIX ancestry test; anchors remain tuple elements."""
    root_parts = frozenset(p.parts for p in paths)
    root_depths = frozenset(len(parts) for parts in root_parts)
    return all(parts[:depth] not in root_parts
               for parts in root_parts for depth in root_depths
               if depth < len(parts))
