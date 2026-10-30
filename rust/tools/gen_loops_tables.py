"""Writes crates/lunchroom-core/src/loops/tables.rs: the punctuation and digit tables that R1.1's
repeat test ignores. Usage: python3 tools/gen_loops_tables.py crates/lunchroom-core/src/loops/tables.rs
"""
import sys, unicodedata

def ranges(pred):
    out, start = [], None
    for cp in range(0x110000):
        hit = pred(chr(cp))
        if hit and start is None:
            start = cp
        if not hit and start is not None:
            out.append((start, cp - 1))
            start = None
    if start is not None:
        out.append((start, 0x10FFFF))
    return out

def emit(name, doc, rs):
    lines = [f"/// {doc}", f"pub(crate) const {name}: [(char, char); {len(rs)}] = ["]
    for a, b in rs:
        lines.append(f"    ('\\u{{{a:x}}}', '\\u{{{b:x}}}'),")
    lines.append("];")
    return "\n".join(lines)

v = unicodedata.unidata_version
body = [
    "//! Unicode tables for R1.1's repeat test, generated from Python's `unicodedata` (Unicode "
    f"{v})",
    "//! by `rust/tools/gen_loops_tables.py`; do not edit by hand.",
    "",
    emit("PUNCTUATION", "Every character of general category P (punctuation), as inclusive ranges.",
         ranges(lambda c: unicodedata.category(c).startswith('P'))),
    "",
    emit("DIGITS", "Every character of general category Nd (decimal digit), as inclusive ranges.",
         ranges(lambda c: unicodedata.category(c) == 'Nd')),
    "",
]
open(sys.argv[1], 'w').write("\n".join(body))
print(v, 'written', sys.argv[1])
