"""
Undo the disguises an attacker uses to slip text past keyword patterns.

The keyword guard in guards.py matches the text exactly as written, so the
adaptive evaluation (adaptive/) got past it with look-alike letters,
zero-width characters, fullwidth forms, underscores, URL encoding and base64.
A model reads through all of those. This module produces the *views* of a
string a model could read, and the verified guard checks every view.

It cannot help against paraphrase: an instruction that doesn't use the
listed words is not a disguise, it's a different sentence. That is why the
verified and trusted modes don't rely on keywords for safety (see trust.py).
"""

import base64
import binascii
import re
import unicodedata
from urllib.parse import unquote

# Letters from other scripts that look like Latin ones. Covers the Cyrillic
# and Greek forms used in confusable attacks; not the full Unicode table.
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w", "ɡ": "g",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "У": "Y", "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S",
    "α": "a", "ε": "e", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "ν": "v", "ι": "i", "κ": "k",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
})

# Digits and symbols used as letters ("1gn0re"). Only applied inside words that
# mix letters and digits, so version numbers and IP addresses are untouched.
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_MIXED_WORD = re.compile(r"\b(?=\w*[a-zA-Z])(?=\w*[0-9@$])[\w@$]+\b")
_SEPARATORS = re.compile(r"[_+\-.~*|/\\]+")
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")
_ENTITY = re.compile(r"&#(x[0-9a-fA-F]+|\d+);")
MAX_DECODE_DEPTH = 2


def strip_invisible(text: str) -> str:
    """Remove format characters (zero-width space/joiner, BOM, bidi controls)."""
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")


def fold(text: str) -> str:
    """NFKC (fullwidth -> ASCII, ligatures), invisible characters out, look-alikes to Latin."""
    return strip_invisible(unicodedata.normalize("NFKC", text)).translate(CONFUSABLES)


def deleet(text: str) -> str:
    return _MIXED_WORD.sub(lambda m: m.group(0).translate(LEET), text)


def _printable(raw: bytes) -> str | None:
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not decoded or sum(ch.isprintable() or ch.isspace() for ch in decoded) / len(decoded) < 0.9:
        return None
    return decoded


def decoded_segments(text: str) -> list[str]:
    """Text hidden in base64, hex or HTML entities inside the string."""
    found = []
    for match in _B64.finditer(text):
        chunk = match.group(0)
        try:
            out = _printable(base64.b64decode(chunk + "=" * (-len(chunk) % 4), validate=True))
        except (binascii.Error, ValueError):
            out = None
        if out:
            found.append(out)
    for match in _HEX.finditer(text):
        out = _printable(bytes.fromhex(match.group(0)))
        if out:
            found.append(out)
    if _ENTITY.search(text):
        found.append(_ENTITY.sub(lambda m: chr(int(m.group(1)[1:], 16) if m.group(1)[0] == "x"
                                               else int(m.group(1))), text))
    return found


def views(text: str, depth: int = 0) -> list[str]:
    """Every reading of `text` worth checking, the original first, duplicates removed."""
    base = fold(text)
    candidates = [text, base, unquote(base), _SEPARATORS.sub(" ", base), deleet(base),
                  deleet(_SEPARATORS.sub(" ", unquote(base)))]
    if depth < MAX_DECODE_DEPTH:
        for segment in decoded_segments(unquote(base)):
            candidates += views(segment, depth + 1)
    seen, out = set(), []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def changed(text: str) -> bool:
    """True if the text reads differently once disguises are removed (a weak signal by itself)."""
    return fold(text) != text
