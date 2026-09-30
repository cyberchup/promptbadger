"""Input normalization applied before rules run.

v1 keeps this deliberately small: Unicode NFKC folding (turns full-width and
stylized letters into plain ASCII), stripping zero-width/invisible characters,
and collapsing whitespace. Rules match case-insensitively, so case is left alone
to keep matched_text readable.

The v2 milestone extends this module with decoding of base64/hex/ROT13 payloads,
homoglyph mapping, and leetspeak folding.
"""

from __future__ import annotations

import re
import unicodedata

# Zero-width and other invisible formatting characters commonly used to split
# keywords ("ig​nore") so naive string matching misses them.
_INVISIBLE = re.compile(
    "["
    "­"  # soft hyphen
    "᠎"  # mongolian vowel separator
    "​-‏"  # zero-width space/joiners, LRM/RLM
    "‪-‮"  # bidi embedding/override
    "⁠-⁤"  # word joiner, invisible operators
    "⁦-⁩"  # bidi isolates
    "﻿"  # zero-width no-break space / BOM
    "]"
)
_WHITESPACE = re.compile(r"\s+")


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = _INVISIBLE.sub("", text)
    text = _WHITESPACE.sub(" ", text)
    return text.strip()
