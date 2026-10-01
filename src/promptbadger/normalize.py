"""Input normalization applied before rules run.

Unicode NFKC folding (turns full-width and stylized letters into plain ASCII),
stripping zero-width/invisible characters, and collapsing whitespace. Rules match
case-insensitively, so case is left alone to keep matched_text readable.

`normalize()` returns the normalized string. `Mapped` and `normalize_mapped()` do the
same while remembering, for every output character, which characters of the raw input
it came from, so a detection can point at the exact text the user sent. The
deobfuscation views in `deobfuscate.py` are built on the same mapping.
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


class Mapped:
    """A derived text plus, per character, the raw-input interval it came from.

    The per-character maps are only needed when a rule matches, which is rare, so a
    Mapped can be given a `compute` function instead and builds them on first use.
    """

    __slots__ = ("text", "_starts", "_ends", "_compute")

    def __init__(self, text: str, starts: list[int] | None = None, ends: list[int] | None = None, compute=None):
        self.text = text
        self._starts, self._ends, self._compute = starts, ends, compute

    def _maps(self) -> None:
        if self._starts is None:
            self._starts, self._ends = self._compute()
            self._compute = None

    @property
    def starts(self) -> list[int]:
        self._maps()
        return self._starts

    @property
    def ends(self) -> list[int]:
        self._maps()
        return self._ends

    @classmethod
    def identity(cls, raw: str) -> Mapped:
        n = len(raw)
        return cls(raw, compute=lambda: (list(range(n)), list(range(1, n + 1))))

    def span(self, start: int, end: int) -> tuple[int, int]:
        """The raw-input interval covered by text[start:end]."""
        if not self.text:
            return (0, 0)
        if end <= start:
            i = min(start, len(self.text) - 1)
            return (self.starts[i], self.starts[i])
        return (min(self.starts[start:end]), max(self.ends[start:end]))


class Builder:
    """Assemble a Mapped text piece by piece."""

    def __init__(self) -> None:
        self.chars: list[str] = []
        self.starts: list[int] = []
        self.ends: list[int] = []

    def add(self, text: str, start: int, end: int) -> None:
        """Append `text`, every character attributed to raw[start:end]."""
        for ch in text:
            self.chars.append(ch)
            self.starts.append(start)
            self.ends.append(end)

    def copy(self, src: Mapped, i: int, j: int) -> None:
        """Append src.text[i:j] with its existing mapping."""
        self.chars.extend(src.text[i:j])
        self.starts.extend(src.starts[i:j])
        self.ends.extend(src.ends[i:j])

    def build(self) -> Mapped:
        return Mapped("".join(self.chars), self.starts, self.ends)


def _clusters(text: str):
    """Yield (i, j) for a base character plus the combining marks that follow it."""
    i, n = 0, len(text)
    while i < n:
        j = i + 1
        while j < n and (unicodedata.combining(text[j]) or "ᅠ" <= text[j] <= "ᇿ"):
            j += 1
        yield i, j
        i = j


def fold(src: Mapped) -> Mapped:
    """NFKC + strip invisible characters, keeping the mapping. Whitespace is untouched."""
    if unicodedata.is_normalized("NFKC", src.text) and not _INVISIBLE.search(src.text):
        return src  # the common case: nothing to fold
    b = Builder()
    for i, j in _clusters(src.text):
        out = _INVISIBLE.sub("", unicodedata.normalize("NFKC", src.text[i:j]))
        b.add(out, src.starts[i], src.ends[j - 1])
    return b.build()


def collapse_whitespace(src: Mapped) -> Mapped:
    """Collapse whitespace runs to one space and trim the ends, keeping the mapping."""
    text = _WHITESPACE.sub(" ", src.text).strip()

    def compute() -> tuple[list[int], list[int]]:
        b, last = Builder(), 0
        for m in _WHITESPACE.finditer(src.text):
            b.copy(src, last, m.start())
            if m.start() > 0 and m.end() < len(src.text):
                b.add(" ", src.starts[m.start()], src.ends[m.end() - 1])
            last = m.end()
        b.copy(src, last, len(src.text))
        built = b.build()
        if built.text != text:  # cannot happen, but never return a misaligned map
            coarse = _coarse(text, (src.ends or [0])[-1])
            return coarse.starts, coarse.ends
        return built.starts, built.ends

    return Mapped(text, compute=compute)


def _coarse(text: str, raw_len: int) -> Mapped:
    """Proportional mapping, for the rare text where per-cluster NFKC differs."""
    n = max(len(text), 1)
    starts = [min(raw_len, i * raw_len // n) for i in range(len(text))]
    ends = [min(raw_len, max(s + 1, (i + 1) * raw_len // n)) for i, s in enumerate(starts)]
    return Mapped(text, starts, ends)


def normalize_mapped(raw: str, folded: Mapped | None = None) -> Mapped:
    """normalize(raw), with a raw-input mapping. The text always equals normalize(raw)."""
    mapped = collapse_whitespace(folded if folded is not None else fold(Mapped.identity(raw)))
    expected = normalize(raw)
    return mapped if mapped.text == expected else _coarse(expected, len(raw))
