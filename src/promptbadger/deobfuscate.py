"""Deobfuscation views: decode-and-rescan for prompts and retrieved content.

Attackers hide instructions from filters by changing how they are written rather than
what they say (MITRE ATLAS AML.T0068 LLM Prompt Obfuscation). Each view undoes one
family of tricks; the scanner runs the rules on every view and reports the first view
a rule fires in, with the matched text and span taken from the raw input:

  tags        Unicode tag characters (invisible "ASCII smuggling") made visible
  unescaped   HTML entities, %-encoding, \\x and \\u escapes
  decoded     base64 / hex / binary runs that decode to readable text (two levels)
  spacing     letter-spaced words ("i-g-n-o-r-e", "I G N O R E"); when the word breaks
              are lost ("S a y t h a t"), words are recovered from the rule pack's
              vocabulary
  homoglyph   Cyrillic/Greek look-alikes inside words that also use Latin letters
  leetspeak   digit and symbol swaps inside words that mix letters and digits
  rot13, reversed, reversed-words
              whole-text ciphers, built for every input, so they are only scanned
              when the deciphered text reveals words the original did not contain
              (a cipher view of ordinary text is gibberish)

Views are additive: the original text is always scanned first, so a view can add a
detection but never hide one. Views compose in the order above, so base64 of
leetspeak or letter-spaced leetspeak are also covered.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass

from .normalize import Builder, Mapped, collapse_whitespace, fold, normalize_mapped

OBFUSCATION_ATLAS = "AML.T0068"  # LLM Prompt Obfuscation
MAX_VIEWS = 16
_MAX_RUN = 100_000  # skip encoded runs longer than this (attachments, images)
_MAX_CANDIDATES = 64  # per decoding pass


@dataclass(frozen=True)
class View:
    name: str  # "original", "leetspeak", "decoded+leetspeak", ...
    text: Mapped


def _join(a: str, b: str) -> str:
    return f"{a}+{b}" if a else b


def _replace(src: Mapped, matches: Iterable[tuple[int, int, str]]) -> Mapped | None:
    """Replace src.text[i:j] with `out` for each (i, j, out); None if nothing changed."""
    b, last, changed = Builder(), 0, False
    for i, j, out in matches:
        b.copy(src, last, i)
        b.add(out, src.starts[i], src.ends[j - 1])
        last, changed = j, True
    if not changed:
        return None
    b.copy(src, last, len(src.text))
    return b.build()


def _translate_tokens(src: Mapped, token: re.Pattern, should, table) -> Mapped | None:
    """Character-for-character translation of qualifying tokens (the mapping is kept).
    `table` is a str.translate table or a function from token to translated token."""
    chars, changed = list(src.text), False
    for m in token.finditer(src.text):
        if should(m.group(0)):
            out = table(m.group(0)) if callable(table) else m.group(0).translate(table)
            if out != m.group(0):
                chars[m.start() : m.end()] = out
                changed = True
    return Mapped("".join(chars), compute=lambda: (src.starts, src.ends)) if changed else None


# --- tags: invisible Unicode tag characters -------------------------------------------

_TAG_RUN = re.compile("[\U000e0000-\U000e007f]+")
_BLACK_FLAG = "\U0001f3f4"  # emoji subdivision flags (England, Scotland, Wales) use tags


def _reveal_tags(src: Mapped) -> Mapped | None:
    b, last, changed = Builder(), 0, False
    for m in _TAG_RUN.finditer(src.text):
        if m.start() > 0 and src.text[m.start() - 1] == _BLACK_FLAG:
            continue
        b.copy(src, last, m.start())
        visible = [(chr(ord(c) - 0xE0000), k) for k, c in enumerate(m.group(0), m.start()) if 0xE0020 <= ord(c) <= 0xE007E]
        if visible:
            b.add(" ", src.starts[m.start()], src.starts[m.start()])
            for ch, k in visible:
                b.add(ch, src.starts[k], src.ends[k])
            b.add(" ", src.ends[m.end() - 1], src.ends[m.end() - 1])
        last, changed = m.end(), True
    if not changed:
        return None
    b.copy(src, last, len(src.text))
    return b.build()


# --- unescaped: HTML entities, %-encoding, \x and \u escapes ---------------------------

_ESCAPE = re.compile(
    r"(?:%[0-9A-Fa-f]{2})+|(?:\\x[0-9A-Fa-f]{2})+|\\u[0-9A-Fa-f]{4}"
    r"|&#[0-9]{1,7};|&#[xX][0-9A-Fa-f]{1,6};|&[A-Za-z][A-Za-z0-9]{1,31};"
)


def _unescape_one(s: str) -> str | None:
    try:
        if s.startswith("%"):
            return bytes.fromhex(s.replace("%", "")).decode("utf-8")
        if s.startswith("\\x"):
            return bytes.fromhex(s.replace("\\x", "")).decode("utf-8")
        if s.startswith("\\u"):
            return chr(int(s[2:], 16))
    except (ValueError, UnicodeDecodeError):
        return None
    out = html.unescape(s)
    return out if out != s else None


def _unescape(src: Mapped) -> Mapped | None:
    repl = []
    for m in _ESCAPE.finditer(src.text):
        out = _unescape_one(m.group(0))
        if out is not None and out != m.group(0):
            repl.append((m.start(), m.end(), out))
    return _replace(src, repl)


# --- decoded: base64 / hex / binary ----------------------------------------------------

_BINARY = re.compile(r"(?<![01])(?:[01]{8}[ ,]?){4,}(?![01])")
_HEX = re.compile(r"(?<![0-9A-Za-z])(?:0x)?(?:[0-9A-Fa-f]{2}(?:[ :,-](?=[0-9A-Fa-f]{2}))?){8,}(?![0-9A-Za-z])")
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/=_-])")


def _readable(data: bytes) -> str | None:
    """Decoded bytes if they are mostly printable text, else None."""
    try:
        text = data.decode("utf-8").strip()
    except UnicodeDecodeError:
        return None
    if len(text) < 6:
        return None
    printable = sum(ch.isprintable() or ch in "\n\r\t" for ch in text)
    letters = sum(ch.isalpha() for ch in text)
    digits = sum(ch.isdigit() for ch in text)  # leetspeak swaps letters for digits
    if printable < 0.95 * len(text):
        return None
    if letters < 0.4 * len(text) and (letters < 0.2 * len(text) or letters + digits < 0.5 * len(text)):
        return None
    return text


def _from_binary(s: str) -> bytes | None:
    bits = re.sub(r"[ ,]", "", s)
    return bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8))


def _from_hex(s: str) -> bytes | None:
    digits = re.sub(r"[ :,-]", "", s[2:] if s[:2].lower() == "0x" else s)
    try:
        return bytes.fromhex(digits)
    except ValueError:
        return None


def _from_base64(s: str) -> bytes | None:
    body = s.rstrip("=")
    if len(body) % 4 == 1:
        return None
    alt = b"-_" if ("-" in body or "_" in body) else None
    try:
        return base64.b64decode(body + "=" * (-len(body) % 4), altchars=alt, validate=True)
    except (binascii.Error, ValueError):
        return None


def _decode_pass(src: Mapped) -> Mapped | None:
    current, changed = src, False
    for pattern, decoder in ((_BINARY, _from_binary), (_HEX, _from_hex), (_BASE64, _from_base64)):
        repl = []
        for m in pattern.finditer(current.text):
            if len(repl) >= _MAX_CANDIDATES:
                break
            if len(m.group(0)) > _MAX_RUN:
                continue
            data = decoder(m.group(0))
            text = _readable(data) if data else None
            if text:
                repl.append((m.start(), m.end(), f" {text} "))
        out = _replace(current, repl)
        if out is not None:
            current, changed = out, True
    return current if changed else None


def _decode(src: Mapped) -> Mapped | None:
    once = _decode_pass(src)
    if once is None:
        return None
    return _decode_pass(once) or once  # base64 inside base64, hex inside base64, ...


# --- spacing: letter-spaced words --------------------------------------------------------

_C = r"(?:[^\W_]|[@$])"
_SEP = r"(?:[ \t]*[-._*/|~+:,·•][ \t]*|[ \t]{1,4}|[ \t]*\r?\n[ \t]*(?:\r?\n[ \t]*)?)"
_SPACED_RUN = re.compile(rf"(?<![^\W_@$]){_C}(?:{_SEP}{_C}){{3,}}(?![^\W_@$])")
_ELEMENT = re.compile(_C)

_LEET_I = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g",
                         "@": "a", "$": "s", "|": "l", "!": "i"})
_LEET_L = {**_LEET_I, ord("1"): "l"}


def _segment(blob: str, vocabulary: frozenset[str], max_word: int) -> list[tuple[int, int]] | None:
    """Split a run of letters into vocabulary words (fewest unknown letters, then fewest
    words). Returns (start, end) pieces, or None unless known words cover at least half
    the letters (so a real word like "therapist" is not split into "the rapist")."""
    n, inf = len(blob), float("inf")
    cost = [(0, 0)] + [(inf, inf)] * n
    back = [0] * (n + 1)
    known = [False] * (n + 1)
    for i in range(1, n + 1):
        best, prev, is_word = (cost[i - 1][0] + 1, cost[i - 1][1] + 1), i - 1, False
        for length in range(1, min(max_word, i) + 1):
            if blob[i - length : i] in vocabulary:
                cand = (cost[i - length][0], cost[i - length][1] + 1)
                if cand < best:
                    best, prev, is_word = cand, i - length, True
        cost[i], back[i], known[i] = best, prev, is_word
    pieces, i = [], n
    while i > 0:
        pieces.append((back[i], i, known[i]))
        i = back[i]
    pieces.reverse()
    # Only words of 3+ letters count: "is", "a" or "me" alone must not justify a split.
    if sum(e - s for s, e, k in pieces if k and e - s >= 3) * 2 <= n:
        return None
    merged: list[list] = []
    for s, e, k in pieces:  # glue consecutive unknown letters into one piece
        if merged and not k and not merged[-1][2]:
            merged[-1][1] = e
        else:
            merged.append([s, e, k])
    return [(s, e) for s, e, _ in merged]


def _collapse_spacing(src: Mapped, vocabulary: frozenset[str], max_word: int) -> Mapped | None:
    b, last, changed = Builder(), 0, False
    for run in _SPACED_RUN.finditer(src.text):
        elems = [(run.start() + m.start(), run.start() + m.end()) for m in _ELEMENT.finditer(run.group(0))]
        seps = [src.text[elems[k][1] : elems[k + 1][0]] for k in range(len(elems) - 1)]
        intra = Counter(seps).most_common(1)[0][0]
        breaks = sorted(k for k, s in enumerate(seps) if s != intra)
        groups = [(s, e) for s, e in zip([0] + [k + 1 for k in breaks], [k + 1 for k in breaks] + [len(elems)])]
        # Whitespace word breaks ("i-g-n-o-r-e p-r-e-v", "I G N  A L L") mean the groups
        # are already words. Without them the groups are glued words ("youhaveit"),
        # split only by punctuation, so the word breaks are recovered from the vocabulary.
        has_word_breaks = any(not seps[k].strip() for k in breaks)
        words = []
        for gs, ge in groups:
            blob = "".join(src.text[i] for i, _ in elems[gs:ge]).lower().translate(_LEET_I)
            pieces = None
            if vocabulary and not has_word_breaks and len(blob) >= 4 and blob not in vocabulary:
                pieces = _segment(blob, vocabulary, max_word)
            words += [(gs + s, gs + e) for s, e in pieces] if pieces else [(gs, ge)]
        b.copy(src, last, run.start())
        for w, (s, e) in enumerate(words):
            if w:  # a space between recovered words, attributed to the separator
                gap_start, gap_end = elems[s - 1][1], elems[s][0]
                b.add(" ", src.starts[gap_start], src.ends[gap_end - 1])
            for i, _ in elems[s:e]:
                b.copy(src, i, i + 1)
        last, changed = run.end(), True
    if not changed:
        return None
    b.copy(src, last, len(src.text))
    return b.build()


# --- homoglyph and leetspeak: character swaps ---------------------------------------------

_CONFUSABLES = {
    # Cyrillic
    "а": "a", "А": "A", "В": "B", "е": "e", "Е": "E", "ё": "e", "к": "k", "К": "K", "М": "M",
    "Н": "H", "о": "o", "О": "O", "р": "p", "Р": "P", "с": "c", "С": "C", "Т": "T", "у": "y",
    "У": "Y", "х": "x", "Х": "X", "ѕ": "s", "Ѕ": "S", "і": "i", "І": "I", "ї": "i", "ј": "j",
    "Ј": "J", "ԁ": "d", "ԛ": "q", "ԝ": "w", "һ": "h", "ӏ": "l", "Ү": "Y",
    # Greek
    "α": "a", "Α": "A", "Β": "B", "ε": "e", "Ε": "E", "Ζ": "Z", "Η": "H", "ι": "i", "Ι": "I",
    "κ": "k", "Κ": "K", "Μ": "M", "ν": "v", "Ν": "N", "ο": "o", "Ο": "O", "ρ": "p", "Ρ": "P",
    "τ": "t", "Τ": "T", "υ": "u", "Υ": "Y", "χ": "x", "Χ": "X", "γ": "y",
    # Armenian and Latin extensions
    "օ": "o", "ս": "u", "ց": "g", "ɡ": "g", "ı": "i", "ȷ": "j", "ɑ": "a",
}
_HOMOGLYPH_TABLE = str.maketrans(_CONFUSABLES)
_WORD = re.compile(r"\w+")
# Whole tokens of 2-40 characters: leet words are short. Runs of 41+ base64-alphabet
# characters are data (base64, hashes, keys) and are skipped as a whole.
# Email addresses (contact@contoso.com) are matched whole and skipped too.
_LEET_TOKEN = re.compile(
    r"[\w.+-]+@[\w-]+\.[\w.-]+"
    r"|[A-Za-z0-9+/=_\-@$|!]{41,}|(?<![A-Za-z0-9@$|!])[A-Za-z0-9@$|!]{2,40}(?![A-Za-z0-9@$|!])"
)
_LEET_INSIDE = re.compile(r"[A-Za-z][01345789@$|!]+[A-Za-z]")  # pr3v10us, 1gn0r3, h@ck
_LEET_TRIGGER = set("01345789@$|")


def _is_mixed_script(token: str) -> bool:
    return any("a" <= c.lower() <= "z" for c in token) and any(c in _CONFUSABLES for c in token)


_ANY_CONFUSABLE = re.compile("[" + "".join(_CONFUSABLES) + "]")
_LEET_NEAR_LETTER = re.compile(r"[A-Za-z][01345789@$|!]|[01345789@$|][A-Za-z]")


def _homoglyph(src: Mapped) -> Mapped | None:
    if not _ANY_CONFUSABLE.search(src.text):  # quick exit for most text
        return None
    return _translate_tokens(src, _WORD, _is_mixed_script, _HOMOGLYPH_TABLE)


def _leet(src: Mapped, table: dict, vocabulary: frozenset[str]) -> Mapped | None:
    """Fold tokens whose digits sit inside the word (pr3v10us), or that fold to a word the
    rule pack knows (4ll -> all). "10am", "Q3", "Win11" and "mp3" are left alone."""

    def is_leet(token: str) -> bool:
        if len(token) > 40 or "." in token:  # a data run or an email address, skipped whole
            return False
        if not any(c.isalpha() for c in token) or not any(c in _LEET_TRIGGER for c in token):
            return False
        return bool(_LEET_INSIDE.search(token)) or token.lower().translate(table) in vocabulary

    # Keep upper case upper ("D4N" -> "DAN"): some rules are case-sensitive on purpose.
    upper_table = {k: v.upper() for k, v in table.items()}

    def fold_token(token: str) -> str:
        letters = [c for c in token if c.isalpha()]
        return token.translate(upper_table if letters and all(c.isupper() for c in letters) else table)

    if not _LEET_NEAR_LETTER.search(src.text):  # quick exit: no digit or symbol touches a letter
        return None
    return _translate_tokens(src, _LEET_TOKEN, is_leet, fold_token)


# --- whole-text ciphers --------------------------------------------------------------------

_CIPHER_GATE = 2  # a cipher view is scanned only if it reveals at least this many new words


def _rot13(src: Mapped) -> Mapped:
    return Mapped(codecs.encode(src.text, "rot13"), compute=lambda: (src.starts, src.ends))


def _reverse(src: Mapped) -> Mapped:
    return Mapped(src.text[::-1], compute=lambda: (src.starts[::-1], src.ends[::-1]))


_TOKEN = re.compile(r"\S+")


def _reverse_words(src: Mapped) -> Mapped:
    """Reverse each whitespace-separated token, punctuation included ("!enod" -> "done!").
    `src` is whitespace-collapsed, so tokens are separated by single spaces."""

    def compute() -> tuple[list[int], list[int]]:
        starts, ends = list(src.starts), list(src.ends)
        for m in _TOKEN.finditer(src.text):
            i, j = m.start(), m.end()
            starts[i:j], ends[i:j] = starts[i:j][::-1], ends[i:j][::-1]
        return starts, ends

    return Mapped(" ".join(token[::-1] for token in src.text.split(" ")), compute=compute)


# --- vocabulary for re-spacing words --------------------------------------------------------

_FUNCTION_WORDS = frozenset(
    "a an the i you your me my we us our it its is are was be to of in on and or not no all any "
    "now new this that these those what with from for as at by do say tell show give print write "
    "only just then than so if yes about above below before after everything nothing".split()
)


_REGEX_ESCAPE = re.compile(r"\\[A-Za-z]")  # \b, \s, \w ... are syntax, not words


def build_vocabulary(rules) -> frozenset[str]:
    """Words the rule pack knows: function words, every word in its `match` tests, and
    the literal words its patterns look for (from the regex source)."""
    words = set(_FUNCTION_WORDS)
    for rule in rules:
        for text in rule.tests.get("match", []):
            words.update(w for w in re.findall(r"[^\W\d_]+", text.lower()) if len(w) >= 2)
        for pattern in rule.patterns:
            words.update(re.findall(r"[^\W\d_]{3,}", _REGEX_ESCAPE.sub(" ", pattern.pattern.lower())))
    return frozenset(words)


_LONG_WORDS: dict[int, tuple[frozenset[str], frozenset[str], int]] = {}


def _vocab_info(vocabulary: frozenset[str]) -> tuple[frozenset[str], int]:
    """(vocabulary words of 4+ letters, longest word length), computed once per vocabulary."""
    cached = _LONG_WORDS.get(id(vocabulary))
    if cached is None or cached[0] is not vocabulary:
        long_words = frozenset(w for w in vocabulary if len(w) >= 4)
        cached = (vocabulary, long_words, max((len(w) for w in vocabulary), default=0))
        _LONG_WORDS[id(vocabulary)] = cached
    return cached[1], cached[2]


def _new_words(view: str, before: set[str], long_words: frozenset[str]) -> int:
    """How many distinct vocabulary words of 4+ letters the view reveals that the original
    (whose words are `before`) did not contain. A cipher view of ordinary text is
    gibberish (about 0); a deciphered payload is not. Short words are ignored: gibberish
    hits them by chance."""
    return len((set(_WORD.findall(view.lower())) - before) & long_words)


# --- assembling the views ---------------------------------------------------------------------

MAX_INPUT = 500_000  # longer inputs get the original view only (bounded cost)


def build_views(
    raw: str,
    vocabulary: frozenset[str] = _FUNCTION_WORDS,
    always_ciphers: bool = False,
) -> list[View]:
    """The original normalized text first, then every view that differs from it.

    `always_ciphers` adds rot13/reversed views without the vocabulary gate (used for
    canary tokens, which contain no injection words)."""
    folded = fold(Mapped.identity(raw))
    original = normalize_mapped(raw, folded)
    views = [View("original", original)]
    if len(raw) > MAX_INPUT:
        return views
    seen = {original.text}
    long_words, max_word = _vocab_info(vocabulary)
    original_words = set(_WORD.findall(original.text.lower()))

    def add(name: str, mapped: Mapped, gated: bool = False) -> None:
        if len(views) >= MAX_VIEWS or not mapped.text or mapped.text in seen:
            return
        if gated and _new_words(mapped.text, original_words, long_words) < _CIPHER_GATE:
            return
        seen.add(mapped.text)
        views.append(View(name, mapped))

    # Structural views work on the folded text, before whitespace is collapsed, because
    # letter spacing is read from the gaps ("i g n o r e  a l l" has wider word breaks).
    structural = [("", folded)]
    tags = _reveal_tags(folded)
    if tags is not None:
        structural.append(("tags", tags))
    for name, base in list(structural):
        out = _unescape(base)
        if out is not None:
            structural.append((_join(name, "unescaped"), out))
    for name, base in list(structural):
        out = _decode(base)
        if out is not None:
            structural.append((_join(name, "decoded"), out))
    for name, base in list(structural):
        out = _collapse_spacing(base, vocabulary, max_word)
        if out is not None:
            structural.append((_join(name, "spacing"), out))

    # Character swaps keep positions, so they run on whitespace-collapsed text directly.
    bases = [("", original)] + [(name, collapse_whitespace(m)) for name, m in structural[1:]]
    for name, base in bases:
        if name:
            add(name, base)
        homo = _homoglyph(base)
        if homo is not None:
            add(_join(name, "homoglyph"), homo)
        hname, hbase = (_join(name, "homoglyph"), homo) if homo is not None else (name, base)
        for table in (_LEET_I, _LEET_L):
            leet = _leet(hbase, table, vocabulary)
            if leet is not None:
                add(_join(hname, "leetspeak"), leet)

    for name, cipher in (("rot13", _rot13), ("reversed", _reverse), ("reversed-words", _reverse_words)):
        add(name, cipher(original), gated=not always_ciphers)
    return views
