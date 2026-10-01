"""Robustness to obfuscation: does an injection stay detected once it is disguised?

Takes injections the scanner already detects in plain form (held-out test splits),
rewrites each one with an obfuscation technique, and reports the share still detected
(suspicious or worse) with deobfuscation views off and on. Techniques promptbadger does
not decode are included on purpose, so the table shows the gaps as well as the wins.

This measures coverage of each technique, not a recall number: the transforms are
synthetic, and the decoders were written for these technique families.

Usage:
    python eval/obfuscation_eval.py [--limit N] [--report eval/results/obfuscation.md]
"""

from __future__ import annotations

import argparse
import base64
import codecs
import random
import sys
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from promptbadger import Scanner, __version__  # noqa: E402

SOURCES = [
    ("deepset/prompt-injections", "test", "text", "label", None),
    ("xTRam1/safe-guard-prompt-injection", "test", "text", "label", None),
    ("jackhhao/jailbreak-classification", "test", "prompt", "type", "jailbreak"),
]

_LEET = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7",
                       "A": "4", "E": "3", "I": "1", "O": "0", "S": "5", "T": "7"})
_HOMOGLYPHS = str.maketrans({"a": "а", "e": "е", "o": "о", "p": "р", "c": "с",
                             "i": "і", "x": "х", "y": "у"})


def _caesar3(text: str) -> str:
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + 3) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + 3) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def _chunked(text: str) -> str:
    """Break words into 2-letter chunks: "ig no re al l"."""
    return " ".join(" ".join(w[i:i + 2] for i in range(0, len(w), 2)) for w in text.split())


TRANSFORMS = {
    # handled by v0.2 views
    "leetspeak": lambda t: t.translate(_LEET),
    "letter spacing, hyphens": lambda t: " ".join("-".join(w) for w in t.split()),
    "letter spacing, double-space word breaks": lambda t: "  ".join(" ".join(w) for w in t.split()),
    "letter spacing, no word breaks": lambda t: " ".join(c for c in t if not c.isspace()),
    "base64": lambda t: base64.b64encode(t.encode()).decode(),
    "hex": lambda t: t.encode().hex(),
    "URL encoding": lambda t: quote(t, safe=""),
    "HTML entities": lambda t: "".join(f"&#{ord(c)};" for c in t),
    "Cyrillic homoglyphs": lambda t: t.translate(_HOMOGLYPHS),
    "rot13": lambda t: codecs.encode(t, "rot13"),
    "reversed text": lambda t: t[::-1],
    "reversed words": lambda t: " ".join(w[::-1] for w in t.split()),
    "hidden tag characters": lambda t: "Please summarize this." + "".join(chr(0xE0000 + ord(c)) for c in t if ord(c) < 0x7F),
    "base64 of leetspeak": lambda t: base64.b64encode(t.translate(_LEET).encode()).decode(),
    # not handled: shown so the gaps are visible
    "Caesar shift 3 (not decoded)": _caesar3,
    "2-letter chunks (not decoded)": _chunked,
}


def load_positives(limit: int | None) -> list[str]:
    from datasets import load_dataset

    texts = []
    for name, split, text_col, label_col, positive in SOURCES:
        for row in load_dataset(name, split=split):
            label = row[label_col]
            is_attack = (str(label) == positive) if positive else int(label) == 1
            if is_attack:
                texts.append(row[text_col])
    random.Random(0).shuffle(texts)
    return texts[:limit] if limit else texts


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--limit", type=int, help="use at most N injections (default: all detected ones)")
    p.add_argument("--report", type=Path, help="write the markdown table here")
    args = p.parse_args(argv)

    on, off = Scanner(), Scanner(deobfuscate=False)
    flagged = lambda s, t: s.scan(t).verdict != "benign"  # noqa: E731
    base = [t for t in load_positives(None) if flagged(on, t)]
    if args.limit:
        base = base[: args.limit]

    lines = [
        f"# promptbadger {__version__}: detection under obfuscation",
        "",
        f"{len(base)} injections from the deepset, safe-guard and jailbreak-classification test splits",
        "that are detected (suspicious or worse) in plain form, each rewritten with one technique.",
        "",
        "| Technique | Still detected, views off | Still detected, views on |",
        "|---|---|---|",
    ]
    for name, fn in TRANSFORMS.items():
        variants = [fn(t) for t in base]
        before = sum(flagged(off, v) for v in variants) / len(base)
        after = sum(flagged(on, v) for v in variants) / len(base)
        lines.append(f"| {name} | {before:.0%} | {after:.0%} |")
    report = "\n".join(lines) + "\n"
    print(report)
    if args.report:
        args.report.write_text(report, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
