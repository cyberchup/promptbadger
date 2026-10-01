"""Build an indirect-injection eval set from Microsoft's LLMail-Inject challenge (MIT).

LLMail-Inject asked people to hide instructions in an email so that an email assistant
would act on them: real, human-written indirect prompt injection. This script writes a
JSONL file for `run_eval.py --direction context`:

- label 1: phase-2 submissions labelled attack_attempt=True
- label 0: the challenge's own benign emails (emails_for_fp_tests.json)

Submissions labelled "Unclear" are dropped. Those labelled False (not an attack attempt,
but not clean mail either) go to a separate file with --non-attacks, all labelled 0, so
their false-positive rate can be reported on its own.

Usage:
    python eval/prepare_llmail.py --out llmail.jsonl [--cache DIR] [--non-attacks llmail-false.jsonl]
    python eval/run_eval.py --dataset llmail.jsonl --direction context
"""

from __future__ import annotations

import argparse
import json
import urllib.request
from pathlib import Path

BASE = "https://huggingface.co/datasets/microsoft/llmail-inject-challenge/resolve/main/data/"
FILES = ("labelled_unique_submissions_phase2.json", "emails_for_fp_tests.json")


def fetch(cache: Path) -> tuple[dict, list]:
    cache.mkdir(parents=True, exist_ok=True)
    for name in FILES:
        path = cache / name
        if not path.exists():
            print(f"downloading {name} ...")
            urllib.request.urlretrieve(BASE + name, path)
    subs = json.loads((cache / FILES[0]).read_text(encoding="utf-8"))
    benign = json.loads((cache / FILES[1]).read_text(encoding="utf-8"))
    return subs, benign


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", type=Path, required=True, help="JSONL to write (attacks + benign emails)")
    p.add_argument("--non-attacks", type=Path, help="also write the attack_attempt=False submissions here")
    p.add_argument("--cache", type=Path, default=Path(".cache/llmail"), help="download directory")
    args = p.parse_args(argv)

    subs, benign = fetch(args.cache)
    label = {text: str(meta["attack_attempt"]) for text, meta in subs.items()}
    attacks = [t for t, v in label.items() if v == "True"]
    with open(args.out, "w", encoding="utf-8") as fh:
        for text in attacks:
            fh.write(json.dumps({"text": text, "label": 1}) + "\n")
        for text in benign:
            fh.write(json.dumps({"text": text, "label": 0}) + "\n")
    print(f"{args.out}: {len(attacks)} attack submissions, {len(benign)} benign emails")

    if args.non_attacks:
        others = [t for t, v in label.items() if v == "False"]
        with open(args.non_attacks, "w", encoding="utf-8") as fh:
            for text in others:
                fh.write(json.dumps({"text": text, "label": 0}) + "\n")
        print(f"{args.non_attacks}: {len(others)} submissions labelled not-an-attack")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
