"""Per-rule activity on every held-out and benign set: the evidence behind rule status.

For each rule and set: hits on attacks, hits on benign text, and how many of those
benign hits ended in an alert (suspicious or worse). Rules only, decoded views on;
prompts go through scan() and documents or email through scan_context(). Only counts
are printed, never row text. The status bar these counts are checked against is in
CONTRIBUTING.md.

LLMail-Inject needs the file written by prepare_llmail.py. Without --llmail its column
is left out; eval/results/llmail-context.md has the same per-rule counts.

Usage:
    python eval/rule_activity.py [--llmail llmail.jsonl] [--report eval/results/rule-activity.md]
"""

from __future__ import annotations

import argparse
import sys
import time
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))
sys.path.insert(0, str(HERE))

from run_eval import load_hf, load_local  # noqa: E402

from promptbadger import Scanner, __version__, load_rules  # noqa: E402

# (label, direction, load_hf arguments, keep only this label or None)
SETS = [
    ("deepset test", "input", dict(name="deepset/prompt-injections", split="test"), None),
    ("safe-guard test", "input", dict(name="xTRam1/safe-guard-prompt-injection", split="test"), None),
    ("jailbreak test", "input", dict(name="jackhhao/jailbreak-classification", split="test", text_col="prompt",
                                     label_col="type", positive="jailbreak"), None),
    ("SPML", "input", dict(name="reshabhs/SPML_Chatbot_Prompt_Injection", split="train",
                           text_col="User Prompt", label_col="Prompt injection"), None),
    ("Gandalf", "input", dict(name="Lakera/gandalf_ignore_instructions", split="train+validation+test",
                              constant_label=1), None),
    ("Alpaca", "input", dict(name="tatsu-lab/alpaca", split="train", text_col="instruction", constant_label=0), None),
    ("Dolly instructions", "input", dict(name="databricks/databricks-dolly-15k", split="train",
                                         text_col="instruction", constant_label=0), None),
    ("Enron ham", "context", dict(name="SetFit/enron_spam", split="train+test"), 0),
    ("Dolly contexts", "context", dict(name="databricks/databricks-dolly-15k", split="train", text_col="context",
                                       constant_label=0), None),
]


def tally(rows: list[tuple[str, int]], scan) -> dict:
    """rule id -> [attack hits, benign hits, benign hits that alerted], plus set totals."""
    per_rule = defaultdict(lambda: [0, 0, 0])
    totals = {"attacks": 0, "benign": 0, "attack alerts": 0, "benign alerts": 0}
    for text, label in rows:
        result = scan(text)
        alerted = result.verdict != "benign"
        totals["attacks" if label else "benign"] += 1
        totals["attack alerts" if label else "benign alerts"] += alerted
        for rule_id in {d.rule_id for d in result.detections}:
            per_rule[rule_id][0 if label else 1] += 1
            per_rule[rule_id][2] += alerted and not label
    return {"rules": per_rule, "totals": totals}


def cell(counts: list[int], totals: dict) -> str:
    attacks, benign, alerts = counts
    parts = []
    if totals["attacks"]:
        parts.append(str(attacks))
    if totals["benign"]:
        parts.append(str(benign) + (f" ({alerts})" if alerts else ""))
    return " / ".join(parts)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--llmail", type=Path, help="LLMail-Inject file from prepare_llmail.py (context attacks)")
    p.add_argument("--report", type=Path, help="write the markdown report here")
    args = p.parse_args(argv)

    scanner = Scanner()
    scans = {"input": scanner.scan, "context": scanner.scan_context}
    started = time.time()
    results = {}
    for label, direction, spec, keep in SETS:
        rows = [(t, y) for t, y in load_hf(**spec) if isinstance(t, str) and t.strip() and keep in (None, y)]
        results[label] = (direction, tally(rows, scans[direction]))
        print(f"{label}: {len(rows):,} rows", file=sys.stderr, flush=True)
    if args.llmail:
        results["LLMail-Inject"] = ("context", tally(load_local(args.llmail), scanner.scan_context))

    sets = list(results)
    lines = [
        f"# promptbadger {__version__}: rule activity",
        "",
        "Hits per rule on every held-out and benign set, rules only, decoded views on. A cell is",
        "`attack hits / benign hits`, with benign hits that ended in an alert (suspicious or worse)",
        "in brackets; sets with one class show one number. Rule status is checked against these",
        "counts as described in CONTRIBUTING.md.",
        "",
        "| Set | Scanned with | Attacks | Benign | Alerts on attacks | Alerts on benign |",
        "|---|---|---|---|---|---|",
    ]
    for name in sets:
        direction, r = results[name]
        t = r["totals"]
        fn = "scan_context()" if direction == "context" else "scan()"
        lines.append(f"| {name} | `{fn}` | {t['attacks']:,} | {t['benign']:,} | {t['attack alerts']:,} "
                     f"| {t['benign alerts']:,} |")
    lines += ["", "| Rule | Status | " + " | ".join(sets) + " |", "|---|---|" + "---|" * len(sets)]
    for rule in sorted(load_rules(), key=lambda r: r.id):
        cells = []
        for name in sets:
            direction, r = results[name]
            cells.append(cell(r["rules"].get(rule.id, [0, 0, 0]), r["totals"]) if direction in rule.scope else "n/a")
        lines.append(f"| {rule.id} | {rule.status} | " + " | ".join(cells) + " |")
    if not args.llmail:
        lines += ["", "LLMail-Inject is not included; see [llmail-context.md](llmail-context.md) for its per-rule counts."]
    lines += ["", f"Scanned in {time.time() - started:.0f} s."]

    report = "\n".join(lines) + "\n"
    print(report)
    if args.report:
        args.report.write_text(report, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
