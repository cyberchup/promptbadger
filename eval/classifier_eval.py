"""Held-out evaluation of the v0.3 classifier, as registered in eval/results/classifier-protocol.md.

Runs every evaluation set through three configurations (rules only, classifier only,
rules plus classifier) and writes one report, eval/results/classifier-heldout.md.
"Classifier only" still includes the always-on hidden-Unicode check (PB-SMUGGLE).

Usage:
    pip install -e ".[eval]"
    python eval/classifier_eval.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))
sys.path.insert(0, str(HERE))

from run_eval import _clip, load_hf, run  # noqa: E402

from promptbadger import Scanner, __version__  # noqa: E402
from promptbadger.classifier import Classifier  # noqa: E402

SETS = [  # (label, role, load_hf arguments)
    ("deepset test", "in-distribution", dict(name="deepset/prompt-injections", split="test")),
    ("safe-guard test", "in-distribution", dict(name="xTRam1/safe-guard-prompt-injection", split="test")),
    ("jailbreak-classification test", "in-distribution",
     dict(name="jackhhao/jailbreak-classification", split="test", text_col="prompt", label_col="type",
          positive="jailbreak")),
    ("SPML", "independent", dict(name="reshabhs/SPML_Chatbot_Prompt_Injection", split="train",
                                 text_col="User Prompt", label_col="Prompt injection")),
    ("Gandalf", "independent, attacks only",
     dict(name="Lakera/gandalf_ignore_instructions", split="train+validation+test", constant_label=1)),
    ("Alpaca", "false-positive stress, benign only",
     dict(name="tatsu-lab/alpaca", split="train", text_col="instruction", constant_label=0)),
]
CONFIGS = ("rules", "classifier", "rules + classifier")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--report", type=Path, default=HERE / "results" / "classifier-heldout.md")
    p.add_argument("--examples", type=int, default=8, help="list up to N classifier-added false positives per set")
    args = p.parse_args(argv)

    clf = Classifier.load()
    scanners = {
        "rules": Scanner(),
        "classifier": Scanner(rules=[], classifier=clf),
        "rules + classifier": Scanner(classifier=clf),
    }
    sections, summary = [], []
    for label, role, spec in SETS:
        rows = [(text or "", y) for text, y in load_hf(**spec)]
        pos = sum(y for _, y in rows)
        out = {cfg: run(rows, scanners[cfg]) for cfg in CONFIGS}
        print(f"{label}: {len(rows)} rows done")

        table = [
            f"### {label} ({role}): {len(rows):,} rows, {pos:,} injections",
            "",
            "| Configuration | Alert on | Precision | Recall | F1 | FPR | TP | FP |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for cfg in CONFIGS:
            for point, m in out[cfg][1].items():
                table.append(f"| {cfg} | {point} | {_m(m, 'precision', 0 < pos < len(rows))} | {_m(m, 'recall', pos > 0)} "
                             f"| {_m(m, 'f1', 0 < pos < len(rows))} | {_m(m, 'fpr', pos < len(rows))} "
                             f"| {m['tp']} | {m['fp']} |")
            s = out[cfg][1]["suspicious+"]
            summary.append((label, cfg, s, pos, len(rows)))

        rules_res, combo_res = out["rules"][0], out["rules + classifier"][0]
        added = [(t, y, c) for (t, y), r, c in zip(rows, rules_res, combo_res)
                 if r.verdict == "benign" and c.verdict != "benign"]
        caught, new_fp = [a for a in added if a[1]], [a for a in added if not a[1]]
        table += ["", f"Classifier effect at suspicious or worse: {len(caught):,} attacks caught that the rules "
                  f"missed, {len(new_fp):,} benign rows newly flagged."]
        if new_fp and args.examples:
            table += ["", "Newly flagged benign rows (first few, with the classifier's top terms):", ""]
            for text, _, res in new_fp[: args.examples]:
                ml = next(d for d in res.detections if d.rule_id == "PB-ML")
                table.append(f"- p={ml.confidence} [{ml.matched_text}] `{_clip(text)}`")
        sections.append("\n".join(table))

    report = render(clf, summary, sections)
    print(report)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(report, encoding="utf-8")
    return 0


def _m(m: dict, key: str, defined: bool) -> str:
    return f"{m[key]:.3f}" if defined else "n/a"


def render(clf, summary, sections) -> str:
    meta = clf.meta
    out = [
        f"# promptbadger {__version__} classifier: held-out evaluation",
        "",
        "Run once, as registered in [classifier-protocol.md](classifier-protocol.md), with the model",
        f"trained {meta.get('trained', '?')} on {meta.get('training_rows', '?'):,} rows "
        f"([training report](classifier-training.md)). Thresholds: suspicious p >= {clf.suspicious_p}, "
        f"malicious p >= {clf.malicious_p}. Nothing was changed after this run.",
        "",
        "## Summary (alert on suspicious or worse)",
        "",
        "| Set | Configuration | Precision | Recall | FPR |",
        "|---|---|---|---|---|",
    ]
    for label, cfg, s, pos, n in summary:
        out.append(f"| {label} | {cfg} | {_m(s, 'precision', 0 < pos < n)} | {_m(s, 'recall', pos > 0)} "
                   f"| {_m(s, 'fpr', pos < n)} |")
    out += ["", "Precision and F1 are n/a on single-class sets; recall is n/a on benign-only sets, FPR on attack-only sets.",
            "", "## Per set", ""]
    out += [s + "\n" for s in sections]
    return "\n".join(out)


if __name__ == "__main__":
    sys.exit(main())
