"""Measure detection quality against a labeled dataset.

Reports precision, recall, F1 and false-positive rate at two operating points:
  - alert on MALICIOUS only (high-fidelity: what you'd block on)
  - alert on SUSPICIOUS or worse (high-recall: what you'd log / review)

Usage:
    python eval/run_eval.py                                   # bundled sample set
    python eval/run_eval.py --dataset path/to/data.jsonl      # {"text":..., "label":0|1}
    python eval/run_eval.py --dataset path/to/data.csv        # columns text,label
    python eval/run_eval.py --hf deepset/prompt-injections --split test   # needs `pip install datasets`
    python eval/run_eval.py --hf deepset/prompt-injections --report eval/results/deepset-test.md
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from promptbadger import Scanner, __version__  # noqa: E402

HERE = Path(__file__).parent
DEFAULT_DATASET = HERE / "data" / "sample.jsonl"


def load_local(path: Path) -> list[tuple[str, int]]:
    if path.suffix == ".jsonl":
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    elif path.suffix == ".csv":
        with open(path, encoding="utf-8", newline="") as fh:
            rows = list(csv.DictReader(fh))
    else:
        raise SystemExit(f"unsupported dataset format: {path.suffix} (use .jsonl or .csv)")
    return [(r["text"], int(r["label"])) for r in rows]


def load_hf(name: str, split: str) -> list[tuple[str, int]]:
    try:
        from datasets import load_dataset
    except ImportError:
        raise SystemExit("Hugging Face datasets not installed: pip install -e '.[eval]'")
    ds = load_dataset(name, split=split)
    return [(row["text"], int(row["label"])) for row in ds]


def metrics(y_true: list[int], y_pred: list[int]) -> dict:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t and p)
    fp = sum(1 for t, p in zip(y_true, y_pred) if not t and p)
    tn = sum(1 for t, p in zip(y_true, y_pred) if not t and not p)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t and not p)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return dict(tp=tp, fp=fp, tn=tn, fn=fn, precision=precision, recall=recall, f1=f1, fpr=fpr)


def run(rows: list[tuple[str, int]], scanner: Scanner):
    start = time.perf_counter()
    results = [scanner.scan(text) for text, _ in rows]
    elapsed_ms = (time.perf_counter() - start) * 1000
    y_true = [label for _, label in rows]
    points = {
        "malicious": metrics(y_true, [int(r.verdict == "malicious") for r in results]),
        "suspicious+": metrics(y_true, [int(r.verdict != "benign") for r in results]),
    }
    rule_hits = Counter(d.rule_id for r in results for d in r.detections)
    rule_fp = Counter(d.rule_id for r, (_, y) in zip(results, rows) if not y for d in r.detections)
    return results, points, rule_hits, rule_fp, elapsed_ms


def render(name, rows, results, points, rule_hits, rule_fp, elapsed_ms, show_misses) -> str:
    pos = sum(y for _, y in rows)
    out = [
        f"# promptbadger {__version__} evaluation: {name}",
        "",
        f"{len(rows)} samples ({pos} injection, {len(rows) - pos} benign). "
        f"Scan time {elapsed_ms:.0f} ms total, {elapsed_ms / max(len(rows), 1):.2f} ms/sample.",
        "",
        "| Alert on | Precision | Recall | F1 | FPR | TP | FP | TN | FN |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for point, m in points.items():
        out.append(
            f"| {point} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | {m['fpr']:.3f} "
            f"| {m['tp']} | {m['fp']} | {m['tn']} | {m['fn']} |"
        )
    out += ["", "## Rule activity", "", "| Rule | Hits | Hits on benign |", "|---|---|---|"]
    for rule_id in sorted(rule_hits):
        out.append(f"| {rule_id} | {rule_hits[rule_id]} | {rule_fp.get(rule_id, 0)} |")

    if show_misses:
        fns = [(t, r) for (t, y), r in zip(rows, results) if y and r.verdict == "benign"]
        fps = [(t, r) for (t, y), r in zip(rows, results) if not y and r.verdict != "benign"]
        out += ["", f"## False negatives ({len(fns)}, verdict benign on injection)", ""]
        out += [f"- `{_clip(t)}`" for t, _ in fns[:show_misses]]
        out += ["", f"## False positives ({len(fps)}, suspicious or malicious on benign)", ""]
        out += [f"- [{r.verdict}, {','.join(d.rule_id for d in r.detections)}] `{_clip(t)}`" for t, r in fps[:show_misses]]
    return "\n".join(out) + "\n"


def _clip(text: str, n: int = 140) -> str:
    text = " ".join(text.split()).replace("`", "'")
    return text if len(text) <= n else text[: n - 3] + "..."


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = p.add_mutually_exclusive_group()
    src.add_argument("--dataset", type=Path, help=".jsonl or .csv with text,label columns")
    src.add_argument("--hf", help="Hugging Face dataset name, e.g. deepset/prompt-injections")
    p.add_argument("--split", default="test", help="split for --hf (default: test)")
    p.add_argument("--rules", help="rules directory (default: bundled)")
    p.add_argument("--misses", type=int, default=25, help="list up to N false negatives/positives (0 to hide)")
    p.add_argument("--report", type=Path, help="also write the markdown report to this file")
    p.add_argument("--min-f1", type=float, help="exit 1 if F1 at the suspicious+ point is below this (for CI)")
    args = p.parse_args(argv)

    if args.hf:
        rows, name = load_hf(args.hf, args.split), f"{args.hf} ({args.split})"
    else:
        path = args.dataset or DEFAULT_DATASET
        rows, name = load_local(path), path.name

    scanner = Scanner(rules_dir=args.rules)
    results, points, hits, fp_hits, ms = run(rows, scanner)
    report = render(name, rows, results, points, hits, fp_hits, ms, args.misses)
    print(report)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(report, encoding="utf-8")

    if args.min_f1 is not None and points["suspicious+"]["f1"] < args.min_f1:
        print(f"F1 {points['suspicious+']['f1']:.3f} below required {args.min_f1}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
