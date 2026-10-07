"""Train the v0.3 classifier (TF-IDF + logistic regression) and export it.

Follows eval/results/classifier-protocol.md: train splits only, training rows that also
appear in an evaluation set dropped, features and C chosen by 5-fold cross-validation,
thresholds set from a false-positive budget on the out-of-fold predictions. Nothing
here reads an evaluation set except to remove duplicates of its texts.

Writes the model to src/promptbadger/data/classifier.json.gz (pure-Python inference, no
scikit-learn at runtime) and a training report to eval/results/classifier-training.md.

Usage:
    pip install -e ".[train]"
    python eval/train_classifier.py
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import math
import random
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from promptbadger import __version__  # noqa: E402
from promptbadger.classifier import MODEL_PATH, Classifier, features  # noqa: E402
from promptbadger.normalize import normalize  # noqa: E402

TRAIN_SETS = [  # (dataset, split, text column, label column, positive label or None for 0/1)
    ("deepset/prompt-injections", "train", "text", "label", None),
    ("xTRam1/safe-guard-prompt-injection", "train", "text", "label", None),
    ("jackhhao/jailbreak-classification", "train", "prompt", "type", "jailbreak"),
]
EVAL_SETS = [  # training rows whose text appears in any of these are dropped
    ("deepset/prompt-injections", "test", "text"),
    ("xTRam1/safe-guard-prompt-injection", "test", "text"),
    ("jackhhao/jailbreak-classification", "test", "prompt"),
    ("reshabhs/SPML_Chatbot_Prompt_Injection", "train", "User Prompt"),
    ("Lakera/gandalf_ignore_instructions", "train", "text"),
    ("Lakera/gandalf_ignore_instructions", "validation", "text"),
    ("Lakera/gandalf_ignore_instructions", "test", "text"),
    ("tatsu-lab/alpaca", "train", "instruction"),
]

GRID_CHAR_NGRAMS = (False, True)
GRID_C = (0.5, 2, 8)
FOLDS = 5
SEED = 0
MIN_DF = 2
MAX_FEATURES = 50_000
FPR_SUSPICIOUS = 0.01
FPR_MALICIOUS = 0.002
FLOOR_SUSPICIOUS = 0.572  # 35 x p reaches a score of 20
FLOOR_MALICIOUS = 0.834  # 60 x p reaches 50
# Cross-source check: fit on one training set, score another. Within-set CV shares
# templates between folds; this shows how much of the model is the dataset's vocabulary.
CROSS_SOURCE = ("xTRam1/safe-guard-prompt-injection", "deepset/prompt-injections")


def key(text: str) -> str:
    return normalize(text).lower()


def load_column(name: str, split: str, column: str) -> list:
    from datasets import load_dataset

    return load_dataset(name, split=split)[column]


def load_training() -> tuple[list[str], list[int], list[str], dict]:
    from datasets import load_dataset

    eval_keys: dict[str, str] = {}
    for name, split, col in EVAL_SETS:
        for text in load_column(name, split, col):
            if isinstance(text, str):
                eval_keys.setdefault(key(text), f"{name} ({split})")

    texts, labels, sources = [], [], []
    seen: dict[str, int] = {}
    stats = {"raw": Counter(), "dropped_eval": Counter(), "dropped_dup": Counter(), "duplicates": 0, "label_conflicts": 0}
    for name, split, text_col, label_col, positive in TRAIN_SETS:
        ds = load_dataset(name, split=split)
        for text, raw in zip(ds[text_col], ds[label_col]):
            stats["raw"][name] += 1
            label = int(str(raw) == positive) if positive else int(raw)
            k = key(text)
            if k in eval_keys:
                stats["dropped_eval"][eval_keys[k]] += 1
                continue
            if k in seen:
                stats["duplicates"] += 1
                stats["dropped_dup"][name] += 1
                stats["label_conflicts"] += int(labels[seen[k]] != label)
                continue
            seen[k] = len(texts)
            texts.append(text)
            labels.append(label)
            sources.append(name)
    return texts, labels, sources, stats


def vectorizer():
    from sklearn.feature_extraction.text import TfidfVectorizer

    # Features are precomputed by promptbadger.classifier.features; the analyzer passes them through.
    return TfidfVectorizer(analyzer=_passthrough, sublinear_tf=True, min_df=MIN_DF, max_features=MAX_FEATURES)


def _passthrough(feats: list[str]) -> list[str]:
    return feats


def fit(feats: list[list[str]], y, c: float):
    from sklearn.linear_model import LogisticRegression

    vec = vectorizer()
    x = vec.fit_transform(feats)
    lr = LogisticRegression(C=c, solver="liblinear", max_iter=2000)
    lr.fit(x, y)
    return vec, lr


def out_of_fold(feats: list[list[str]], y, c: float):
    import numpy as np
    from sklearn.model_selection import StratifiedKFold

    probs = np.zeros(len(y))
    for train_idx, val_idx in StratifiedKFold(FOLDS, shuffle=True, random_state=SEED).split(feats, y):
        vec, lr = fit([feats[i] for i in train_idx], y[train_idx], c)
        probs[val_idx] = lr.predict_proba(vec.transform([feats[i] for i in val_idx]))[:, 1]
    return probs


def budget_threshold(benign_probs, fpr: float) -> float:
    """Lowest 3-decimal threshold that at most `fpr` of the benign rows reach."""
    ranked = sorted(benign_probs, reverse=True)
    allowed = int(fpr * len(ranked))
    return math.floor(ranked[allowed] * 1000) / 1000 + 0.001


def at_threshold(probs, y, t: float) -> dict:
    tp = int(sum(1 for p, l in zip(probs, y) if l and p >= t))
    fp = int(sum(1 for p, l in zip(probs, y) if not l and p >= t))
    pos, neg = int(sum(y)), len(y) - int(sum(y))
    return {"recall": tp / pos, "fpr": fp / neg, "precision": tp / (tp + fp) if tp + fp else 0.0, "tp": tp, "fp": fp}


def export(vec, lr, char_ngrams: bool, thresholds: dict, meta: dict) -> dict:
    coefs = lr.coef_[0]
    vocab = {
        feat: [round(float(vec.idf_[i]), 6), round(float(coefs[i]), 6)]
        for feat, i in sorted(vec.vocabulary_.items())
    }
    return {
        "char_ngrams": char_ngrams,
        "intercept": round(float(lr.intercept_[0]), 6),
        "thresholds": thresholds,
        "vocab": vocab,
        "meta": meta,
    }


def write_model(model: dict, path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(model, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:  # mtime=0: same bytes on every run
        gz.write(raw)
    path.write_bytes(buf.getvalue())
    return len(buf.getvalue())


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--model", type=Path, default=MODEL_PATH, help="where to write the model")
    p.add_argument("--report", type=Path, default=ROOT / "eval" / "results" / "classifier-training.md")
    args = p.parse_args(argv)

    import numpy as np
    import sklearn
    from sklearn.metrics import average_precision_score

    start = time.perf_counter()
    texts, labels, sources, stats = load_training()
    y = np.array(labels)
    print(f"{len(texts)} training rows ({int(y.sum())} injection) after dropping "
          f"{sum(stats['dropped_eval'].values())} that appear in evaluation sets and {stats['duplicates']} duplicates")

    feats = {cn: [features(t, cn) for t in texts] for cn in GRID_CHAR_NGRAMS}
    grid = []
    for cn in GRID_CHAR_NGRAMS:
        for c in GRID_C:
            probs = out_of_fold(feats[cn], y, c)
            ap = average_precision_score(y, probs)
            benign = probs[y == 0]
            r1 = at_threshold(probs, y, budget_threshold(benign, FPR_SUSPICIOUS))["recall"]
            grid.append({"char_ngrams": cn, "C": c, "ap": ap, "recall_at_1pct": r1, "probs": probs})
            print(f"  char_ngrams={cn!s:5} C={c:<4} AP={ap:.4f} recall@1%FPR={r1:.3f}")
    best = max(grid, key=lambda g: g["ap"])
    cn, c, probs = best["char_ngrams"], best["C"], best["probs"]

    benign = probs[y == 0]
    raw_s, raw_m = budget_threshold(benign, FPR_SUSPICIOUS), budget_threshold(benign, FPR_MALICIOUS)
    t_m = round(max(raw_m, FLOOR_MALICIOUS), 3)
    t_s = round(min(max(raw_s, FLOOR_SUSPICIOUS), t_m), 3)
    oof_s, oof_m = at_threshold(probs, y, t_s), at_threshold(probs, y, t_m)

    fit_src, score_src = CROSS_SOURCE
    src = np.array(sources)
    tr, te = np.where(src == fit_src)[0], np.where(src == score_src)[0]
    cvec, clr = fit([feats[cn][i] for i in tr], y[tr], c)
    cprobs = clr.predict_proba(cvec.transform([feats[cn][i] for i in te]))[:, 1]
    cross = {
        "rows": len(te), "injections": int(y[te].sum()), "ap": average_precision_score(y[te], cprobs),
        "suspicious": at_threshold(cprobs, y[te], t_s), "malicious": at_threshold(cprobs, y[te], t_m),
    }
    print(f"cross-source ({fit_src} -> {score_src}): AP={cross['ap']:.3f} "
          f"recall@suspicious={cross['suspicious']['recall']:.3f}")

    vec, lr = fit(feats[cn], y, c)
    meta = {
        "promptbadger": __version__,
        "trained": time.strftime("%Y-%m-%d"),
        "scikit_learn": sklearn.__version__,
        "training_rows": len(texts),
        "training_injections": int(y.sum()),
        "training_sets": [f"{n} ({s})" for n, s, *_ in TRAIN_SETS],
        "C": c,
        "cv_average_precision": round(float(best["ap"]), 4),
        "cross_source_average_precision": round(float(cross["ap"]), 4),
        "protocol": "eval/results/classifier-protocol.md",
    }
    model = export(vec, lr, cn, {"suspicious": t_s, "malicious": t_m}, meta)
    size = write_model(model, args.model)

    # Parity: the pure-Python classifier must reproduce scikit-learn's probabilities.
    clf = Classifier.load(args.model)
    sample = random.Random(SEED).sample(range(len(texts)), min(1000, len(texts)))
    sk = lr.predict_proba(vec.transform([feats[cn][i] for i in sample]))[:, 1]
    parity = max(abs(clf.probability(texts[i]) - s) for i, s in zip(sample, sk))
    if parity > 1e-3:
        print(f"parity check failed: max |pure-Python - scikit-learn| = {parity:.2e}", file=sys.stderr)
        return 1

    words = sorted(((w, f[2:]) for f, (_, w) in model["vocab"].items() if f.startswith("w:")), reverse=True)
    report = render(stats, texts, y, sources, grid, best, raw_s, raw_m, t_s, t_m, oof_s, oof_m, cross,
                    len(model["vocab"]), size, parity, words, time.perf_counter() - start)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(report, encoding="utf-8")
    print(f"model: {args.model} ({size / 1024:.0f} KiB, {len(model['vocab'])} features), "
          f"thresholds suspicious {t_s} / malicious {t_m}, parity {parity:.1e}")
    print(f"report: {args.report}")
    return 0


def render(stats, texts, y, sources, grid, best, raw_s, raw_m, t_s, t_m, oof_s, oof_m, cross,
           n_features, size, parity, words, seconds) -> str:
    out = [
        f"# promptbadger {__version__} classifier training",
        "",
        "Protocol: [classifier-protocol.md](classifier-protocol.md). All numbers on this page are",
        "cross-validated on the training splits; held-out results are in the evaluation reports.",
        "",
        "## Data",
        "",
        "| Training set | Rows | Duplicates of earlier rows | Kept | Injections kept |",
        "|---|---|---|---|---|",
    ]
    for name, *_ in TRAIN_SETS:
        kept = [i for i, s in enumerate(sources) if s == name]
        out.append(f"| {name} (train) | {stats['raw'][name]} | {stats['dropped_dup'][name]} | {len(kept)} "
                   f"| {int(sum(y[i] for i in kept))} |")
    out.append(f"| **Total** | {sum(stats['raw'].values())} | {stats['duplicates']} | {len(texts)} | {int(y.sum())} |")
    out += ["", "Every jailbreak in the jailbreak-classification train split also appears in safe-guard",
            "(train or test): safe-guard was partly built from it. Its jailbreaks are therefore in the",
            "training data through safe-guard, or dropped because they are in safe-guard test."]
    out += ["", f"Dropped {stats['duplicates']} exact duplicates within the training data "
            f"({stats['label_conflicts']} with conflicting labels; the first label was kept) and "
            f"{sum(stats['dropped_eval'].values())} rows whose text appears in an evaluation set:", ""]
    out += [f"- {name}: {n}" for name, n in stats["dropped_eval"].most_common()] or ["- none"]
    out += [
        "",
        f"## Model selection ({FOLDS}-fold stratified CV, seed {SEED})",
        "",
        "| Character 3-5 grams | C | Average precision | Recall at 1% FPR |",
        "|---|---|---|---|",
    ]
    for g in grid:
        mark = " **(chosen)**" if g is best else ""
        out.append(f"| {'yes' if g['char_ngrams'] else 'no'} | {g['C']} | {g['ap']:.4f}{mark} | {g['recall_at_1pct']:.3f} |")
    out += [
        "",
        "## Thresholds",
        "",
        "| | From FP budget | Floor | Used | Out-of-fold recall | Out-of-fold FPR | Out-of-fold precision |",
        "|---|---|---|---|---|---|---|",
        f"| Suspicious (FPR <= {FPR_SUSPICIOUS:.1%}) | {raw_s:.3f} | {FLOOR_SUSPICIOUS} | {t_s} | "
        f"{oof_s['recall']:.3f} | {oof_s['fpr']:.4f} | {oof_s['precision']:.3f} |",
        f"| Malicious (FPR <= {FPR_MALICIOUS:.1%}) | {raw_m:.3f} | {FLOOR_MALICIOUS} | {t_m} | "
        f"{oof_m['recall']:.3f} | {oof_m['fpr']:.4f} | {oof_m['precision']:.3f} |",
        "",
        "The out-of-fold precision is at the training base rate "
        f"({y.mean():.0%} injections); real traffic has far fewer, so expect lower precision there.",
        "",
        "## Cross-source check",
        "",
        f"Fit on {CROSS_SOURCE[0]} (train), scored on {CROSS_SOURCE[1]} (train; {cross['rows']} rows, "
        f"{cross['injections']} injections), same features and C:",
        "",
        "| | Recall | FPR | Precision |",
        "|---|---|---|---|",
        f"| p >= {t_s} (suspicious) | {cross['suspicious']['recall']:.3f} | {cross['suspicious']['fpr']:.3f} "
        f"| {cross['suspicious']['precision']:.3f} |",
        f"| p >= {t_m} (malicious) | {cross['malicious']['recall']:.3f} | {cross['malicious']['fpr']:.3f} "
        f"| {cross['malicious']['precision']:.3f} |",
        "",
        f"Average precision {cross['ap']:.3f}, against {best['ap']:.3f} within-set. Most of what the model",
        "learns is each dataset's vocabulary, so the within-set numbers above overstate how it",
        "does on text from a new source. The held-out reports are the measure that counts.",
        "",
        "## Exported model",
        "",
        f"{n_features:,} features, {size / 1024:.0f} KiB gzipped. Largest difference between the "
        f"pure-Python and scikit-learn probabilities on 1,000 training rows: {parity:.1e}.",
        "",
        "Strongest word features, as a check for dataset artefacts (terms that separate the",
        "training sets rather than attacks from benign text):",
        "",
        "| Toward injection | Weight | Toward benign | Weight |",
        "|---|---|---|---|",
    ]
    top, bottom = words[:20], words[::-1][:20]
    for (wp, fp), (wn, fn) in zip(top, bottom):
        out.append(f"| {_cell(fp)} | {wp:+.2f} | {_cell(fn)} | {wn:+.2f} |")
    out += ["", f"Training took {seconds:.0f} s."]
    return "\n".join(out) + "\n"


def _cell(term: str) -> str:
    return "`" + term.replace("`", "'").replace("|", r"\|") + "`"


if __name__ == "__main__":
    sys.exit(main())
