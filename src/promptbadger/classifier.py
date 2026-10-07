"""The machine-learned layer (v0.3): TF-IDF features and logistic regression.

The regex rules are precise but only catch wording they were written for. The
classifier scores how much the text as a whole resembles the injections and jailbreaks
it was trained on, and reports that as one more detection, `PB-ML`, so it feeds the
same noisy-OR score and SIEM event as the rules:

- `confidence` is the model's probability p.
- Below the suspicious threshold nothing is emitted, so the classifier never lifts a
  weak rule hit on its own. From there to the malicious threshold the detection is
  medium severity (weight 35 x p); above it, high (60 x p). Both thresholds were set
  from a false-positive budget on cross-validated training predictions and sit at or
  above the points where 35 x p reaches a score of 20 and 60 x p reaches 50.
- `matched_text` lists the terms that pushed the score up most, which is what an
  analyst needs to judge the alert.

Inference is pure Python. The model is a gzipped JSON file (vocabulary, idf weights,
coefficients, thresholds) exported by `eval/train_classifier.py`; scikit-learn is only
needed to train it. `features()` is the tokenizer used on both sides, so training and
inference see identical features.
"""

from __future__ import annotations

import gzip
import json
import math
import re
from collections import Counter
from pathlib import Path

from .models import Detection
from .normalize import normalize

RULE_ID = "PB-ML"
TITLE = "Classifier: resembles known prompt injections"
ATLAS = ["AML.T0051"]
OWASP = ["LLM01:2026"]
MODEL_PATH = Path(__file__).parent / "data" / "classifier.json.gz"

# Long inputs are scored on their first MAX_CHARS characters, which bounds scan time.
MAX_CHARS = 20_000
CHAR_NGRAMS = (3, 4, 5)
_TOKEN = re.compile(r"\w+|[^\w\s]+")


def features(text: str, char_ngrams: bool = True) -> list[str]:
    """Word unigrams and bigrams ("w:"), plus character 3-5 grams within tokens ("c:")."""
    tokens = _TOKEN.findall(normalize(text)[:MAX_CHARS].lower())
    feats = ["w:" + t for t in tokens]
    feats += [f"w:{a} {b}" for a, b in zip(tokens, tokens[1:])]
    if char_ngrams:
        for token in tokens:
            padded = f" {token} "
            for n in CHAR_NGRAMS:
                feats += ["c:" + padded[i : i + n] for i in range(len(padded) - n + 1)]
    return feats


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1 / (1 + math.exp(-z))
    e = math.exp(z)
    return e / (1 + e)


class Classifier:
    """A trained model: `probability(text)`, `explain(text)` and `detect(text)`."""

    def __init__(self, model: dict):
        self.char_ngrams = model["char_ngrams"]
        self.vocab: dict[str, list[float]] = model["vocab"]  # feature -> [idf, coefficient]
        self.intercept = model["intercept"]
        self.suspicious_p = model["thresholds"]["suspicious"]
        self.malicious_p = model["thresholds"]["malicious"]
        if not 0 < self.suspicious_p <= self.malicious_p < 1:
            raise ValueError("classifier thresholds must satisfy 0 < suspicious <= malicious < 1")
        self.meta: dict = model.get("meta", {})

    @classmethod
    def load(cls, path: str | Path | None = None) -> Classifier:
        with gzip.open(path or MODEL_PATH, "rt", encoding="utf-8") as fh:
            return cls(json.load(fh))

    def _tfidf(self, text: str) -> dict[str, float]:
        """Sublinear TF-IDF, L2-normalized over known features (as scikit-learn computes it)."""
        counts = Counter(f for f in features(text, self.char_ngrams) if f in self.vocab)
        weights = {f: (1 + math.log(c)) * self.vocab[f][0] for f, c in counts.items()}
        norm = math.sqrt(sum(w * w for w in weights.values()))
        return {f: w / norm for f, w in weights.items()} if norm else {}

    def probability(self, text: str) -> float:
        z = self.intercept + sum(w * self.vocab[f][1] for f, w in self._tfidf(text).items())
        return _sigmoid(z)

    def explain(self, text: str, k: int = 4) -> list[str]:
        """The k terms that raised the score most. Words first; character grams fill in."""
        contributions = [(w * self.vocab[f][1], f) for f, w in self._tfidf(text).items()]
        # Punctuation-only features ("?", ": ") score but mean nothing to an analyst.
        positive = sorted((c for c in contributions if c[0] > 0 and any(ch.isalnum() for ch in c[1][2:])), reverse=True)
        words = [f[2:] for _, f in positive if f.startswith("w:")]
        chars = [f"…{f[2:].strip()}…" for _, f in positive if f.startswith("c:")]
        return (words + chars)[:k]

    def detect(self, text: str) -> Detection | None:
        p = self.probability(text)
        if p < self.suspicious_p:
            return None
        return Detection(
            rule_id=RULE_ID,
            title=TITLE,
            severity="high" if p >= self.malicious_p else "medium",
            confidence=round(p, 3),
            matched_text=", ".join(self.explain(text))[:200],
            span=(0, len(text)),
            atlas=list(ATLAS),
            owasp=list(OWASP),
        )
