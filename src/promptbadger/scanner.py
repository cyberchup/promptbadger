"""The scanner: run rules against input and turn detections into a verdict."""

from __future__ import annotations

import hashlib
from pathlib import Path

from . import __version__
from .models import (
    VERDICT_BENIGN,
    VERDICT_MALICIOUS,
    VERDICT_SUSPICIOUS,
    Detection,
    Rule,
    ScanResult,
)
from .normalize import normalize
from .rules import load_rules

DEFAULT_MALICIOUS_THRESHOLD = 50
DEFAULT_SUSPICIOUS_THRESHOLD = 20


class Scanner:
    """Scan text for prompt-injection indicators.

    Scoring: each rule that fires contributes weight = severity_weight * confidence.
    Weights are combined with a noisy-OR, 1 - prod(1 - w), so independent weak
    signals add up while no amount of weak signals exceeds 100. The same idea as
    risk-based alerting in a SIEM: many low-fidelity hits on one entity can
    together cross the alert threshold.
    """

    def __init__(
        self,
        rules: list[Rule] | None = None,
        rules_dir: str | Path | None = None,
        malicious_threshold: int = DEFAULT_MALICIOUS_THRESHOLD,
        suspicious_threshold: int = DEFAULT_SUSPICIOUS_THRESHOLD,
    ):
        self.rules = rules if rules is not None else load_rules(rules_dir)
        if not 0 <= suspicious_threshold <= malicious_threshold <= 100:
            raise ValueError("need 0 <= suspicious_threshold <= malicious_threshold <= 100")
        self.malicious_threshold = malicious_threshold
        self.suspicious_threshold = suspicious_threshold

    @staticmethod
    def match_rule(rule: Rule, text: str) -> Detection | None:
        """Return a Detection if `rule` fires on already-normalized `text`."""
        hits = [p.search(text) for p in rule.patterns]
        found = [m for m in hits if m]
        if not found or (rule.condition == "all" and len(found) != len(hits)):
            return None
        first = min(found, key=lambda m: m.start())
        return Detection(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            confidence=rule.confidence,
            matched_text=first.group(0)[:200],
            span=(first.start(), first.end()),
            atlas=rule.tags.get("atlas", []),
            owasp=rule.tags.get("owasp", []),
        )

    def scan(self, text: str) -> ScanResult:
        normalized = normalize(text)
        detections: list[Detection] = []
        remaining = 1.0
        for rule in self.rules:
            det = self.match_rule(rule, normalized)
            if det:
                detections.append(det)
                remaining *= 1 - rule.weight

        score = round((1 - remaining) * 100)
        if score >= self.malicious_threshold:
            verdict = VERDICT_MALICIOUS
        elif score >= self.suspicious_threshold:
            verdict = VERDICT_SUSPICIOUS
        else:
            verdict = VERDICT_BENIGN

        detections.sort(key=lambda d: d.span[0])
        return ScanResult(
            verdict=verdict,
            score=score,
            detections=detections,
            input_length=len(text),
            input_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            scanner_version=__version__,
            ruleset_size=len(self.rules),
        )


_default: Scanner | None = None


def scan(text: str) -> ScanResult:
    """Convenience function using the bundled rule pack."""
    global _default
    if _default is None:
        _default = Scanner()
    return _default.scan(text)
