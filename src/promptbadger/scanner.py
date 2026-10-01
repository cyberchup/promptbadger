"""The scanner: run rules against input and turn detections into a verdict."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from pathlib import Path

from . import __version__
from .canary import find_canaries
from .exfil import OUTPUT_CHECKS, find_exfil, find_smuggling
from .models import (
    SEVERITY_WEIGHTS,
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

    Scoring: each detection contributes weight = severity_weight * confidence.
    Weights are combined with a noisy-OR, 1 - prod(1 - w), so independent weak
    signals add up while no amount of weak signals exceeds 100. The same idea as
    risk-based alerting in a SIEM: many low-fidelity hits on one entity can
    together cross the alert threshold.

    Three entry points, one per place text crosses into or out of the model:
    - `scan()`: user prompts, against rules scoped to "input".
    - `scan_context()`: content the model will read (retrieved documents, emails, web
      pages, tool output), against rules scoped to "context" plus hidden-Unicode checks.
      This is where indirect prompt injection (ATLAS AML.T0051.001) shows up.
    - `scan_output()`: model replies, for leaks (canary tokens, data in rendered URLs,
      hidden Unicode). `trusted_domains` are hosts the chat client may load from.
    """

    def __init__(
        self,
        rules: list[Rule] | None = None,
        rules_dir: str | Path | None = None,
        malicious_threshold: int = DEFAULT_MALICIOUS_THRESHOLD,
        suspicious_threshold: int = DEFAULT_SUSPICIOUS_THRESHOLD,
        trusted_domains: Iterable[str] = (),
    ):
        self.rules = rules if rules is not None else load_rules(rules_dir)
        self.input_rules = [r for r in self.rules if "input" in r.scope]
        self.context_rules = [r for r in self.rules if "context" in r.scope]
        if not 0 <= suspicious_threshold <= malicious_threshold <= 100:
            raise ValueError("need 0 <= suspicious_threshold <= malicious_threshold <= 100")
        self.malicious_threshold = malicious_threshold
        self.suspicious_threshold = suspicious_threshold
        self.trusted_domains = tuple(trusted_domains)

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

    def scan(self, text: str, canaries: Iterable[str] = ()) -> ScanResult:
        """Scan a prompt. (`canaries` is kept for compatibility; prefer `scan_output`.)"""
        normalized = normalize(text)
        detections = [d for d in (self.match_rule(r, normalized) for r in self.input_rules) if d]
        detections += find_canaries(normalized, canaries)
        return self._result(text, detections, "input", len(self.input_rules))

    def scan_context(self, text: str) -> ScanResult:
        """Scan content the model will read (document, email, web page, tool output)."""
        normalized = normalize(text)
        detections = [d for d in (self.match_rule(r, normalized) for r in self.context_rules) if d]
        detections += find_smuggling(text)
        return self._result(text, detections, "context", len(self.context_rules) + 1)

    def scan_output(self, text: str, canaries: Iterable[str] = ()) -> ScanResult:
        """Scan a model reply for leaks. The input rule pack is not run on output."""
        canaries = list(canaries)
        detections = find_canaries(normalize(text), canaries) + find_exfil(text, self.trusted_domains)
        return self._result(text, detections, "output", OUTPUT_CHECKS + len(canaries))

    def _result(self, text: str, detections: list[Detection], direction: str, checks: int) -> ScanResult:
        remaining = 1.0
        for d in detections:
            remaining *= 1 - SEVERITY_WEIGHTS[d.severity] / 100 * d.confidence
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
            ruleset_size=checks,
            direction=direction,
        )


_default: Scanner | None = None


def _scanner() -> Scanner:
    global _default
    if _default is None:
        _default = Scanner()
    return _default


def scan(text: str, canaries: Iterable[str] = ()) -> ScanResult:
    """Convenience function using the bundled rule pack."""
    return _scanner().scan(text, canaries)


def scan_context(text: str) -> ScanResult:
    """Convenience function: check retrieved content for indirect prompt injection."""
    return _scanner().scan_context(text)


def scan_output(text: str, canaries: Iterable[str] = ()) -> ScanResult:
    """Convenience function: check a model reply for leaks (no trusted domains)."""
    return _scanner().scan_output(text, canaries)
