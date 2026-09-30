"""Core data types: rules, individual detections, and the overall scan result."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

# Base weight each severity contributes to the risk score (0-100) before confidence.
SEVERITY_WEIGHTS = {"informational": 5, "low": 15, "medium": 35, "high": 60, "critical": 85}

VERDICT_BENIGN = "benign"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_MALICIOUS = "malicious"


@dataclass
class Rule:
    """A single detection rule loaded from YAML."""

    id: str
    title: str
    description: str
    severity: str
    confidence: float
    patterns: list[re.Pattern]
    condition: str = "any"  # "any" or "all"
    status: str = "experimental"
    tags: dict[str, list[str]] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    tests: dict[str, list[str]] = field(default_factory=dict)
    source_file: str = ""

    @property
    def weight(self) -> float:
        """This rule's contribution to the risk score, as a probability in [0, 1]."""
        return SEVERITY_WEIGHTS[self.severity] / 100 * self.confidence


@dataclass
class Detection:
    """One rule firing against one input."""

    rule_id: str
    title: str
    severity: str
    confidence: float
    matched_text: str
    span: tuple[int, int]
    atlas: list[str]
    owasp: list[str]


@dataclass
class ScanResult:
    """Outcome of scanning a single input."""

    verdict: str
    score: int
    detections: list[Detection]
    input_length: int
    input_sha256: str
    scanner_version: str
    ruleset_size: int

    @property
    def is_injection(self) -> bool:
        return self.verdict == VERDICT_MALICIOUS

    def to_dict(self) -> dict:
        return asdict(self)
