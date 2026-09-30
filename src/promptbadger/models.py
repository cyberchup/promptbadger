"""Core data types: rules, individual detections, and the overall scan result."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

# Base weight each severity contributes to the risk score (0-100) before confidence.
SEVERITY_WEIGHTS = {"informational": 5, "low": 15, "medium": 35, "high": 60, "critical": 85}

VERDICT_BENIGN = "benign"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_MALICIOUS = "malicious"

# The Sentinel analytics rule and hunting queries filter on this value.
EVENT_TYPE = "PromptInjectionScan"
DIRECTIONS = ("input", "output")


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
    ruleset_size: int  # rules (input) or leak checks (output) evaluated
    direction: str = "input"  # "input" from scan(), "output" from scan_output()

    @property
    def is_injection(self) -> bool:
        return self.verdict == VERDICT_MALICIOUS

    def to_dict(self) -> dict:
        return asdict(self)

    def to_event(
        self,
        source: str,
        input_text: str | None = None,
        *,
        direction: str | None = None,
        user: str | None = None,
        session_id: str | None = None,
    ) -> dict:
        """Shape the result as a SIEM log event: what `promptbadger scan --jsonl` emits.

        `direction` defaults to how the result was produced ("input" from `scan()`,
        "output" from `scan_output()`). `user` and `session_id` let the SIEM join on
        identity and add up weak signals across a conversation; they are only included
        when given. The raw
        input is left out unless `input_text` is given; `input_sha256` still lets you
        correlate repeated inputs without storing them.
        """
        direction = direction or self.direction
        if direction not in DIRECTIONS:
            raise ValueError(f"direction must be one of {DIRECTIONS}, not {direction!r}")
        event = {
            "TimeGenerated": datetime.now(timezone.utc).isoformat(),
            "EventType": EVENT_TYPE,
            "Source": source,
            "Direction": direction,
        }
        if user is not None:
            event["User"] = user
        if session_id is not None:
            event["SessionId"] = session_id
        event.update({k: v for k, v in self.to_dict().items() if k != "direction"})
        if input_text is not None:
            event["input"] = input_text
        return event
