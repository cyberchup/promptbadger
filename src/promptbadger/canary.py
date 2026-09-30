"""Canary tokens: catch system-prompt leakage in model output, whatever the wording.

Put a random marker in the system prompt (`make_canary()`), then scan the model's
responses with `Scanner.scan_output(reply, canaries=[token])`. If the marker shows up,
hidden context was exposed, no matter how the attacker phrased the request. It is
the honeytoken idea applied to LLM apps: near-zero false positives, because the
token is random and never appears in normal text.

Matching is case-insensitive and ignores separators between characters, so
"PBC 3F9A-1C0E..." or a token split with spaces still counts. Encoded forms
(base64, translated, reversed) are not caught.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Iterable

from .models import Detection

CANARY_RULE_ID = "PB-CANARY"
CANARY_TITLE = "Canary token leaked (system prompt exposure)"
CANARY_SEVERITY = "critical"  # weight 0.85: malicious on its own
CANARY_ATLAS = ["AML.T0056"]  # Extract LLM System Prompt
CANARY_OWASP = ["LLM08:2026"]  # Hidden Context Exposure

_MIN_CHARS = 12  # shorter markers could plausibly occur in normal text


def make_canary(prefix: str = "pbc") -> str:
    """Return a random marker to embed in a system prompt, e.g. 'pbc-3f9a1c0e7b2d4a68'."""
    return f"{prefix}-{secrets.token_hex(8)}"


def _pattern(canary: str) -> re.Pattern:
    chars = re.sub(r"[\W_]", "", canary)
    if len(chars) < _MIN_CHARS:
        raise ValueError(f"canary {canary!r} is too short; use make_canary() or >= {_MIN_CHARS} letters/digits")
    return re.compile(r"[\W_]*".join(map(re.escape, chars)), re.IGNORECASE)


def find_canaries(text: str, canaries: Iterable[str]) -> list[Detection]:
    """One detection per canary that appears in already-normalized `text`."""
    detections = []
    for canary in canaries:
        m = _pattern(canary).search(text)
        if m:
            detections.append(
                Detection(
                    rule_id=CANARY_RULE_ID,
                    title=CANARY_TITLE,
                    severity=CANARY_SEVERITY,
                    confidence=1.0,
                    matched_text=m.group(0)[:200],
                    span=(m.start(), m.end()),
                    atlas=list(CANARY_ATLAS),
                    owasp=list(CANARY_OWASP),
                )
            )
    return detections
