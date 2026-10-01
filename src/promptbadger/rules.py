"""Load and validate YAML detection rules."""

from __future__ import annotations

import re
from importlib import resources
from pathlib import Path

import yaml

from .models import SEVERITY_WEIGHTS, Rule

REQUIRED_FIELDS = ("id", "title", "description", "severity", "confidence", "detection")
VALID_STATUS = {"experimental", "test", "stable", "deprecated"}
ID_PATTERN = re.compile(r"^PI-\d{3}$")
# Where a rule runs: "input" = user prompts (scan), "context" = content the model reads
# (retrieved documents, emails, web pages, tool output; scan_context).
VALID_SCOPES = ("input", "context")
DEFAULT_SCOPE = ["input", "context"]


class RuleError(ValueError):
    """Raised when a rule file is malformed."""


def _parse_rule(data: dict, source: str) -> Rule:
    missing = [f for f in REQUIRED_FIELDS if f not in data]
    if missing:
        raise RuleError(f"{source}: missing required field(s): {', '.join(missing)}")

    rule_id = str(data["id"])
    if not ID_PATTERN.match(rule_id):
        raise RuleError(f"{source}: id '{rule_id}' must look like PI-001")

    severity = str(data["severity"]).lower()
    if severity not in SEVERITY_WEIGHTS:
        raise RuleError(f"{source}: severity '{severity}' not in {sorted(SEVERITY_WEIGHTS)}")

    confidence = float(data["confidence"])
    if not 0 < confidence <= 1:
        raise RuleError(f"{source}: confidence must be in (0, 1]")

    status = str(data.get("status", "experimental"))
    if status not in VALID_STATUS:
        raise RuleError(f"{source}: status '{status}' not in {sorted(VALID_STATUS)}")

    detection = data["detection"] or {}
    raw_patterns = detection.get("patterns") or []
    if not raw_patterns:
        raise RuleError(f"{source}: detection.patterns must contain at least one regex")
    condition = detection.get("condition", "any")
    if condition not in ("any", "all"):
        raise RuleError(f"{source}: detection.condition must be 'any' or 'all'")

    compiled = []
    for p in raw_patterns:
        try:
            compiled.append(re.compile(p, re.IGNORECASE))
        except re.error as exc:
            raise RuleError(f"{source}: bad regex {p!r}: {exc}") from exc

    scope = data.get("scope", DEFAULT_SCOPE)
    scope = [scope] if isinstance(scope, str) else list(scope or [])
    if not scope or any(s not in VALID_SCOPES for s in scope):
        raise RuleError(f"{source}: scope must be a non-empty list from {list(VALID_SCOPES)}")

    tests = data.get("tests") or {}
    for kind, cases in tests.items():
        for case in cases or []:
            if not isinstance(case, str):
                raise RuleError(f"{source}: tests.{kind} entry {case!r} is not a string (quote it)")

    tags = data.get("tags") or {}
    return Rule(
        id=rule_id,
        title=str(data["title"]),
        description=str(data["description"]).strip(),
        severity=severity,
        confidence=confidence,
        patterns=compiled,
        condition=condition,
        status=status,
        scope=scope,
        tags={k: [str(v) for v in (vals or [])] for k, vals in tags.items()},
        references=list(data.get("references") or []),
        falsepositives=list(data.get("falsepositives") or []),
        tests={k: list(v or []) for k, v in (data.get("tests") or {}).items()},
        source_file=source,
    )


def load_rule_file(path: Path) -> Rule:
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise RuleError(f"{path}: rule file must be a YAML mapping")
    return _parse_rule(data, str(path))


def load_rules(directory: str | Path | None = None, include_deprecated: bool = False) -> list[Rule]:
    """Load every *.yml rule in `directory` (defaults to the bundled rule pack)."""
    if directory is None:
        directory = Path(str(resources.files("promptbadger") / "rules"))
    directory = Path(directory)
    rules = [load_rule_file(p) for p in sorted(directory.glob("*.yml"))]

    seen: dict[str, str] = {}
    for r in rules:
        if r.id in seen:
            raise RuleError(f"duplicate rule id {r.id} in {r.source_file} and {seen[r.id]}")
        seen[r.id] = r.source_file

    if not include_deprecated:
        rules = [r for r in rules if r.status != "deprecated"]
    return rules
