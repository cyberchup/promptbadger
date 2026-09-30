"""Every rule carries its own true-positive and true-negative cases, like Sigma rule tests.

These tests make sure each rule fires on its `match` examples and stays quiet on its
`no_match` examples, so a regex change that breaks a rule fails CI.
"""

import re

import pytest

from promptbadger import Scanner, load_rules
from promptbadger.normalize import normalize

RULES = load_rules()


def _cases(kind):
    for rule in RULES:
        for text in rule.tests.get(kind, []):
            yield pytest.param(rule, text, id=f"{rule.id}-{kind}-{text[:30]}")


def test_ruleset_loads():
    assert len(RULES) >= 10
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_rule_has_metadata_and_tests(rule):
    assert rule.tags.get("atlas"), f"{rule.id} has no MITRE ATLAS mapping"
    owasp = rule.tags.get("owasp") or []
    assert owasp, f"{rule.id} has no OWASP mapping"
    bad = [t for t in owasp if not re.fullmatch(r"LLM(0[1-9]|10):2026", t)]
    assert not bad, f"{rule.id} has non-2026 OWASP IDs {bad} (use the 2026 edition; LLM07:2025 is LLM08:2026)"
    assert rule.references, f"{rule.id} has no references"
    assert rule.falsepositives, f"{rule.id} should document known false positives"
    assert len(rule.tests.get("match", [])) >= 2, f"{rule.id} needs at least 2 match tests"
    assert len(rule.tests.get("no_match", [])) >= 2, f"{rule.id} needs at least 2 no_match tests"


@pytest.mark.parametrize("rule,text", list(_cases("match")))
def test_rule_matches(rule, text):
    assert Scanner.match_rule(rule, normalize(text)), f"{rule.id} should match: {text!r}"


@pytest.mark.parametrize("rule,text", list(_cases("no_match")))
def test_rule_does_not_match(rule, text):
    det = Scanner.match_rule(rule, normalize(text))
    assert det is None, f"{rule.id} should NOT match {text!r} (matched {det.matched_text!r})"
