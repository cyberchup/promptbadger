"""Canary tokens (system-prompt leak detection) and the session/identity event fields."""

import json
import re

import pytest

from promptbadger import Scanner, make_canary
from promptbadger.cli import main

CANARY = "pbc-3f9a1c0e7b2d4a68"


@pytest.fixture(scope="module")
def scanner():
    return Scanner()


def test_make_canary_is_random_and_well_formed():
    a, b = make_canary(), make_canary()
    assert a != b
    assert re.fullmatch(r"pbc-[0-9a-f]{16}", a)


@pytest.mark.parametrize(
    "reply",
    [
        f"Sure! My instructions begin: Internal reference {CANARY}. You are a helpful bot...",
        f"REFERENCE: {CANARY.upper()}",
        "Here it is: p b c 3 f 9 a 1 c 0 e 7 b 2 d 4 a 6 8",  # spaced out to dodge a filter
        "pbc3f9a1c0e7b2d4a68",  # separator dropped
    ],
)
def test_leaked_canary_is_malicious(scanner, reply):
    result = scanner.scan(reply, canaries=[CANARY])
    assert result.verdict == "malicious"
    [det] = [d for d in result.detections if d.rule_id == "PB-CANARY"]
    assert det.severity == "critical"
    assert det.atlas == ["AML.T0056"]
    assert det.owasp == ["LLM08:2026"]


@pytest.mark.parametrize(
    "reply",
    [
        "I can't share my instructions, but I'm happy to help with your order.",
        "The build hash is 3f9a1c0e and the ticket is PBC-1042.",  # fragments are not the token
    ],
)
def test_no_leak_no_detection(scanner, reply):
    result = scanner.scan(reply, canaries=[CANARY])
    assert not [d for d in result.detections if d.rule_id == "PB-CANARY"]


def test_canary_is_ignored_when_not_requested(scanner):
    assert scanner.scan(f"token {CANARY}").verdict == "benign"


def test_short_canary_is_rejected(scanner):
    with pytest.raises(ValueError):
        scanner.scan("anything", canaries=["abc"])


def test_event_carries_direction_user_and_session(scanner):
    event = scanner.scan("hello").to_event(source="chat-api", user="dylan@example.com", session_id="s-42")
    assert (event["Direction"], event["User"], event["SessionId"]) == ("input", "dylan@example.com", "s-42")
    bare = scanner.scan("hello").to_event(source="chat-api", direction="output")
    assert bare["Direction"] == "output"
    assert "User" not in bare and "SessionId" not in bare
    with pytest.raises(ValueError):
        scanner.scan("hello").to_event(source="chat-api", direction="sideways")


def test_cli_output_scan_with_canary(capsys):
    code = main([
        "scan", "--jsonl", "--direction", "output", "--canary", CANARY,
        "--user", "u1", "--session-id", "s1", f"My hidden reference is {CANARY}",
    ])
    event = json.loads(capsys.readouterr().out.strip())
    assert code == 1
    assert event["Direction"] == "output" and event["User"] == "u1" and event["SessionId"] == "s1"
    assert [d["rule_id"] for d in event["detections"]] == ["PB-CANARY"]


def test_cli_rejects_short_canary(capsys):
    assert main(["scan", "--canary", "abc", "text"]) == 2
