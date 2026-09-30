"""Command-line interface.

Examples:
    promptbadger scan "Ignore all previous instructions"
    echo "some text" | promptbadger scan -
    promptbadger scan --file prompts.txt --jsonl          # one input per line, JSON Lines out
    promptbadger scan --file replies.txt --direction output --canary pbc-3f9a1c0e7b2d4a68 --jsonl
    promptbadger rules                                      # list the loaded rule pack
    promptbadger test-rules                                 # run every rule's embedded tests
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .normalize import normalize
from .rules import RuleError, load_rules
from .scanner import DEFAULT_MALICIOUS_THRESHOLD, DEFAULT_SUSPICIOUS_THRESHOLD, Scanner

EXIT_BENIGN, EXIT_DETECTED, EXIT_ERROR = 0, 1, 2
_COLORS = {"benign": "\033[32m", "suspicious": "\033[33m", "malicious": "\033[31m"}
_RESET = "\033[0m"


def _print_human(result, text: str, color: bool) -> None:
    c = _COLORS[result.verdict] if color else ""
    r = _RESET if color else ""
    preview = text if len(text) <= 80 else text[:77] + "..."
    print(f"{c}{result.verdict.upper()}{r}  score={result.score}  {preview!r}")
    for d in result.detections:
        tags = ", ".join(d.atlas + d.owasp)
        print(f"  - {d.rule_id} [{d.severity}] {d.title}  ({tags})")
        print(f"      matched: {d.matched_text!r}")


def _cmd_scan(args) -> int:
    scanner = Scanner(
        rules_dir=args.rules,
        malicious_threshold=args.malicious_threshold,
        suspicious_threshold=args.suspicious_threshold,
    )

    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            inputs = [(f"{args.file}:{i}", line.rstrip("\n")) for i, line in enumerate(fh, 1) if line.strip()]
    elif args.text == "-" or args.text is None:
        inputs = [("stdin", sys.stdin.read())]
    else:
        inputs = [("argv", args.text)]

    worst = EXIT_BENIGN
    fail_on = {"malicious"} if args.fail_on == "malicious" else {"malicious", "suspicious"}
    color = sys.stdout.isatty() and not args.no_color

    for source, text in inputs:
        result = scanner.scan(text, canaries=args.canary or ())
        if result.verdict in fail_on:
            worst = EXIT_DETECTED
        if args.json or args.jsonl:
            event = result.to_event(
                source,
                text if args.include_input else None,
                direction=args.direction,
                user=args.user,
                session_id=args.session_id,
            )
            print(json.dumps(event, indent=None if args.jsonl else 2))
        else:
            _print_human(result, text, color)
    return worst


def _cmd_rules(args) -> int:
    rules = load_rules(args.rules, include_deprecated=True)
    for r in rules:
        print(f"{r.id}  {r.severity:<8} conf={r.confidence:<4} {r.status:<12} {r.title}")
        print(f"        ATLAS: {', '.join(r.tags.get('atlas', []))}   OWASP: {', '.join(r.tags.get('owasp', []))}")
    print(f"\n{len(rules)} rules")
    return EXIT_BENIGN


def _cmd_test_rules(args) -> int:
    rules = load_rules(args.rules)
    failures = 0
    total = 0
    for rule in rules:
        for kind, expect in (("match", True), ("no_match", False)):
            for text in rule.tests.get(kind, []):
                total += 1
                fired = Scanner.match_rule(rule, normalize(text)) is not None
                if fired != expect:
                    failures += 1
                    print(f"FAIL {rule.id} {kind}: {text!r}")
    print(f"{total - failures}/{total} rule tests passed across {len(rules)} rules")
    return EXIT_DETECTED if failures else EXIT_BENIGN


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="promptbadger", description="Detect prompt injection in text.")
    p.add_argument("--version", action="version", version=f"promptbadger {__version__}")
    p.add_argument("--rules", help="directory of YAML rules (default: bundled rule pack)")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan text, a file, or stdin")
    s.add_argument("text", nargs="?", help="text to scan, or '-' for stdin")
    s.add_argument("-f", "--file", help="scan each non-empty line of a file")
    out = s.add_mutually_exclusive_group()
    out.add_argument("--json", action="store_true", help="pretty JSON output")
    out.add_argument("--jsonl", action="store_true", help="one JSON event per line (for log shipping)")
    s.add_argument("--include-input", action="store_true", help="include raw input text in JSON events")
    s.add_argument("--canary", action="append", metavar="TOKEN",
                   help="flag this canary token if it appears (repeatable); use when scanning model output")
    s.add_argument("--direction", choices=["input", "output"], default="input",
                   help="what is being scanned, recorded in JSON events (default: input)")
    s.add_argument("--user", help="user identity to record in JSON events")
    s.add_argument("--session-id", help="conversation/session ID to record in JSON events")
    s.add_argument("--malicious-threshold", type=int, default=DEFAULT_MALICIOUS_THRESHOLD)
    s.add_argument("--suspicious-threshold", type=int, default=DEFAULT_SUSPICIOUS_THRESHOLD)
    s.add_argument("--fail-on", choices=["malicious", "suspicious"], default="malicious",
                   help="verdict that makes the exit code 1 (default: malicious)")
    s.add_argument("--no-color", action="store_true")
    s.set_defaults(func=_cmd_scan)

    r = sub.add_parser("rules", help="list loaded rules")
    r.set_defaults(func=_cmd_rules)

    t = sub.add_parser("test-rules", help="run each rule's embedded match/no_match tests")
    t.set_defaults(func=_cmd_test_rules)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (RuleError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
