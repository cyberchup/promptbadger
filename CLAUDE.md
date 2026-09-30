# promptbadger

Detection-as-code for LLM prompt injection. Sigma-style YAML rules mapped to MITRE ATLAS
and OWASP LLM Top 10, a scoring engine, a CLI, an evaluation harness, and Microsoft
Sentinel content. This is a public portfolio project, so code quality, honest
metrics and a readable README matter as much as detection coverage.

The owner is a detection engineer (SOC/MSSP background, Sentinel/KQL). Frame design
choices in detection-engineering terms (fidelity, FP rate, tuning, coverage mapping).

## Commands

```bash
pip install -e ".[dev]"          # add ,eval for the Hugging Face dataset loader
pytest -q                        # full suite
promptbadger test-rules          # each rule's embedded match/no_match cases
promptbadger scan "text"         # human output; --json / --jsonl for events
python eval/run_eval.py          # sample set; CI gate is --min-f1 0.78
python eval/run_eval.py --hf deepset/prompt-injections --split test --report eval/results/deepset-test.md
python demo/app.py               # Gradio demo (needs gradio installed)
```

Development is on Windows (PowerShell, venv at `.venv`). CI runs on Ubuntu, Python 3.10-3.12.

## Layout

- `src/promptbadger/scanner.py` - `Scanner.scan()`, noisy-OR scoring, verdict thresholds
- `src/promptbadger/rules.py` - YAML loading and validation (`RuleError` on bad rules)
- `src/promptbadger/normalize.py` - pre-match normalization (NFKC, invisible chars, whitespace)
- `src/promptbadger/models.py` - `Rule`, `Detection`, `ScanResult`, severity weights
- `src/promptbadger/cli.py` - `scan`, `rules`, `test-rules` subcommands; exit 0/1/2
- `src/promptbadger/rules/pi_NNN_*.yml` - the rule pack (packaged as package data)
- `eval/` - `run_eval.py`, `data/sample.jsonl` (dev set), `results/` (reports)
- `integrations/sentinel/` - analytics rule and hunting KQL for the JSONL events
- `demo/` - Gradio app for the Hugging Face Space (installs promptbadger from GitHub)

## Scoring

Rule weight = severity weight (informational 5, low 15, medium 35, high 60, critical 85)
x confidence. Fired weights combine as `1 - prod(1 - w)`, scaled to 0-100.
Defaults: malicious >= 50, suspicious >= 20. One high-confidence rule reaches malicious
on its own; low rules (PI-008, PI-011) only matter alongside stronger ones. If you change
weights or thresholds, rerun the eval and update the README numbers.

## Rule conventions (enforced by tests/test_rules.py)

- File `pi_NNN_short_name.yml`, id `PI-NNN`, unique. Next free id: PI-014.
- Required: id, title, description, severity, confidence (0-1], detection.patterns.
- Must have `tags.atlas` (e.g. AML.T0051.000 direct injection, AML.T0054 jailbreak,
  AML.T0051.001 indirect), `tags.owasp` (LLM01:2025, LLM07:2025 for prompt leakage),
  `references`, `falsepositives`, and at least 2 `tests.match` and 2 `tests.no_match`.
- Patterns are Python regex, matched case-insensitively against normalized text. Use
  `(?-i:...)` for case-sensitive parts (e.g. DAN persona vs. the name Dan).
- Quote any YAML test string containing `: ` or it parses as a dict (the loader rejects it).
- Single-quoted YAML regex: escape a literal `'` as `''`.
- Every new rule needs a hard-negative `no_match` case: benign text a careless regex
  would hit (security discussions, "enable developer mode on my phone", "ignore my last message").
- Set `status: experimental` for new rules until they've been measured on held-out data.

## Evaluation discipline

- `eval/data/sample.jsonl` was written alongside the rules. It is a dev set and a
  regression gate, not a headline metric. Adding rows is fine; don't delete misses to
  improve the score.
- Public datasets are held-out: deepset/prompt-injections test, xTRam1/safe-guard-prompt-injection
  test, jackhhao/jailbreak-classification test (`--text-col prompt --label-col type
  --positive jailbreak`). Do not tune regexes against their rows, including the misses
  listed in their reports. Report their numbers as-is in the README and `eval/results/`.
- Known gaps seen in held-out misses are listed under "Known gaps" in the README, not
  patched. A rule written to close one must come from other data and be measured on a
  held-out set it wasn't derived from; if a held-out set gets used for tuning, move it to
  the development list and say so in the README.
- The deepset **train** split is a development set: studying its misses to write rules
  is allowed (PI-012, PI-013 and the PI-002/003/008/009 extensions came from it). Report
  train numbers only as dev numbers (`eval/results/deepset-train.md`), next to the test
  numbers. Train and test share attack templates, so a fair generalisation number
  needs an independent held-out dataset.
- FP stress test: tatsu-lab/alpaca (52k benign instructions). Zero suspicious+ as of
  PI-013; any new rule that alerts there needs a look before merging.
- Known label disagreement: deepset marks benign persona prompts ("I want you to act as
  a debater") as injection. PI-011 is deliberately informational instead of chasing those.
- Report precision, recall, F1 and FPR at both operating points (malicious-only and
  suspicious-or-worse). A precision drop matters as much as a recall gain.

## Roadmap

- v0.1 (done): regex rule engine, 11 direct-injection rules, CLI, JSON events, eval, CI, Sentinel content, demo
- v0.1.x (done): PI-012 context reset, PI-013 RAG grounding override, broader DE/ES/FR/RU/BCS
  coverage; developed on deepset train. Held-out recall: deepset test 0.200 -> 0.250,
  safe-guard 0.260 -> 0.263, jailbreak-classification unchanged 0.655. FPR 0 everywhere.
- v0.2: obfuscation. Decode base64/hex/ROT13 and rescan, homoglyph mapping, leetspeak
  folding, spaced-letter collapsing. Keep original-text spans reportable. Likely home:
  `normalize.py` producing multiple candidate views that all get scanned.
- v0.3: ML classifier layer (TF-IDF + logistic regression baseline, then a small
  transformer), combined with rule scores. Train only on train splits.
- v0.4: optional LLM-as-judge for inputs the fast layers mark suspicious.
- v0.5: indirect injection (AML.T0051.001) for retrieved documents, web pages, tool output.
- Later: FastAPI service for use as a gateway sidecar; publish to PyPI (name is free).

## Style

- Python 3.10+, type hints, standard library plus PyYAML at runtime. New runtime
  dependencies go behind an optional extra.
- Keep the README honest: state limitations and known misses next to the metrics.
- Commit messages: imperative, short summary line.
