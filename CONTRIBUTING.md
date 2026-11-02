# Contributing to promptbadger

promptbadger is a detection project, so a change is reviewed the way a detection is:
does it catch something real, how much noise does it add, and is the number behind it
honest.

## Setup

```bash
git clone https://github.com/cyberchup/promptbadger.git
cd promptbadger
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

pytest -q                                  # unit tests
promptbadger test-rules                    # every rule's embedded match / no_match cases
python eval/run_eval.py --min-f1 0.78      # sample-set regression gate
```

CI runs those three on Python 3.10, 3.11 and 3.12. Add `.[eval]` to load Hugging Face
datasets for the evaluations below.

## False positives and missed detections

Use the issue templates. A false positive with the text and its JSON event
(`promptbadger scan --json`) is a tuning request; an attack that isn't flagged is a
coverage request. Neither needs a fix attached: a good report is a contribution.

## Writing or changing a rule

Rules are YAML files in `src/promptbadger/rules/`. `tests/test_rules.py` enforces:

- File name `pi_NNN_short_name.yml` and id `PI-NNN`, using the next unused number.
- `id`, `title`, `description`, `severity`, `confidence` (0 to 1] and
  `detection.patterns`.
- `tags.atlas` with MITRE ATLAS technique IDs, and `tags.owasp` from the OWASP LLM Top 10
  **2026** edition, written `LLMnn:2026`. Prompt injection is LLM01:2026, secret or
  sensitive-data requests LLM02:2026, system prompt leakage LLM08:2026 (Hidden Context
  Exposure). LLM07:2026 is Misinformation, not prompt leakage.
- `references` and `falsepositives`.
- At least two `tests.match` and two `tests.no_match` cases.

Conventions the tests can't check:

- **Add a hard negative.** At least one `no_match` case should be benign text a careless
  regex would hit: a security discussion quoting an attack, "enable developer mode on my
  phone", "ignore my last message".
- **Start as `status: experimental`** until the rule has been measured on held-out data.
- **Set `scope`** if the rule only makes sense in one place. The default is
  `[input, context]`; use `[context]` for text that is normal in a user's own prompt but a
  red flag inside a retrieved document or email (addressing the AI, hidden markup).
- **Pick severity for what the rule should do alone.** Weight is severity × confidence,
  and weights combine as `1 - prod(1 - w)`. A high rule at confidence 0.9 reaches
  *malicious* (50) by itself; a medium rule at 0.6 or above reaches *suspicious* (20);
  low and informational rules only count alongside something stronger.
- Patterns are Python regex, matched case-insensitively against normalized text (NFKC,
  invisible characters removed, whitespace collapsed). Use `(?-i:...)` for parts that
  must match case, such as the DAN persona versus the name Dan.
- In YAML, quote any test string containing `: ` (otherwise it parses as a mapping and
  the loader rejects it), and in single-quoted regex write a literal `'` as `''`.

## Evaluation rules

The README's numbers are only worth something if these hold:

- `eval/data/sample.jsonl` is a development set and a regression gate. Adding rows is
  welcome, including your rule's hard negatives. Deleting rows the scanner misses is not.
- These public datasets are **held out**: deepset/prompt-injections (test split),
  xTRam1/safe-guard-prompt-injection (test), jackhhao/jailbreak-classification (test),
  reshabhs/SPML_Chatbot_Prompt_Injection, Lakera/gandalf_ignore_instructions and
  microsoft/llmail-inject-challenge. Don't write or tune a rule from their rows,
  including the miss lists in `eval/results/`. A gap seen there goes on the README's
  Known gaps list; a rule that closes it has to come from other data.
- The deepset **train** split is a development set: studying its misses is fine, and
  its numbers are reported as development numbers.
- Say in the pull request where the rule's examples came from.
- Report precision, recall, F1 and false-positive rate at both operating points
  (malicious only; suspicious or worse), before and after, on the held-out sets. A
  precision drop counts as much as a recall gain.
- A new rule shouldn't alert on benign instructions. The stress test is Alpaca
  (52,002 rows):

  ```bash
  python eval/run_eval.py --hf tatsu-lab/alpaca --split train --text-col instruction --constant-label 0
  ```

The full discipline, including the classifier and judge protocols, is in
`eval/results/*-protocol.md`.

## Pull requests

- One rule or one change per pull request.
- Commit messages: imperative mood, a short summary line.
- New runtime dependencies go behind an optional extra; the core needs only PyYAML.
- README links are absolute URLs, because PyPI renders the README and can't resolve
  relative paths.
- Workflow changes: pin every action to a full commit SHA with a `# vX.Y.Z` comment,
  check out with `persist-credentials: false`, and declare `permissions:`.
  `zizmor .github/` should pass.

Security issues in promptbadger itself (ReDoS, crashes, data leaks) go through
[SECURITY.md](SECURITY.md), not the issue tracker.
