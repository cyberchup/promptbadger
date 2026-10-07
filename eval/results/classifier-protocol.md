# v0.3 classifier: evaluation protocol

Written 2026-10-07, before the classifier was trained or any held-out set was scored.
Results are reported against this protocol; anything changed after a held-out run
is reported as tuned on that set, and the set moves to the development list.

## Training data

Train splits only:

| Dataset | Split | Text / label |
|---|---|---|
| deepset/prompt-injections | train (546) | `text` / `label` |
| xTRam1/safe-guard-prompt-injection | train (8,236) | `text` / `label` |
| jackhhao/jailbreak-classification | train (1,044) | `prompt` / `type == jailbreak` |

Before training, every training row whose normalized, lowercased text also appears in
an evaluation set below is dropped. Alpaca, Dolly, Enron and LLMail are not used for
training: they stay false-positive and indirect-injection test sets.

## Model selection (training data only)

- Features: word 1-2 grams, optionally plus character 3-5 grams within tokens, TF-IDF
  with sublinear term frequency and L2 normalization, computed by promptbadger's own
  pure-Python tokenizer so training and inference see identical features. Vocabulary:
  features in at least 2 training rows, at most the 50,000 most frequent.
- Logistic regression. Grid: feature set x C in {0.5, 2, 8}.
- Selection metric: average precision of out-of-fold predictions, 5-fold stratified
  cross-validation, fixed seed.

## Thresholds (from out-of-fold predictions on training benign rows)

The classifier emits one detection, `PB-ML`, with `confidence` = model probability p.
It reuses the rule scoring unchanged: severity medium (weight 35 x p) below the
malicious threshold, high (60 x p) above it.

- Suspicious threshold `t_s`: the lowest p with out-of-fold FPR <= 1%, but at least
  0.572 (where 35 x p reaches a score of 20).
- Malicious threshold `t_m`: the lowest p with out-of-fold FPR <= 0.2%, but at least
  0.834 (where 60 x p reaches 50).
- Below `t_s` nothing is emitted, so the classifier never lifts a weak rule hit on its own.

## Evaluation (no tuning)

Each set is reported for three configurations, rules only, classifier only and rules
plus classifier, at both operating points (malicious only; suspicious or worse), with
precision, recall, F1 and FPR.

| Set | Role |
|---|---|
| deepset, safe-guard, jailbreak-classification test splits | In-distribution: same sources and templates as the training splits, so optimistic for the classifier |
| reshabhs/SPML_Chatbot_Prompt_Injection (all 16,012 rows, `User Prompt` / `Prompt injection`) | Independent held-out. Only its schema had been looked at |
| Lakera/gandalf_ignore_instructions (all 1,000 rows, all attacks) | Independent, recall only. 5 test rows were printed once while choosing datasets in v0.1; never evaluated |
| tatsu-lab/alpaca (52,002 instructions, all benign) | False-positive stress test |

The classifier runs on `scan()` (user input) only. Context scans are unchanged in v0.3;
running it on documents and email needs its own measurement on LLMail, Enron and Dolly.

The classifier ships off by default (`Scanner(classifier=True)`, `--ml`) until these
numbers are in.
