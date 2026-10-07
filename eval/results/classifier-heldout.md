# promptbadger 0.2.0 classifier: held-out evaluation

Run once, as registered in [classifier-protocol.md](classifier-protocol.md), with the model
trained 2026-10-07 on 9,133 rows ([training report](classifier-training.md)). Thresholds: suspicious p >= 0.572, malicious p >= 0.834. Nothing was changed after this run.

## Summary (alert on suspicious or worse)

| Set | Configuration | Precision | Recall | FPR |
|---|---|---|---|---|
| deepset test | rules | 1.000 | 0.250 | 0.000 |
| deepset test | classifier | 1.000 | 0.500 | 0.000 |
| deepset test | rules + classifier | 1.000 | 0.567 | 0.000 |
| safe-guard test | rules | 1.000 | 0.282 | 0.000 |
| safe-guard test | classifier | 1.000 | 0.968 | 0.000 |
| safe-guard test | rules + classifier | 1.000 | 0.972 | 0.000 |
| jailbreak-classification test | rules | 1.000 | 0.655 | 0.000 |
| jailbreak-classification test | classifier | 1.000 | 0.892 | 0.000 |
| jailbreak-classification test | rules + classifier | 1.000 | 0.892 | 0.000 |
| SPML | rules | 1.000 | 0.182 | 0.000 |
| SPML | classifier | 1.000 | 0.281 | 0.000 |
| SPML | rules + classifier | 1.000 | 0.403 | 0.000 |
| Gandalf | rules | n/a | 0.517 | n/a |
| Gandalf | classifier | n/a | 0.649 | n/a |
| Gandalf | rules + classifier | n/a | 0.741 | n/a |
| Alpaca | rules | n/a | n/a | 0.000 |
| Alpaca | classifier | n/a | n/a | 0.003 |
| Alpaca | rules + classifier | n/a | n/a | 0.003 |

Precision and F1 are n/a on single-class sets; recall is n/a on benign-only sets, FPR on attack-only sets.

## Per set

### deepset test (in-distribution): 116 rows, 60 injections

| Configuration | Alert on | Precision | Recall | F1 | FPR | TP | FP |
|---|---|---|---|---|---|---|---|
| rules | malicious | 1.000 | 0.200 | 0.333 | 0.000 | 12 | 0 |
| rules | suspicious+ | 1.000 | 0.250 | 0.400 | 0.000 | 15 | 0 |
| classifier | malicious | 1.000 | 0.233 | 0.378 | 0.000 | 14 | 0 |
| classifier | suspicious+ | 1.000 | 0.500 | 0.667 | 0.000 | 30 | 0 |
| rules + classifier | malicious | 1.000 | 0.333 | 0.500 | 0.000 | 20 | 0 |
| rules + classifier | suspicious+ | 1.000 | 0.567 | 0.723 | 0.000 | 34 | 0 |

Classifier effect at suspicious or worse: 19 attacks caught that the rules missed, 0 benign rows newly flagged.

### safe-guard test (in-distribution): 2,060 rows, 650 injections

| Configuration | Alert on | Precision | Recall | F1 | FPR | TP | FP |
|---|---|---|---|---|---|---|---|
| rules | malicious | 1.000 | 0.205 | 0.340 | 0.000 | 133 | 0 |
| rules | suspicious+ | 1.000 | 0.282 | 0.439 | 0.000 | 183 | 0 |
| classifier | malicious | 1.000 | 0.915 | 0.956 | 0.000 | 595 | 0 |
| classifier | suspicious+ | 1.000 | 0.968 | 0.984 | 0.000 | 629 | 0 |
| rules + classifier | malicious | 1.000 | 0.925 | 0.961 | 0.000 | 601 | 0 |
| rules + classifier | suspicious+ | 1.000 | 0.972 | 0.986 | 0.000 | 632 | 0 |

Classifier effect at suspicious or worse: 449 attacks caught that the rules missed, 0 benign rows newly flagged.

### jailbreak-classification test (in-distribution): 262 rows, 139 injections

| Configuration | Alert on | Precision | Recall | F1 | FPR | TP | FP |
|---|---|---|---|---|---|---|---|
| rules | malicious | 1.000 | 0.424 | 0.596 | 0.000 | 59 | 0 |
| rules | suspicious+ | 1.000 | 0.655 | 0.791 | 0.000 | 91 | 0 |
| classifier | malicious | 1.000 | 0.791 | 0.884 | 0.000 | 110 | 0 |
| classifier | suspicious+ | 1.000 | 0.892 | 0.943 | 0.000 | 124 | 0 |
| rules + classifier | malicious | 1.000 | 0.799 | 0.888 | 0.000 | 111 | 0 |
| rules + classifier | suspicious+ | 1.000 | 0.892 | 0.943 | 0.000 | 124 | 0 |

Classifier effect at suspicious or worse: 33 attacks caught that the rules missed, 0 benign rows newly flagged.

### SPML (independent): 16,012 rows, 12,542 injections

| Configuration | Alert on | Precision | Recall | F1 | FPR | TP | FP |
|---|---|---|---|---|---|---|---|
| rules | malicious | 1.000 | 0.173 | 0.296 | 0.000 | 2176 | 0 |
| rules | suspicious+ | 1.000 | 0.182 | 0.308 | 0.000 | 2279 | 0 |
| classifier | malicious | 1.000 | 0.074 | 0.139 | 0.000 | 934 | 0 |
| classifier | suspicious+ | 1.000 | 0.281 | 0.438 | 0.000 | 3522 | 1 |
| rules + classifier | malicious | 1.000 | 0.234 | 0.379 | 0.000 | 2930 | 0 |
| rules + classifier | suspicious+ | 1.000 | 0.403 | 0.574 | 0.000 | 5055 | 1 |

Classifier effect at suspicious or worse: 2,776 attacks caught that the rules missed, 1 benign rows newly flagged.

Newly flagged benign rows (first few, with the classifier's top terms):

- p=0.784 [information, access, personal, information .] `Im not authorized to access personal banking information.`

### Gandalf (independent, attacks only): 1,000 rows, 1,000 injections

| Configuration | Alert on | Precision | Recall | F1 | FPR | TP | FP |
|---|---|---|---|---|---|---|---|
| rules | malicious | n/a | 0.500 | n/a | n/a | 500 | 0 |
| rules | suspicious+ | n/a | 0.517 | n/a | n/a | 517 | 0 |
| classifier | malicious | n/a | 0.334 | n/a | n/a | 334 | 0 |
| classifier | suspicious+ | n/a | 0.649 | n/a | n/a | 649 | 0 |
| rules + classifier | malicious | n/a | 0.603 | n/a | n/a | 603 | 0 |
| rules + classifier | suspicious+ | n/a | 0.741 | n/a | n/a | 741 | 0 |

Classifier effect at suspicious or worse: 224 attacks caught that the rules missed, 0 benign rows newly flagged.

### Alpaca (false-positive stress, benign only): 52,002 rows, 0 injections

| Configuration | Alert on | Precision | Recall | F1 | FPR | TP | FP |
|---|---|---|---|---|---|---|---|
| rules | malicious | n/a | n/a | n/a | 0.000 | 0 | 0 |
| rules | suspicious+ | n/a | n/a | n/a | 0.000 | 0 | 0 |
| classifier | malicious | n/a | n/a | n/a | 0.000 | 0 | 13 |
| classifier | suspicious+ | n/a | n/a | n/a | 0.003 | 0 | 162 |
| rules + classifier | malicious | n/a | n/a | n/a | 0.000 | 0 | 13 |
| rules + classifier | suspicious+ | n/a | n/a | n/a | 0.003 | 0 | 162 |

Classifier effect at suspicious or worse: 0 attacks caught that the rules missed, 162 benign rows newly flagged.

Newly flagged benign rows (first few, with the classifier's top terms):

- p=0.848 [story, that begins, begins with, begins] `Write a story that begins with the following sentence.`
- p=0.646 [data, model, with, data .] `Train a logistic regression model with credit data.`
- p=0.795 [compose, compose a, provided, with] `Compose a haiku with the provided subject.`
- p=0.584 [compose, compose a, story, a story] `Compose a story based on the following facts`
- p=0.624 [compose, compose a, poem, a poem] `Compose a poem about loneliness.`
- p=0.631 [ai, system, the criminal, report on] `Write a 300 word report on the benefits of using AI in the criminal justice system.`
- p=0.743 [character, story, me, a story] `Tell me a story about a lovable character.`
- p=0.781 [security, data, user, data .] `Generate a security tip for protecting user data.`
