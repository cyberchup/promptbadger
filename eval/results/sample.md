# promptbadger 0.1.0 evaluation: sample.jsonl

100 samples (50 injection, 50 benign). Scan time 12 ms total, 0.12 ms/sample.

| Alert on | Precision | Recall | F1 | FPR | TP | FP | TN | FN |
|---|---|---|---|---|---|---|---|---|
| malicious | 0.957 | 0.440 | 0.603 | 0.020 | 22 | 1 | 49 | 28 |
| suspicious+ | 0.902 | 0.740 | 0.813 | 0.080 | 37 | 4 | 46 | 13 |

## Rule activity

| Rule | Hits | Hits on benign |
|---|---|---|
| PI-001 | 9 | 1 |
| PI-002 | 5 | 1 |
| PI-003 | 5 | 0 |
| PI-004 | 5 | 0 |
| PI-005 | 5 | 0 |
| PI-006 | 5 | 1 |
| PI-007 | 3 | 0 |
| PI-008 | 3 | 1 |
| PI-009 | 4 | 0 |
| PI-010 | 3 | 1 |
| PI-011 | 3 | 2 |
