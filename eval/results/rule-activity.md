# promptbadger 0.3.1: rule activity

Hits per rule on every held-out and benign set, rules only, decoded views on. A cell is
`attack hits / benign hits`, with benign hits that ended in an alert (suspicious or worse)
in brackets; sets with one class show one number. Rule status is checked against these
counts as described in CONTRIBUTING.md.

| Set | Scanned with | Attacks | Benign | Alerts on attacks | Alerts on benign |
|---|---|---|---|---|---|
| deepset test | `scan()` | 60 | 56 | 15 | 0 |
| safe-guard test | `scan()` | 650 | 1,410 | 183 | 0 |
| jailbreak test | `scan()` | 139 | 123 | 91 | 0 |
| SPML | `scan()` | 12,541 | 3,470 | 2,279 | 0 |
| Gandalf | `scan()` | 1,000 | 0 | 517 | 0 |
| Alpaca | `scan()` | 0 | 52,002 | 0 | 0 |
| Dolly instructions | `scan()` | 0 | 15,011 | 0 | 2 |
| Enron ham | `scan_context()` | 0 | 16,545 | 0 | 0 |
| Dolly contexts | `scan_context()` | 0 | 4,467 | 0 | 0 |

| Rule | Status | deepset test | safe-guard test | jailbreak test | SPML | Gandalf | Alpaca | Dolly instructions | Enron ham | Dolly contexts |
|---|---|---|---|---|---|---|---|---|---|---|
| PI-001 | stable | 6 / 0 | 120 / 0 | 26 / 0 | 2096 / 0 | 484 | 0 | 0 | 0 | 0 |
| PI-002 | stable | 0 / 0 | 23 / 0 | 29 / 0 | 80 / 0 | 17 | 0 | 0 | 0 | 0 |
| PI-003 | stable | 2 / 0 | 0 / 0 | 0 / 0 | 91 / 0 | 21 | 0 | 0 | 0 | 0 |
| PI-004 | stable | 0 / 0 | 18 / 0 | 38 / 0 | 0 / 0 | 0 | 0 | 0 | 0 | 0 |
| PI-005 | stable | 0 / 0 | 26 / 0 | 19 / 0 | 17 / 0 | 2 | 0 | 2 (2) | 0 | 0 |
| PI-006 | stable | 0 / 0 | 1 / 0 | 0 / 0 | 0 / 0 | 0 | 0 | 0 | 0 | 0 |
| PI-007 | stable | 0 / 0 | 2 / 0 | 3 / 0 | 4 / 0 | 3 | 0 | 0 | 0 | 0 |
| PI-008 | test | 3 / 0 | 0 / 0 | 1 / 0 | 0 / 0 | 0 | 0 | 0 | 1 | 0 |
| PI-009 | test | 4 / 0 | 0 / 0 | 0 / 0 | 5 / 0 | 2 | 0 | 0 | 0 | 0 |
| PI-010 | stable | 2 / 0 | 24 / 0 | 43 / 0 | 0 / 0 | 0 | 0 | 0 | 0 | 0 |
| PI-011 | stable | 3 / 0 | 23 / 25 | 37 / 8 | 198 / 0 | 2 | 11 | 0 | 1 | 0 |
| PI-012 | stable | 1 / 0 | 0 / 0 | 0 / 0 | 49 / 0 | 7 | 0 | 0 | 0 | 0 |
| PI-013 | test | 4 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 | 0 | 0 | 0 | 0 |
| PI-014 | stable | 0 / 0 | 12 / 0 | 0 / 0 | 81 / 0 | 18 | 0 | 0 | 0 | 0 |
| PI-015 | stable | n/a | n/a | n/a | n/a | n/a | n/a | n/a | 0 | 0 |
| PI-016 | stable | n/a | n/a | n/a | n/a | n/a | n/a | n/a | 0 | 0 |
| PI-017 | stable | n/a | n/a | n/a | n/a | n/a | n/a | n/a | 0 | 0 |
| PI-018 | test | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 | 0 | 0 | 0 | 0 |

LLMail-Inject is not included; see [llmail-context.md](llmail-context.md) for its per-rule counts.

Scanned in 164 s.
