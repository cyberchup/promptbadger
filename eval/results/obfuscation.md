# promptbadger 0.2.0: detection under obfuscation

289 injections from the deepset, safe-guard and jailbreak-classification test splits
that are detected (suspicious or worse) in plain form, each rewritten with one technique.

| Technique | Still detected, views off | Still detected, views on |
|---|---|---|
| leetspeak | 0% | 96% |
| letter spacing, hyphens | 0% | 99% |
| letter spacing, double-space word breaks | 0% | 100% |
| letter spacing, no word breaks | 0% | 98% |
| base64 | 0% | 100% |
| hex | 0% | 100% |
| URL encoding | 0% | 100% |
| HTML entities | 0% | 100% |
| Cyrillic homoglyphs | 2% | 100% |
| rot13 | 0% | 100% |
| reversed text | 0% | 100% |
| reversed words | 0% | 100% |
| hidden tag characters | 100% | 100% |
| base64 of leetspeak | 0% | 95% |
| Caesar shift 3 (not decoded) | 0% | 0% |
| 2-letter chunks (not decoded) | 0% | 0% |
