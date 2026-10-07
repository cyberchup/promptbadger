# promptbadger 0.2.0 classifier training

Protocol: [classifier-protocol.md](classifier-protocol.md). All numbers on this page are
cross-validated on the training splits; held-out results are in the evaluation reports.

## Data

| Training set | Rows | Duplicates of earlier rows | Kept | Injections kept |
|---|---|---|---|---|
| deepset/prompt-injections (train) | 546 | 0 | 546 | 203 |
| xTRam1/safe-guard-prompt-injection (train) | 8236 | 74 | 8073 | 2416 |
| jackhhao/jailbreak-classification (train) | 1044 | 412 | 514 | 0 |
| **Total** | 9826 | 486 | 9133 | 2619 |

Every jailbreak in the jailbreak-classification train split also appears in safe-guard
(train or test): safe-guard was partly built from it. Its jailbreaks are therefore in the
training data through safe-guard, or dropped because they are in safe-guard test.

Dropped 486 exact duplicates within the training data (9 with conflicting labels; the first label was kept) and 207 rows whose text appears in an evaluation set:

- xTRam1/safe-guard-prompt-injection (test): 191
- jackhhao/jailbreak-classification (test): 12
- tatsu-lab/alpaca (train): 2
- reshabhs/SPML_Chatbot_Prompt_Injection (train): 1
- deepset/prompt-injections (test): 1

## Model selection (5-fold stratified CV, seed 0)

| Character 3-5 grams | C | Average precision | Recall at 1% FPR |
|---|---|---|---|
| no | 0.5 | 0.9904 | 0.936 |
| no | 2 | 0.9945 | 0.963 |
| no | 8 | 0.9959 **(chosen)** | 0.975 |
| yes | 0.5 | 0.9917 | 0.942 |
| yes | 2 | 0.9945 | 0.965 |
| yes | 8 | 0.9954 | 0.973 |

## Thresholds

| | From FP budget | Floor | Used | Out-of-fold recall | Out-of-fold FPR | Out-of-fold precision |
|---|---|---|---|---|---|---|
| Suspicious (FPR <= 1.0%) | 0.220 | 0.572 | 0.572 | 0.929 | 0.0009 | 0.998 |
| Malicious (FPR <= 0.2%) | 0.410 | 0.834 | 0.834 | 0.863 | 0.0002 | 1.000 |

The out-of-fold precision is at the training base rate (29% injections); real traffic has far fewer, so expect lower precision there.

## Cross-source check

Fit on xTRam1/safe-guard-prompt-injection (train), scored on deepset/prompt-injections (train; 546 rows, 203 injections), same features and C:

| | Recall | FPR | Precision |
|---|---|---|---|
| p >= 0.572 (suspicious) | 0.064 | 0.000 | 1.000 |
| p >= 0.834 (malicious) | 0.025 | 0.000 | 1.000 |

Average precision 0.694, against 0.996 within-set. Most of what the model
learns is each dataset's vocabulary, so the within-set numbers above overstate how it
does on text from a new source. The held-out reports are the measure that counts.

## Exported model

50,000 features, 443 KiB gzipped. Largest difference between the pure-Python and scikit-learn probabilities on 1,000 training rows: 2.6e-07.

Strongest word features, as a check for dataset artefacts (terms that separate the
training sets rather than attacks from benign text):

| Toward injection | Weight | Toward benign | Weight |
|---|---|---|---|
| `information` | +7.79 | `?` | -9.66 |
| `prompt` | +6.60 | `:` | -4.87 |
| `ai` | +6.60 | `of` | -3.98 |
| `now` | +6.12 | `given` | -3.97 |
| `' the` | +5.65 | `input :` | -3.38 |
| `all` | +5.62 | `. input` | -3.25 |
| `instructions` | +5.60 | `of the` | -2.98 |
| `with '` | +5.31 | `input` | -2.96 |
| `sensitive` | +5.23 | `can you` | -2.91 |
| `ignore` | +5.15 | `first` | -2.77 |
| `chatgpt` | +5.01 | `what` | -2.77 |
| `confidential` | +4.89 | `task` | -2.73 |
| `me` | +4.88 | `find` | -2.73 |
| `everything` | +4.81 | `from` | -2.63 |
| `chatbot` | +4.60 | `is` | -2.57 |
| `security` | +4.48 | `explain` | -2.56 |
| `will` | +4.37 | `task :` | -2.50 |
| `data` | +4.32 | `given a` | -2.39 |
| `provide` | +4.16 | `describe` | -2.30 |
| `forget` | +4.16 | `some` | -2.27 |

Training took 76 s.
