# Kasbah Detection Coverage Scorecard

_Generated: 2026-10-08T04:02:15.860Z_

Corpus: `bench/corpus/detection-scorecard-v1.json` (v1.0.0) — 34 secret-leak cases, 23 multilingual-pii cases.

Reproduce: `node bench/detection-scorecard.js` (also `npm run bench:detection`)

## Headline

| Detector | Precision | Recall | F1 | Accuracy | TP | FP | FN | TN |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| secret-leak (`packages/api-server/src/governance/secret-leak.js`) | 100.0% | 100.0% | 100.0% | 100.0% | 20 | 0 | 0 | 14 |
| multilingual-pii (`packages/api-server/src/systems/multilingual-pii.js`) | 100.0% | 100.0% | 100.0% | 100.0% | 11 | 0 | 0 | 12 |

## Regression gate

Checked-in baseline (`BASELINE` in `bench/detection-scorecard.js`): secret-leak requires precision/recall >= 95.0%/95.0%; multilingual-pii requires >= 90.0%/95.0%. Script exits non-zero if either detector drops below its floor.

**Result this run: PASS**

## secret-leak — per category

| Category | Precision | Recall | F1 | n |
|---|---:|---:|---:|---:|
| anthropic-key | 100.0% | 100.0% | 100.0% | 1 |
| aws-access-key | 100.0% | 100.0% | 100.0% | 1 |
| azure-storage-conn | 100.0% | 100.0% | 100.0% | 1 |
| commit-message | 100.0% | 100.0% | 100.0% | 1 |
| digitalocean-token | 100.0% | 100.0% | 100.0% | 1 |
| documentation-example | 100.0% | 100.0% | 100.0% | 1 |
| example-domain | 100.0% | 100.0% | 100.0% | 1 |
| gcp-service-account | 100.0% | 100.0% | 100.0% | 1 |
| generic-env-key | 100.0% | 100.0% | 100.0% | 1 |
| generic-prose | 100.0% | 100.0% | 100.0% | 1 |
| git-sha | 100.0% | 100.0% | 100.0% | 1 |
| github-pat | 100.0% | 100.0% | 100.0% | 1 |
| gitlab-pat | 100.0% | 100.0% | 100.0% | 1 |
| google-api-key | 100.0% | 100.0% | 100.0% | 1 |
| google-oauth-token | 100.0% | 100.0% | 100.0% | 1 |
| hash-reference | 100.0% | 100.0% | 100.0% | 1 |
| lorem-ipsum | 100.0% | 100.0% | 100.0% | 1 |
| mongodb-url | 100.0% | 100.0% | 100.0% | 1 |
| npm-token | 100.0% | 100.0% | 100.0% | 1 |
| openai-key | 100.0% | 100.0% | 100.0% | 1 |
| phone-lookalike | 100.0% | 100.0% | 100.0% | 1 |
| placeholder-key | 100.0% | 100.0% | 100.0% | 1 |
| placeholder-key-2 | 100.0% | 100.0% | 100.0% | 1 |
| postgres-url | 100.0% | 100.0% | 100.0% | 1 |
| private-key-pem | 100.0% | 100.0% | 100.0% | 1 |
| redis-url | 100.0% | 100.0% | 100.0% | 1 |
| sendgrid-key | 100.0% | 100.0% | 100.0% | 1 |
| short-token | 100.0% | 100.0% | 100.0% | 1 |
| slack-token | 100.0% | 100.0% | 100.0% | 1 |
| slack-webhook | 100.0% | 100.0% | 100.0% | 1 |
| stripe-live-key | 100.0% | 100.0% | 100.0% | 1 |
| test-key-explicit | 100.0% | 100.0% | 100.0% | 1 |
| uuid | 100.0% | 100.0% | 100.0% | 1 |
| version-string | 100.0% | 100.0% | 100.0% | 1 |

## multilingual-pii — per category

| Category | Precision | Recall | F1 | n |
|---|---:|---:|---:|---:|
| aadhaar | 100.0% | 100.0% | 100.0% | 1 |
| combined-pii | 100.0% | 100.0% | 100.0% | 1 |
| credit-card | 100.0% | 100.0% | 100.0% | 1 |
| cyrillic-snils | 100.0% | 100.0% | 100.0% | 1 |
| date-of-birth | 100.0% | 100.0% | 100.0% | 1 |
| egypt-nid | 100.0% | 100.0% | 100.0% | 1 |
| email | 100.0% | 100.0% | 100.0% | 1 |
| generic-prose | 100.0% | 100.0% | 100.0% | 1 |
| git-sha-not-id | 100.0% | 100.0% | 100.0% | 1 |
| iban | 100.0% | 100.0% | 100.0% | 1 |
| invalid-card-luhn | 100.0% | 100.0% | 100.0% | 1 |
| invalid-iban-checksum | 100.0% | 100.0% | 100.0% | 1 |
| invalid-ssn-structural | 100.0% | 100.0% | 100.0% | 1 |
| invoice-number | 100.0% | 100.0% | 100.0% | 1 |
| ip-address | 100.0% | 100.0% | 100.0% | 1 |
| korean-rrn | 100.0% | 100.0% | 100.0% | 1 |
| order-date | 100.0% | 100.0% | 100.0% | 1 |
| phone-number-real | 100.0% | 100.0% | 100.0% | 1 |
| product-sku | 100.0% | 100.0% | 100.0% | 1 |
| timestamp | 100.0% | 100.0% | 100.0% | 1 |
| us-ssn | 100.0% | 100.0% | 100.0% | 1 |
| uuid-not-phone | 100.0% | 100.0% | 100.0% | 1 |
| version-string | 100.0% | 100.0% | 100.0% | 1 |

## False positives (this run)

- secret-leak: none
- multilingual-pii: none

## False negatives (this run)

- secret-leak: none
- multilingual-pii: none

## What this measures (and what it does not)

- **Measures**: precision/recall/F1 of the two live regex/checksum detectors against a hand-labeled corpus of real-shaped credentials/PII (positives) and realistic false-positive traps (negatives: example.com domains, git SHAs, UUIDs, invoice/order numbers, version strings, checksummed-invalid lookalikes).
- **Does not measure**: performance on adversarial obfuscation (e.g. base64-wrapped secrets, zero-width characters), real production traffic distribution, or detectors other than these two (secret-leak, multilingual-pii).
- **False-positive traps in the corpus** (PII-NEG-001/002/003/007/010/012): digit runs inside UUIDs, invoice numbers, order-date references, product SKUs and failed-checksum card/IBAN lookalikes. Earlier versions of the multilingual-pii `PHONE_INTL` and `DOB_ISO` patterns matched these; they are kept as negatives so a regression shows up in the tables above. Any that fail in this run are listed under "False positives (this run)".
- **One case per category**: each category score is a single pass/fail, so 100% means "no regression on this case", not a measured detection rate.
- **Corpus size**: 57 total labeled cases (34 secret-leak, 23 multilingual-pii). Small relative to production traffic — treat this as a floor/regression check, not a claim of exhaustive coverage.
