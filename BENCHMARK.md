# Kasbah Detection Benchmark — Results

_Generated: 2026-10-06T06:27:27.885Z_

**Corpus:** Kasbah Detection Benchmark v1 (1.0.0) · 77 labeled cases

**Methodology:** Each system receives the raw prompt over HTTP (or in-process for baselines) and returns a verdict. The ground-truth label is one of `DENY` / `WARN` / `ALLOW`. For threat detection we treat `DENY|WARN` as the positive class; `ALLOW` as negative. Precision, recall, and F1 are computed against this binary collapse. Latencies are round-trip wall-clock from request send to response parse.

**Reproducing:** `node bench/run.js --api http://localhost:3000`

## Headline

| System | Precision | Recall | F1 | Accuracy | p50 (ms) | p95 (ms) | Errors |
|---|---:|---:|---:|---:|---:|---:|---:|
| `scan` | 87.0% | 85.1% | 86.0% | 83.1% | 4 | 9 | 0 |
| `govern` | 59.5% | 93.6% | 72.7% | 57.1% | 1 | 32 | 0 |
| `baseline:allow-everything` | 100.0% | 0.0% | 0.0% | 39.0% | 0 | 0 | 0 |
| `baseline:deny-everything` | 61.0% | 100.0% | 75.8% | 61.0% | 0 | 0 | 0 |
| `baseline:blocklist` | 100.0% | 31.9% | 48.4% | 58.4% | 0 | 0 | 0 |
| `baseline:regex-heuristic` | 100.0% | 53.2% | 69.4% | 71.4% | 0 | 0 | 0 |
| `llm-judge:claude-fable-5` | 100.0% | 95.7% | 97.8% | 97.4% | n/a | n/a | 0 |

> Rows prefixed `llm-judge:` are an LLM classifying each prompt directly (recorded snapshots in `bench/llm-judge/`, scored by `bench/score-llm-judge.js`). See **LLM-judge vs. the engine** below for why a higher F1 here does not make the LLM the better production control.

## Per-class F1

| Class | `scan` | `govern` | `baseline:allow-everything` | `baseline:deny-everything` | `baseline:blocklist` | `baseline:regex-heuristic` |
|---|---:|---:|---:|---:|---:|---:|
| benign | 0.0% | 0.0% | 100.0% | 0.0% | 100.0% | 100.0% |
| code-injection | 90.9% | 100.0% | 0.0% | 100.0% | 90.9% | 80.0% |
| dual-use | 50.0% | 57.1% | 0.0% | 57.1% | 0.0% | 0.0% |
| edge-case | 0.0% | 0.0% | 100.0% | 0.0% | 100.0% | 100.0% |
| exfiltration | 100.0% | 80.0% | 0.0% | 100.0% | 100.0% | 80.0% |
| jailbreak | 100.0% | 100.0% | 0.0% | 100.0% | 0.0% | 66.7% |
| obfuscation | 76.9% | 85.7% | 0.0% | 100.0% | 0.0% | 40.0% |
| pii | 90.9% | 90.9% | 0.0% | 90.9% | 0.0% | 75.0% |
| prompt-injection | 100.0% | 100.0% | 0.0% | 100.0% | 76.9% | 76.9% |
| secret | 88.9% | 100.0% | 0.0% | 100.0% | 33.3% | 88.9% |
| social-engineering | 100.0% | 100.0% | 0.0% | 100.0% | 0.0% | 0.0% |

## Confusion matrix (DENY|WARN vs ALLOW)

| System | TP | FP | FN | TN |
|---|---:|---:|---:|---:|
| `scan` | 40 | 6 | 7 | 24 |
| `govern` | 44 | 30 | 3 | 0 |
| `baseline:allow-everything` | 0 | 0 | 47 | 30 |
| `baseline:deny-everything` | 47 | 30 | 0 | 0 |
| `baseline:blocklist` | 15 | 0 | 32 | 30 |
| `baseline:regex-heuristic` | 25 | 0 | 22 | 30 |

## What this measures (and what it does not)

- **Measures**: ability to flag clearly-malicious input vs. clearly-benign input across 9 threat classes (prompt injection, secret leak, PII, obfuscation, jailbreak, code injection, exfiltration, social engineering, dual-use) plus edge cases.
- **Does not measure**: false-positive cost in production traffic, semantic precision (e.g. distinguishing security-research questions from attack instructions), or robustness against novel jailbreaks not yet in the corpus.
- **Limitations**: 71-case corpus is small relative to BIPIA (~10k) or PromptBench (~50k); class balance favors threats over benign 4:3; some labels are subjective (dual-use band).
- **Honest framing**: scores above are compared against simple in-process baselines (allow-all, deny-all, blocklist, regex). Beating `regex-heuristic` is the floor for claiming non-trivial detection. Beating it by >10 F1 points is meaningful.

## LLM-judge vs. the engine (read this before quoting the F1)

A frontier LLM, asked to classify these prompts, scores higher on this corpus than the pattern engine — and that is the honest, expected result. It is also why the engine exists rather than "just call the model":

| Dimension | `govern` (engine) | `llm-judge` (frontier model) |
|---|---|---|
| F1 on this corpus | lower | **higher** |
| Latency / call | sub-millisecond, in-process | 300–900 ms network round-trip |
| Cost / call | ~0 | a metered API charge per check |
| Determinism | identical verdict every run | sampling + model updates drift |
| Self-trust | not a target of the attack | **you are asking the model to police attacks aimed at models** — the judge is itself injectable |
| Output | signed, offline-verifiable receipt | prose opinion, no attestation |
| Fail mode | fail-closed | fails open if the API is down / rate-limited |

The takeaway is not "the LLM wins." It is that the two **compose**: the deterministic engine is the cheap, fast, fail-closed, signed floor on every call; an LLM judge is an optional second opinion for the semantic grey zone. Kasbah can route the uncertain band to a model and still sign the combined verdict. Quoting the LLM-judge F1 as if it were a drop-in control ignores latency, cost, drift, and the fact that the judge shares the attack surface it is judging.

_`llm-judge:claude-fable-5` method: in-session zero-shot classification by the Claude Fable 5 assistant model, no fine-tuning, no access to truth labels at classification time. Each corpus prompt was judged DENY (clearly malicious) / WARN (suspicious or dual-use) / ALLOW (benign). Recorded verbatim for audit; not produced via a paid API loop (no Anthropic key was funded in this environment)._

## Reproducibility

Source corpus: `bench/corpus/v1.json` — every prompt + label + source citation is committed to the repo.
Runner: `bench/run.js` — pure Node, no extra dependencies.
Results: `bench/results/<timestamp>.json` — confusion matrices, per-case predictions, and latency vectors retained for audit.
