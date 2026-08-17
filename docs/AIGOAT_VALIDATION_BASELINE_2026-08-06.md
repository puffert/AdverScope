# AI Goat AdverScope validation baseline

**Recorded:** 6 August 2026
**Framework source:** `6007920` (`AdverScope 0.8.0`; database schema 1; report schema 1.0)
**Purpose:** Preserve the pre-Milestone-1 AI Goat state before generic evaluator, execution, reproduction, or planning fixes.

This report is a redacted development baseline. It records project metrics and execution identifiers but does not contain target responses, expected proof values, credentials, browser state, or benchmark solution material. It is not a release-qualification pass.

## Summary

- Projects: 9
- Assessment cases: 559
- Projects without isolated oracle adjudication: C1 and C2
- Projects meeting the initial `0.95` precision and recall threshold: C5, C7, and C8, subject to sample-size review
- Projects below a precision or recall threshold: C3, C4, C6, and C9
- Retained case errors: 35, all currently attributed to C4's accumulated executions

## Per-project baseline

| Challenge | Cases | Errors | TP | TN | FP | FN | Precision | Recall | Qualification note |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| C1 Prompt Injection | 68 | 0 | 0 | 0 | 0 | 0 | unknown | unknown | No oracle adjudication |
| C2 System Prompt Extraction | 32 | 0 | 0 | 0 | 0 | 0 | unknown | unknown | No oracle adjudication |
| C3 RAG Knowledge Poisoning | 20 | 0 | 3 | 0 | 2 | 0 | 0.60 | 1.0 | False positives; evaluator and payload root causes recorded |
| C4 Context Override | 158 | 35 | 16 | 0 | 0 | 3 | 1.0 | 0.8421 | False negatives, one infrastructure adjudication, evaluator and reproduction root causes |
| C5 Multi-turn Escalation | 5 | 0 | 4 | 0 | 0 | 0 | 1.0 | 1.0 | Pass candidate; sample size remains small |
| C6 Identity Hijacking | 191 | 0 | 2 | 0 | 1 | 1 | 0.6667 | 0.6667 | Evaluator false positive and false negative |
| C7 Authoritative Context Poisoning | 15 | 0 | 1 | 0 | 0 | 0 | 1.0 | 1.0 | Pass candidate; one adjudicated positive |
| C8 Chained KB + Injection | 11 | 0 | 1 | 1 | 0 | 0 | 1.0 | 1.0 | Pass candidate; one positive and one negative control |
| C9 Guardrail Erosion | 59 | 0 | 6 | 0 | 0 | 3 | 1.0 | 0.6667 | Three evaluator false negatives |

## Retained execution identifiers

| Challenge | Assessment runs | Testing Tool runs |
|---|---|---|
| C1 | `run_a7acf49f87eb`, `run_261c2eb0cdaf`, `run_6d9bde12241a` | none |
| C2 | `run_7feec45bf30c` | none |
| C3 | `run_30ab1b9d57b8`, `run_2ebf12b9131d`, `run_46e71cfca6af` | `toolrun_db42f239271e`, `toolrun_9e40719b14f0`, `toolrun_b5151a1e6b29` |
| C4 | `run_ec7fbd6a399f`, `run_dd32691e44d4`, `run_c98edc1d4508`, `run_b52a84462c42`, `run_36ee1426184c`, `run_acf3d1026002`, `run_9db5775898e3` | none |
| C5 | `run_f7c1ea538044` | none |
| C6 | `run_d251ac0cd6a2`, `run_bba86f4ddd44`, `run_d55393cf9c84`, `run_e24cd7f8b302`, `run_8ba45898c489` | `toolrun_d122c8b0ba5c` |
| C7 | `run_ec3d310df1b1` | `toolrun_5d20cf3d0ff0` |
| C8 | `run_dda791be75db` | `toolrun_5766d5487aac` |
| C9 | `run_05e4872df158`, `run_467ac86a7bbc` | none |

## Interpretation

The campaign proves that AdverScope can execute substantial chatbot, conversation, RAG, identity, and Testing Tool workloads and retain findings. It does not yet establish professionally reliable AI Goat detection.

The next qualification work must:

1. add isolated C1 and C2 oracle adjudications;
2. eliminate generic false-positive causes in C3 and C6;
3. correct generic evaluator/reproduction misses in C4, C6, and C9;
4. classify C4's execution errors by target, transport, evaluator, reproduction, and framework cause;
5. add sufficient secure controls and independent targets before accepting small-sample perfect scores;
6. rerun every corrected challenge through the normal AdverScope GUI without changing AI Goat or hardcoding its solutions.

The retained machine-readable AI Goat records are stored under [`validation/aigoat/`](../validation/aigoat/).
