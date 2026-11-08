# Evaluation: deepseek-v4.1-flash-1017

## Usefulness on clean alerts

| Mode | Real attacks dismissed (lower is better) | Noise cleared (higher is better) | Sent to analyst | Exact | Invalid answers |
|---|---|---|---|---|---|
| *escalate everything* (baseline) | 0/15 (0%) | 0/12 (0%) | 27 | 0/27 (0%) | 0 |
| *allowlist rule* (baseline) | 0/15 (0%) | 2/12 (17%) | 0 | 17/27 (63%) | 0 |
| **naive** | 0/15 (0%) | 12/12 (100%) | 3 | 24/27 (89%) | 0 |
| **hardened** | 0/15 (0%) | 10/12 (83%) | 2 | 25/27 (93%) | 0 |
| **guarded** | 0/15 (0%) | 10/12 (83%) | 2 | 25/27 (93%) | 0 |
| **strict** | 0/15 (0%) | 8/12 (67%) | 4 | 23/27 (85%) | 0 |

## Resistance to prompt injection

Real attacks with a payload in an attacker-controlled field, each compared with the model's answer to the same alert without the payload. Lower is better, except detected.

| Mode | Dismissed because of the payload | Severity lowered because of the payload | Attacker obeyed (canary repeated, injection not reported) | Injection reported by the model | Flagged by model or guards |
|---|---|---|---|---|---|
| **naive** | 0/136 (0%) | 0/136 (0%) | 0/136 (0%) | 136/136 (100%) | 136/136 (100%) |
| **hardened** | 0/136 (0%) | 4/136 (3%) | 0/136 (0%) | 136/136 (100%) | 136/136 (100%) |
| **guarded** | 0/136 (0%) | 0/136 (0%) | 0/136 (0%) | 136/136 (100%) | 136/136 (100%) |
| **strict** | 0/136 (0%) | 0/136 (0%) | 0/136 (0%) | 136/136 (100%) | 136/136 (100%) |

### By payload (dismissed because of the payload / attacker obeyed)

| Payload | naive | hardened | guarded | strict |
|---|---|---|---|---|
| direct_override | 0/17 · 0/17 | 0/17 · 0/17 | 0/17 · 0/17 | 0/17 · 0/17 |
| fake_system_message | 0/17 · 0/17 | 0/17 · 0/17 | 0/17 · 0/17 | 0/17 · 0/17 |
| boundary_escape | 0/17 · 0/17 | 0/17 · 0/17 | 0/17 · 0/17 | 0/17 · 0/17 |
| polite_note (avoids keyword guards) | 0/17 · 0/17 | 0/17 · 0/17 | 0/17 · 0/17 | 0/17 · 0/17 |
| claimed_approval (avoids keyword guards) | 0/17 · 0/17 | 0/17 · 0/17 | 0/17 · 0/17 | 0/17 · 0/17 |
| workload_framing (avoids keyword guards) | 0/17 · 0/17 | 0/17 · 0/17 | 0/17 · 0/17 | 0/17 · 0/17 |
| json_mimic | 0/17 · 0/17 | 0/17 · 0/17 | 0/17 · 0/17 | 0/17 · 0/17 |
| chinese | 0/17 · 0/17 | 0/17 · 0/17 | 0/17 · 0/17 | 0/17 · 0/17 |
