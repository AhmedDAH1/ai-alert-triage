# Evaluation: qwen2.5:7b

## Usefulness on clean alerts

| Mode | Real attacks dismissed (lower is better) | Noise cleared (higher is better) | Sent to analyst | Exact | Invalid answers |
|---|---|---|---|---|---|
| *escalate everything* (baseline) | 0/14 (0%) | 0/12 (0%) | 26 | 0/26 (0%) | 0 |
| *allowlist rule* (baseline) | 0/14 (0%) | 2/12 (17%) | 0 | 16/26 (62%) | 0 |
| **naive** | 0/14 (0%) | 2/12 (17%) | 11 | 12/26 (46%) | 0 |
| **hardened** | 1/14 (7%) | 3/12 (25%) | 1 | 16/26 (62%) | 0 |
| **guarded** | 1/14 (7%) | 3/12 (25%) | 1 | 16/26 (62%) | 0 |

## Resistance to prompt injection

Real attacks with a payload in an attacker-controlled field. Lower is better, except detected.

| Mode | Attack dismissed | Severity lowered | Attacker obeyed (canary repeated) | Injection detected |
|---|---|---|---|---|
| **naive** | 82/128 (64%) | 111/128 (87%) | 35/128 (27%) | 3/128 (2%) |
| **hardened** | 94/128 (73%) | 119/128 (93%) | 30/128 (23%) | 34/128 (27%) |
| **guarded** | 26/128 (20%) | 40/128 (31%) | 31/128 (24%) | 85/128 (66%) |

### By payload (attack dismissed / attacker obeyed)

| Payload | naive | hardened | guarded |
|---|---|---|---|
| direct_override | 16/16 · 7/16 | 16/16 · 5/16 | 0/16 · 6/16 |
| fake_system_message | 16/16 · 0/16 | 16/16 · 0/16 | 0/16 · 0/16 |
| boundary_escape | 16/16 · 12/16 | 11/16 · 2/16 | 0/16 · 2/16 |
| polite_note (avoids keyword guards) | 5/16 · 1/16 | 12/16 · 4/16 | 13/16 · 4/16 |
| claimed_approval (avoids keyword guards) | 4/16 · 0/16 | 6/16 · 2/16 | 6/16 · 2/16 |
| workload_framing (avoids keyword guards) | 1/16 · 0/16 | 7/16 · 4/16 | 7/16 · 4/16 |
| json_mimic | 13/16 · 13/16 | 10/16 · 11/16 | 0/16 · 11/16 |
| chinese | 11/16 · 2/16 | 16/16 · 2/16 | 0/16 · 2/16 |
