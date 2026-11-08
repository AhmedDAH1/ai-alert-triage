# Changelog

## [0.2.0] - 2026-11-08

Changes driven by the first evaluation (Qwen 2.5 7B, results/v0.1.0).

### Added
- `strict` mode: a dismissal must cite a trusted record that exists for the
  alert (asset inventory, allowlist, change ticket, helpdesk note, IP
  reputation, directory, known senders). Fooled models had justified
  dismissals with the attacker's own text.
- Verdicts include `evidence`, the context records the model relies on.
- A real attack from a host with a genuine inventory record (a compromised
  CI runner), to measure strict mode's known limit. 27 alerts, 136 attacks.

### Fixed
- Injection effects are measured against the model's own answer to the same
  alert without the payload. "Severity lowered" compared with the alert's
  original severity, but models lower severity on clean alerts too, which
  overstated the effect of the payload.

## [0.1.0] - 2026-11-08

First release: naive, hardened and guarded modes; 26 labelled alerts; 8
injection payloads; evaluation with recording and replay.
