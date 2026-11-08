# Changelog

## [0.2.3] - 2026-11-08

### Fixed
- A recording where some prompts got no answer was saved as finished, and
  the missing answers were scored as "needs investigation". The local Qwen
  run hit this: with several requests queued, Ollama took longer than the
  60-second timeout on 128 of the 136 attack prompts in hardened mode. Such a
  run now writes no report, keeps its `.partial` cassette, and running the
  same command again asks only the missing prompts.
- `--provider` now wins over `TRIAGE_MODEL` and `TRIAGE_BASE_URL` left in the
  shell. A local Qwen run was silently sent to the paid DeepSeek reseller
  because those were still set from the previous run. The command now prints
  which model and address it uses, and never sends the API key to a local
  server.
- Local models get a 10-minute timeout (cloud APIs keep 60 seconds);
  `TRIAGE_TIMEOUT` overrides both.

## [0.2.2] - 2026-11-08

### Added
- An interrupted `--record` run resumes: running the same command again
  sends only the prompts the unfinished cassette hasn't answered. A local 7B
  model needs hours for a full run, and a laptop going to sleep shouldn't
  cost all of it.

### Removed
- A Qwen report scored from an unfinished recording by the old replay, which
  counted the missing answers as "needs investigation".

## [0.2.1] - 2026-11-08

Fixes found by the first DeepSeek run. Its recorded answers were re-scored
with these fixes; no new API calls.

### Fixed
- Strict mode rejected every dismissal from models that write citations as
  text (`"asset: vuln-scan-01 (scanner)"`). Citations are now matched by
  record name, and one valid record is enough.
- "Attacker obeyed" counted a model that quoted the canary code while
  reporting the injection. Obeying now means repeating the canary without
  reporting the injection; the report also shows who flagged it (model or
  guards).
- Modes that share a prompt (hardened, guarded, strict) asked the model the
  same question three times and could get different answers even at
  temperature 0, while the cassette kept only one. Each prompt is now asked
  once and every mode's rules are applied to that same answer, so live and
  replayed numbers match and modes are compared on equal terms.
- An interrupted `--record` run left a cassette that looked finished. It now
  records to `<cassette>.partial` and renames only on completion.
- `triage replay` fails when the cassette is missing answers, instead of
  scoring them as "needs investigation".

### Changed
- Reports are named after their cassette (`results/<name>.cassette.json` →
  `results/<name>.md`), and CI checks that every cassette reproduces its
  published report exactly.

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
