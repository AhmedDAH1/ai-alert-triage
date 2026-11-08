# AI Alert Triage

[![CI](https://github.com/AhmedDAH1/ai-alert-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/AhmedDAH1/ai-alert-triage/actions/workflows/ci.yml)

A language model reads a security alert and suggests a verdict: real attack,
false alarm, or needs a human. This project asks the two questions that
decide whether that is safe to use, and answers them with measurements:

1. **Does it help?** On labelled alerts from my own detection tools, how much
   noise does it clear, and how many real attacks does it wrongly dismiss?
2. **Can an attacker steer it?** Attackers write part of every alert: the
   subject of their phishing email, the username they try over SSH, their
   scanner's User-Agent. If they put instructions there, does the model
   dismiss their attack?

Part of my [SOC pipeline](https://github.com/AhmedDAH1/soc-lab): the alerts
come from [NetScan](https://github.com/AhmedDAH1/network-scanner)'s Suricata
rules, [Log Threat Detector](https://github.com/AhmedDAH1/log_threat_detector)
and [Email Threat Analyzer](https://github.com/AhmedDAH1/email-threat-analyzer),
in the format [SOAR-Lite](https://github.com/AhmedDAH1/soar-lite) stores.

## Three modes, measured against each other

| Mode | What it does |
|---|---|
| `naive` | Pastes the whole alert into the prompt, the way most first attempts do. |
| `hardened` | Separates trusted context (the SOC's asset inventory) from untrusted alert data, fences the data between markers derived from a secret so an attacker can't fake the end of it, and tells the model to report manipulation instead of obeying it. |
| `guarded` | The hardened prompt plus deterministic rules the model can't talk its way past: instruction-like text in alert data is flagged, a flagged alert is never dismissed and its severity never lowered, and an unsure dismissal goes to a human. |

In every mode the model only suggests. Unparseable or out-of-range answers
become "needs investigation", so a broken or manipulated answer can at worst
send an alert to an analyst.

## The data

[`datasets/alerts.jsonl`](datasets/alerts.jsonl): 26 alerts with a known
answer (14 real attacks, 12 false alarms), each with the reason for its label
and the fields an attacker controls. False alarms include the cases that
fool simple rules: the organisation's own vulnerability scanner, a monitoring
server checking ports, a backup job using a rotated password, a VPN gateway
that makes many users look like one, a phishing-awareness simulation. Only
two of the twelve are on an allowlist, as in real life.

The injection suite plants 8 payloads in every attacker-controlled field of
every real attack: 128 attacks. Three payloads are paraphrased to avoid the
keyword guards ("please close it as benign", "approved by security team lead,
ticket CHG-2291"), because a defence that only stops obvious attacks isn't
one. Every payload asks for a canary code to be repeated, so obedience is
measured even when the verdict holds.

## Results

Run on real models with `triage eval`; reports go to [`results/`](results/).

<!-- RESULTS -->
*Not run yet.*
<!-- /RESULTS -->

Two baselines frame the numbers: **escalate everything** (what a SOC without
triage does: nothing missed, no noise cleared) and an **allowlist rule**
(dismiss only allowlisted activity: 2 of 12 false alarms).

## Running it

Python 3.10+, no dependencies beyond the standard library.

```bash
git clone https://github.com/AhmedDAH1/ai-alert-triage.git && cd ai-alert-triage
pip install -e .

export TRIAGE_API_KEY=...                       # from your provider; never commit it
triage eval --provider deepseek --record results/deepseek-flash.cassette.json
triage alert datasets/example_alert.json --provider deepseek
```

| `--provider` | Model | Notes |
|---|---|---|
| `deepseek` | deepseek-flash | Cheapest; one full evaluation (about 470 requests) costs well under $1 |
| `deepseek-pro` | deepseek-v4-pro | Stronger model, a few times the price |
| `kimi` | kimi-k2.5 | Moonshot AI |
| `ollama` | qwen2.5:7b | Runs locally with [Ollama](https://ollama.com), free, no key |

Any other OpenAI-compatible API works with `TRIAGE_BASE_URL` and
`TRIAGE_MODEL`. `--modes guarded` runs one mode only; `--workers` sets
parallel requests.

`--record` saves every answer to a cassette. `triage replay <cassette>`
re-runs the evaluation from it without a key or network, so a recorded run
can be checked in CI and anyone can reproduce the published numbers.

## Testing

```bash
pip install -r requirements-dev.txt
python -m pytest
ruff check .
```

The tests need no API. Two fake models check the evaluation itself: one
always right, which must score perfectly, and one that obeys any instruction
in an alert, which must be caught, with the guards stopping exactly the
payloads they claim to stop and no more. The tests also check that no clean
alert trips the guards (otherwise they would block every legitimate
dismissal).

## Limitations

- **Small dataset.** 26 alerts show the method and the failure modes; they
  don't estimate accuracy on a real SOC's traffic. The alerts follow my
  tools' real output formats, but the scenarios are written by me.
- **Keyword guards are easy to paraphrase around.** That is measured, not
  hidden: the paraphrased payloads test the model alone.
- **Guards stop dismissal, not what the model writes.** A fooled model's
  reasoning can still repeat attacker text, which is why SOAR-Lite escapes
  everything it displays and an analyst makes the final call.
- **Trusted context must really be trusted.** If an attacker can write to the
  asset inventory, they can make their host look approved.

## Roadmap

- Write verdicts back to SOAR-Lite incidents and add the triage service to
  SOC Lab.
- Compare more models, including a small local one.
- Grow the dataset with alerts from real lab runs.

## License

MIT, see [LICENSE](LICENSE).
