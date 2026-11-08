"""
The verdict a model must return, and strict parsing of its answer.

Model output is untrusted too: it may be malformed, or shaped by an injected
instruction. Anything that doesn't parse into a valid verdict becomes
"needs_investigation", so a broken answer can never dismiss an alert.
"""

import json
from dataclasses import asdict, dataclass, field

VERDICTS = ("true_positive", "false_positive", "needs_investigation")
SEVERITIES = ("low", "medium", "high", "critical")
MAX_TEXT = 1000
MAX_STEPS = 6


@dataclass
class Verdict:
    verdict: str
    severity: str
    confidence: float
    reasoning: str
    next_steps: list[str] = field(default_factory=list)
    injection_suspected: bool = False
    # Names of trusted CONTEXT records the model cites to justify a dismissal
    evidence: list[str] = field(default_factory=list)
    # What the model itself reported; injection_suspected can also be set by the guards
    model_flagged_injection: bool = False
    # Set by the guards, never by the model: why the model's answer was overridden
    overrides: list[str] = field(default_factory=list)
    valid: bool = True

    def to_dict(self):
        return asdict(self)


def severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity) if severity in SEVERITIES else 1


def fallback(reason: str, severity: str = "medium") -> Verdict:
    """The safe answer when the model's output can't be used."""
    return Verdict(
        verdict="needs_investigation",
        severity=severity if severity in SEVERITIES else "medium",
        confidence=0.0,
        reasoning=f"Automatic triage unavailable: {reason}",
        valid=False,
    )


def parse_verdict(text: str, alert_severity: str = "medium") -> Verdict:
    """Parse the model's JSON answer. Never raises."""
    try:
        start, end = text.index("{"), text.rindex("}") + 1
        data = json.loads(text[start:end])
    except (ValueError, TypeError):
        return fallback("the model's answer was not valid JSON", alert_severity)
    if not isinstance(data, dict):
        return fallback("the model's answer was not a JSON object", alert_severity)

    verdict = str(data.get("verdict", "")).strip().lower()
    severity = str(data.get("severity", "")).strip().lower()
    if verdict not in VERDICTS:
        return fallback(f"unknown verdict {verdict[:40]!r}", alert_severity)
    if severity not in SEVERITIES:
        return fallback(f"unknown severity {severity[:40]!r}", alert_severity)

    try:
        confidence = min(max(float(data.get("confidence", 0.5)), 0.0), 1.0)
    except (TypeError, ValueError):
        confidence = 0.5
    steps = data.get("next_steps") or []
    if not isinstance(steps, list):
        steps = [steps]
    evidence = data.get("evidence") or []
    if not isinstance(evidence, list):
        evidence = [evidence]

    return Verdict(
        verdict=verdict,
        severity=severity,
        confidence=confidence,
        reasoning=str(data.get("reasoning", ""))[:MAX_TEXT],
        next_steps=[str(s)[:200] for s in steps[:MAX_STEPS]],
        injection_suspected=bool(data.get("injection_suspected", False)),
        evidence=[str(e)[:60] for e in evidence[:MAX_STEPS]],
        model_flagged_injection=bool(data.get("injection_suspected", False)),
    )
