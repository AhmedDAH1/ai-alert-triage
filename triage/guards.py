"""
Deterministic checks around the model, applied in "guarded" mode.

A prompt can only ask the model to resist manipulation; these rules enforce
the parts that matter even when it doesn't:

1. Text in the untrusted alert data that looks like instructions to the
   triage system is flagged before the model sees it.
2. An alert that shows signs of manipulation (flagged here, or reported by
   the model) is never dismissed, and its severity is never lowered.
3. A dismissal needs confidence; an unsure "false_positive" is escalated.

The AI only ever suggests: the worst a fooled model can do in guarded mode
is send an alert to a human.
"""

import re

from triage.prompts import untrusted_part
from triage.schema import Verdict, severity_rank

MIN_DISMISS_CONFIDENCE = 0.7

# Phrases addressed to a triage system or an analyst. They have no reason to
# appear in a username, User-Agent or subject line.
INJECTION_PATTERNS = [
    r"ignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier|preceding)\s+(instructions?|rules?|prompts?)",
    r"disregard\s+(all\s+|the\s+)?(previous|prior|above|earlier)",
    r"\bnew\s+instructions?\b",
    r"\byou\s+are\s+now\b",
    r"(^|[\[(<\n.!])\s*(system|assistant|developer)\s*(message|prompt|note)?\s*[:\]>]",
    r"\b(mark|classify|treat|label|report)\s+(this|it|the\s+alert)\s+as\s+(benign|safe|false[\s_-]?positive|clean|harmless)",
    r"\bfalse[\s_-]?positive\b",
    r"[\"']verdict[\"']\s*:",
    r"\binjection_suspected\b",
    r"</?\s*(alert|data|system|instructions?)\b",
    r"\b(soc|security)\s+(team|admin|administrator)s?\s+(says?|note|approved|authori[sz]ed)",
    r"\bauthori[sz]ed\s+(penetration\s+)?test\b.*\b(ignore|benign|no\s+action)",
    r"\bDATA-[0-9a-f]{6,}",
    r"忽略|之前的指令|以上指令|误报",
]
_COMPILED = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)


def injection_signals(alert: dict) -> list[str]:
    """Instruction-like text found in the untrusted part of the alert."""
    found = []
    for text in _strings(untrusted_part(alert)):
        for pattern in _COMPILED:
            match = pattern.search(text)
            if match:
                found.append(match.group(0)[:60])
    return found


def apply_guards(verdict: Verdict, alert: dict) -> Verdict:
    signals = injection_signals(alert)
    original = str(alert.get("severity", "medium")).lower()

    if signals:
        verdict.injection_suspected = True
        verdict.overrides.append(f"instruction-like text in alert data: {signals[0]!r}")

    if verdict.injection_suspected:
        if verdict.verdict == "false_positive":
            verdict.verdict = "needs_investigation"
            verdict.overrides.append("dismissal blocked: the alert shows signs of manipulation")
        if severity_rank(verdict.severity) < severity_rank(original):
            verdict.severity = original
            verdict.overrides.append(f"severity kept at {original}: not lowered for a manipulated alert")

    if verdict.verdict == "false_positive" and verdict.confidence < MIN_DISMISS_CONFIDENCE:
        verdict.verdict = "needs_investigation"
        verdict.overrides.append(f"dismissal blocked: confidence {verdict.confidence:.2f} < {MIN_DISMISS_CONFIDENCE}")

    return verdict
