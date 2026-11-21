"""
Decision-level trust: a counterfactual masking check and a trust score.

The principle: text the attacker wrote may make an alert look worse, never
better. The model reads the full alert, and that reading may escalate. A
dismissal, or a lowered severity, must also hold when the model reads the
same alert with every attacker-writable string masked out. So:

    final dismissal  =>  the model dismissed the alert WITHOUT the attacker's text

An attacker can then only get dismissed what would be dismissed without their
payload; their text can block a dismissal (send the alert to a human), not
cause one. This holds even if the model obeys every injection, under two
assumptions, both stated and tested:

1. The mask is complete: every string an attacker can influence is masked.
   Only structured values in a fixed list (addresses, ports, counts,
   detector enums, authentication results) are shown. Free text, including
   title and description, which detectors often build from attacker text,
   is replaced by a fixed marker, without its length. The number of items in
   a list (URLs, attachments) is kept; that is the only channel left.
2. The masked reading is deterministic enough that one check is meaningful
   (temperature 0, the same prompt).

It costs one extra request, and only for proposed dismissals and downgrades.
What it does not stop: a model that dismisses a real attack with no payload
at all. That is an accuracy problem, measured separately, not an injection.

The trust score turns the evidence behind a dismissal into a routing
decision: auto-close, analyst review (with the model's suggestion), or
escalate. The weights are set by hand and stated, not learned: with 27 alerts
there is nothing to learn them from. The evaluation sweeps the threshold.
"""

import copy
import re
from dataclasses import dataclass, field

from triage import guards
from triage.schema import Verdict, severity_rank

# Values shown in the masked view. Everything else in the untrusted part is masked.
STRUCTURED_KEYS = {
    "source", "severity", "detector", "alert_type", "signature_id", "src_ip", "src_port", "dest_ip",
    "dest_port", "proto", "mitre_technique_id", "threat_score", "spf", "dkim", "dmarc", "recipient",
}
# Detector vocabulary that may carry an attacker value in parentheses: kept without it.
VOCABULARY_KEYS = {"indicators"}
_STRUCTURED_VALUE = re.compile(
    r"^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{2,39}|\d+|T\d{4}(?:\.\d{3})?|[A-Za-z][A-Za-z0-9_-]{0,39}"
    r"|[\w.+-]+@[\w-]+(?:\.[\w-]+)+)$")
_PARENTHESISED = re.compile(r"\s*\([^)]*\)")
# No length or content: the masked view of an attacked alert is then identical
# to the masked view of the clean alert, so its answer cannot depend on the payload.
MASK = "[masked: attacker-writable text]"

AUTO_THRESHOLD = 0.75     # trust needed to close an alert without a human
REVIEW_THRESHOLD = 0.4    # below this, a proposed dismissal goes to the normal queue, not to review
EVIDENCE_WEIGHT = {"authorisation": 1.0, "identity": 0.6, "none": 0.3}
COUNTERFACTUAL_WEIGHT = {"agreed": 1.0, "not_run": 0.5, "disagreed": 0.0}


def _mask_value(key, value):
    if isinstance(value, dict):
        return {k: _mask_value(k, v) for k, v in value.items()}
    if isinstance(value, list):
        if key in VOCABULARY_KEYS:
            return [_PARENTHESISED.sub("", str(v)) for v in value]
        if key in STRUCTURED_KEYS:
            return [_mask_value(key, v) for v in value]
        return [MASK for _ in value]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    text = str(value)
    if key in STRUCTURED_KEYS and _STRUCTURED_VALUE.match(text):
        return text
    return MASK


def mask(alert: dict) -> dict:
    """The alert with every attacker-writable string replaced by a fixed marker. Context is untouched."""
    masked = {k: _mask_value(k, v) for k, v in alert.items() if k != "context"}
    masked["context"] = copy.deepcopy(alert.get("context"))
    return masked


def needs_check(verdict: Verdict, alert: dict) -> bool:
    """A dismissal or a downgrade is proposed: the attacker would want exactly these."""
    original = str(alert.get("severity", "medium")).lower()
    return verdict.verdict == "false_positive" or severity_rank(verdict.severity) < severity_rank(original)


def apply_counterfactual(verdict: Verdict, masked: Verdict, alert: dict) -> Verdict:
    """Keep only what the masked reading also supports."""
    if verdict.verdict == "false_positive" and masked.verdict != "false_positive":
        verdict.verdict = "needs_investigation"
        verdict.overrides.append(f"counterfactual check: without attacker-writable text the model answers "
                                 f"{masked.verdict!r}, so the dismissal depended on that text")
    if severity_rank(verdict.severity) < severity_rank(masked.severity):
        verdict.overrides.append(f"counterfactual check: severity raised to {masked.severity} "
                                 f"(the masked reading's) from {verdict.severity}")
        verdict.severity = masked.severity
    return verdict


def evidence_kind(verdict: Verdict, alert: dict) -> str:
    cited = {guards.record_name(e) for e in verdict.evidence} & guards.trusted_evidence(alert)
    if cited & guards.AUTHORISATION_RECORDS:
        return "authorisation"
    if cited:
        return "identity"
    return "none"


@dataclass
class Decision:
    verdict: Verdict
    route: str                       # auto_close | review | escalate | handle
    trust: float                     # trust in closing this alert automatically, 0..1
    counterfactual: str              # agreed | disagreed | not_run
    masked_verdict: dict | None = None
    signals: dict = field(default_factory=dict)

    def to_dict(self):
        return {"route": self.route, "trust": round(self.trust, 3), "counterfactual": self.counterfactual,
                "signals": self.signals, "verdict": self.verdict.to_dict(), "masked_verdict": self.masked_verdict}


INJECTION_WEIGHT = 0.5    # keyword hit or model report: a reason for a human look, not a block


def trust_score(proposed: Verdict, alert: dict, counterfactual: str) -> tuple[float, dict]:
    """Trust in closing this alert without a human, with the signals behind it.

    confidence x evidence weight x counterfactual weight x (0.5 if injection signal)
    """
    signals = {
        "confidence": round(proposed.confidence, 3),
        "injection_signal": bool(proposed.model_flagged_injection or guards.injection_signals_normalized(alert)),
        "evidence": evidence_kind(proposed, alert),
        "counterfactual": counterfactual,
    }
    if proposed.verdict != "false_positive":
        return 0.0, signals
    score = proposed.confidence * EVIDENCE_WEIGHT[signals["evidence"]] * COUNTERFACTUAL_WEIGHT[counterfactual]
    if signals["injection_signal"]:
        score *= INJECTION_WEIGHT
    return score, signals


def decide(alert: dict, answer, masked_answer=None, mode: str = "trusted") -> Decision:
    """Combine the full and masked readings into a decision.

    `answer` and `masked_answer` are raw model outputs (or the exception raised
    instead of one), as returned by engine.ask. `masked_answer` is needed when
    needs_check() is true for the model's proposal; engine.decide asks for it.

    masked:  strict mode's rules on the full reading, then the counterfactual check.
    trusted: the counterfactual check is the safety gate. Keywords and the model's
             own injection report lower trust instead of blocking; the trust score
             routes the proposal: auto-close, analyst review, or escalation.
    """
    from triage.engine import finalize  # engine imports this module

    raw = finalize(answer, alert, "hardened")    # the model's own proposal, before any rule
    counterfactual, masked, masked_dict = "not_run", None, None
    if needs_check(raw, alert):
        if masked_answer is None:
            raise ValueError("a masked answer is needed: the model proposes a dismissal or a downgrade")
        masked_alert = mask(alert)
        masked = finalize(masked_answer, masked_alert, "hardened")
        masked_dict = masked.to_dict()
        same = (masked.verdict == "false_positive") == (raw.verdict == "false_positive")
        counterfactual = "agreed" if same else "disagreed"

    if mode == "masked":
        verdict = finalize(answer, alert, "strict")
        if masked is not None:
            verdict = apply_counterfactual(verdict, masked, alert)
        route = {"false_positive": "auto_close", "true_positive": "escalate"}.get(verdict.verdict, "handle")
        score, signals = trust_score(raw, alert, counterfactual)
        return Decision(verdict, route, score, counterfactual, masked_dict, signals)

    if mode != "trusted":
        raise ValueError(f"unknown mode {mode!r}")
    verdict = finalize(answer, alert, "hardened")
    score, signals = trust_score(raw, alert, counterfactual)
    original = str(alert.get("severity", "medium")).lower()
    if raw.verdict == "false_positive" and counterfactual == "disagreed":
        verdict.verdict, route = "needs_investigation", "escalate"
        verdict.injection_suspected = True
        verdict.overrides.append("counterfactual check: the dismissal depended on attacker-writable text; "
                                 "treated as a manipulation attempt")
    elif raw.verdict == "false_positive" and verdict.confidence >= guards.MIN_DISMISS_CONFIDENCE \
            and score >= AUTO_THRESHOLD:
        route = "auto_close"
    elif raw.verdict == "false_positive" and score >= REVIEW_THRESHOLD:
        verdict.verdict, route = "needs_investigation", "review"
        verdict.overrides.append(f"trust {score:.2f} < {AUTO_THRESHOLD}: analyst review, suggested false_positive")
    elif raw.verdict == "false_positive":
        verdict.verdict, route = "needs_investigation", "handle"
        verdict.overrides.append(f"trust {score:.2f} < {REVIEW_THRESHOLD}: not enough evidence to suggest closing")
    else:
        route = "escalate" if raw.verdict == "true_positive" else "handle"
    if signals["injection_signal"]:
        verdict.injection_suspected = True
    if route != "auto_close":
        if masked is not None and severity_rank(verdict.severity) < severity_rank(masked.severity):
            verdict = apply_counterfactual(verdict, masked, alert)
        if severity_rank(verdict.severity) < severity_rank(original):
            verdict.overrides.append(f"severity kept at {original}: lowering it needs an automatic close")
            verdict.severity = original
    return Decision(verdict, route, score, counterfactual, masked_dict, signals)
