"""
Triage one alert.

Modes, from weakest to strongest (the evaluation compares all four):
- naive:    everything pasted into one prompt
- hardened: untrusted data fenced and labelled, model told not to obey it
- guarded:  hardened prompt plus deterministic guards (guards.py)
- strict:   guarded, and a dismissal must cite a trusted record (guards.py)

Added after the adaptive evaluation (adaptive/README.md):
- verified: strict, with keywords matched on normalised text, dismissals only
            on authorisation records, and no downgrade without one (guards.py)
- masked:   strict, and a dismissal or downgrade must also hold when the model
            reads the alert with attacker-writable text masked (trust.py)
- trusted:  the masked check as the safety gate; keywords and the model's
            injection report lower trust instead of blocking; a trust score
            routes each decision to auto-close, analyst review or escalation (trust.py)

MODES are the four of the published evaluation, so its reports stay
reproducible; ALL_MODES adds the three new ones.

Hardened, guarded and strict send the model the same prompt; they differ
only in the rules applied to its answer. The evaluation asks once and
applies each mode's rules to that same answer, so the comparison measures
exactly what the guards change.
"""

from triage import guards, prompts, trust
from triage.providers import ProviderError
from triage.schema import Verdict, fallback, parse_verdict

MODES = ("naive", "hardened", "guarded", "strict")
SINGLE_ANSWER_MODES = MODES + ("verified",)
COUNTERFACTUAL_MODES = ("masked", "trusted")      # two readings: full, and masked when needed
ALL_MODES = SINGLE_ANSWER_MODES + tuple(COUNTERFACTUAL_MODES)


def prompt_kind(mode: str) -> str:
    if mode not in ALL_MODES:
        raise ValueError(f"mode must be one of {ALL_MODES}")
    return "naive" if mode == "naive" else "hardened"


def messages_for(alert: dict, mode: str) -> list[dict]:
    return prompts.naive_messages(alert) if prompt_kind(mode) == "naive" else prompts.hardened_messages(alert)


def finalize(answer: str | Exception, alert: dict, mode: str) -> Verdict:
    """Turn the model's answer (or the error instead of one) into a verdict for this mode."""
    severity = str(alert.get("severity", "medium")).lower()
    if isinstance(answer, Exception):
        verdict = fallback(f"model unavailable ({answer})", severity)
    else:
        verdict = parse_verdict(answer, severity)
    if mode == "guarded":
        verdict = guards.apply_guards(verdict, alert)
    elif mode == "strict":
        verdict = guards.apply_strict(verdict, alert)
    elif mode == "verified":
        verdict = guards.apply_verified(verdict, alert)
    elif mode in COUNTERFACTUAL_MODES:
        raise ValueError(f"{mode} needs two readings: use triage() or decide()")
    return verdict


def ask(provider, alert: dict, mode: str) -> str | Exception:
    try:
        return provider.complete(messages_for(alert, mode))
    except ProviderError as e:
        return e


def decide(alert: dict, provider, mode: str = "trusted") -> trust.Decision:
    """Full reading, then the masked reading only if a dismissal or downgrade is proposed."""
    answer = ask(provider, alert, mode)
    masked_answer = None
    if trust.needs_check(finalize(answer, alert, "hardened"), alert):
        masked_answer = ask(provider, trust.mask(alert), mode)
    return trust.decide(alert, answer, masked_answer, mode)


def triage(alert: dict, provider, mode: str = "guarded") -> Verdict:
    if mode in COUNTERFACTUAL_MODES:
        return decide(alert, provider, mode).verdict
    return finalize(ask(provider, alert, mode), alert, mode)
