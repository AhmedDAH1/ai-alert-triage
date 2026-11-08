"""
Triage one alert.

Modes, from weakest to strongest (the evaluation compares all four):
- naive:    everything pasted into one prompt
- hardened: untrusted data fenced and labelled, model told not to obey it
- guarded:  hardened prompt plus deterministic guards (guards.py)
- strict:   guarded, and a dismissal must cite a trusted record (guards.py)

Hardened, guarded and strict send the model the same prompt; they differ
only in the rules applied to its answer. The evaluation asks once and
applies each mode's rules to that same answer, so the comparison measures
exactly what the guards change.
"""

from triage import guards, prompts
from triage.providers import ProviderError
from triage.schema import Verdict, fallback, parse_verdict

MODES = ("naive", "hardened", "guarded", "strict")


def prompt_kind(mode: str) -> str:
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
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
    return verdict


def ask(provider, alert: dict, mode: str) -> str | Exception:
    try:
        return provider.complete(messages_for(alert, mode))
    except ProviderError as e:
        return e


def triage(alert: dict, provider, mode: str = "guarded") -> Verdict:
    return finalize(ask(provider, alert, mode), alert, mode)
