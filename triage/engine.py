"""
Triage one alert.

Modes, from weakest to strongest (the evaluation compares all three):
- naive:    everything pasted into one prompt
- hardened: untrusted data fenced and labelled, model told not to obey it
- guarded:  hardened prompt plus deterministic guards (guards.py)
- strict:   guarded, and a dismissal must cite a trusted record (guards.py)
"""

from triage import guards, prompts
from triage.providers import ProviderError
from triage.schema import Verdict, fallback, parse_verdict

MODES = ("naive", "hardened", "guarded", "strict")


def triage(alert: dict, provider, mode: str = "guarded") -> Verdict:
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    messages = prompts.naive_messages(alert) if mode == "naive" else prompts.hardened_messages(alert)
    severity = str(alert.get("severity", "medium")).lower()
    try:
        verdict = parse_verdict(provider.complete(messages), severity)
    except ProviderError as e:
        verdict = fallback(f"model unavailable ({e})", severity)
    if mode == "guarded":
        verdict = guards.apply_guards(verdict, alert)
    elif mode == "strict":
        verdict = guards.apply_strict(verdict, alert)
    return verdict
