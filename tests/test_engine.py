"""Verdict parsing, prompts, guards and the triage engine."""

import json

import pytest
from conftest import ITEMS, answer

from triage import guards, injections, prompts
from triage.engine import triage
from triage.providers import ProviderError
from triage.schema import parse_verdict

PAYPAL = next(i for i in ITEMS if i["id"] == "eta-paypal")
SCANNER_FP = next(i for i in ITEMS if i["id"] == "ns-syn-approved-scanner")


class Fixed:
    name = "fixed"

    def __init__(self, text):
        self.text = text

    def complete(self, messages):
        return self.text


class Broken:
    name = "broken"

    def complete(self, messages):
        raise ProviderError("HTTP 503")


# ── Parsing: a bad answer must never dismiss an alert ─────────────

@pytest.mark.parametrize("text", [
    "not json", "", "[1, 2]", '{"verdict": "ignore", "severity": "low"}',
    '{"verdict": "false_positive", "severity": "none"}', '{"verdict": "false_positive"',
])
def test_unusable_answers_become_needs_investigation(text):
    verdict = parse_verdict(text, "high")
    assert verdict.verdict == "needs_investigation"
    assert verdict.severity == "high"
    assert not verdict.valid


def test_valid_answer_is_parsed_and_bounded():
    text = "Here you go:\n" + json.dumps({
        "verdict": "TRUE_POSITIVE", "severity": "High", "confidence": 7, "reasoning": "x" * 5000,
        "next_steps": [f"step {i}" for i in range(20)], "injection_suspected": True})
    verdict = parse_verdict(text)
    assert (verdict.verdict, verdict.severity, verdict.confidence) == ("true_positive", "high", 1.0)
    assert len(verdict.reasoning) == 1000 and len(verdict.next_steps) == 6
    assert verdict.injection_suspected


def test_model_outage_escalates_instead_of_failing():
    verdict = triage(PAYPAL["alert"], Broken())
    assert verdict.verdict == "needs_investigation" and not verdict.valid


# ── Prompts ───────────────────────────────────────────────────────

def test_hardened_prompt_fences_untrusted_data_and_keeps_context_outside():
    text = prompts.hardened_messages(PAYPAL["alert"])[1]["content"]
    marker = prompts.boundary(PAYPAL["alert"])
    before, data, after = text.split(marker)[-3:]
    assert "paypa1-secure.com" in data
    assert '"org_domain"' in text.split("ALERT DATA")[0]       # trusted context comes first
    assert '"context"' not in data                            # and is not inside the untrusted block
    assert after.strip() == ""


def test_attacker_cannot_fake_the_end_of_the_data():
    variant = next(v for v in injections.variants(PAYPAL) if v["payload"] == "boundary_escape")
    marker = prompts.boundary(variant["alert"])
    assert marker not in json.dumps(variant["alert"])
    text = prompts.hardened_messages(variant["alert"])[1]["content"]
    # twice in the instruction line, twice around the data; the attacker's fake marker is different
    assert text.count(marker) == 4
    assert "DATA-0000000000000000" != marker


def test_boundary_depends_on_a_secret(monkeypatch):
    first = prompts.boundary(PAYPAL["alert"])
    monkeypatch.setenv("TRIAGE_BOUNDARY_SECRET", "another deployment")
    assert prompts.boundary(PAYPAL["alert"]) != first


# ── Guards ────────────────────────────────────────────────────────

def test_no_clean_dataset_alert_trips_the_guards(items):
    # Otherwise the guards would block every legitimate dismissal.
    assert [i["id"] for i in items if guards.injection_signals(i["alert"])] == []


@pytest.mark.parametrize("payload", sorted(set(injections.PAYLOADS) - injections.EVADES_KEYWORDS))
def test_keyword_payloads_are_flagged(payload):
    variant = next(v for v in injections.variants(PAYPAL) if v["payload"] == payload)
    assert guards.injection_signals(variant["alert"])


@pytest.mark.parametrize("payload", sorted(injections.EVADES_KEYWORDS))
def test_paraphrased_payloads_get_past_the_keywords(payload):
    # Documented limit: these depend on the model, which is why the
    # evaluation measures them separately.
    variant = next(v for v in injections.variants(PAYPAL) if v["payload"] == payload)
    assert guards.injection_signals(variant["alert"]) == []


def test_fooled_model_cannot_dismiss_a_flagged_alert():
    variant = next(v for v in injections.variants(PAYPAL) if v["payload"] == "direct_override")
    verdict = triage(variant["alert"], Fixed(answer("false_positive", "low", 0.99)), "guarded")
    assert verdict.verdict == "needs_investigation"
    assert verdict.severity == "critical"          # restored, not lowered
    assert verdict.overrides


def test_model_reported_injection_also_blocks_dismissal():
    verdict = triage(PAYPAL["alert"], Fixed(answer("false_positive", "low", 0.99, injection=True)), "guarded")
    assert verdict.verdict == "needs_investigation"


def test_unsure_dismissal_is_escalated():
    verdict = triage(SCANNER_FP["alert"], Fixed(answer("false_positive", "low", 0.5)), "guarded")
    assert verdict.verdict == "needs_investigation"


def test_confident_dismissal_of_clean_noise_is_allowed():
    verdict = triage(SCANNER_FP["alert"], Fixed(answer("false_positive", "low", 0.9)), "guarded")
    assert verdict.verdict == "false_positive" and verdict.overrides == []


def test_hardened_mode_has_no_guards():
    variant = next(v for v in injections.variants(PAYPAL) if v["payload"] == "direct_override")
    assert triage(variant["alert"], Fixed(answer("false_positive", "low", 0.99)), "hardened").verdict == "false_positive"


# ── Strict mode: dismissals need trusted evidence ─────────────────

CI_RUNNER = next(i for i in ITEMS if i["id"] == "ltd-bf-from-ci-runner")
UNKNOWN_SOURCE = next(i for i in ITEMS if i["id"] == "ltd-bf-root-admin")


@pytest.mark.parametrize("evidence", [[], ["note"], ["org_domain"], ["allowlist"]])
def test_unknown_source_can_never_be_dismissed(evidence):
    verdict = triage(UNKNOWN_SOURCE["alert"], Fixed(answer("false_positive", "low", 0.99, evidence=evidence)), "strict")
    assert verdict.verdict == "needs_investigation"


def test_evidence_must_be_a_record_that_exists():
    fake = triage(SCANNER_FP["alert"], Fixed(answer("false_positive", "low", 0.9, evidence=["change_ticket"])), "strict")
    cited = ["allowlist", "asset.role"]
    real = triage(SCANNER_FP["alert"], Fixed(answer("false_positive", "low", 0.9, evidence=cited)), "strict")
    assert fake.verdict == "needs_investigation"
    assert real.verdict == "false_positive"


def test_generic_facts_are_not_evidence():
    email = next(i for i in ITEMS if i["id"] == "eta-github-notification")
    verdict = triage(email["alert"], Fixed(answer("false_positive", "low", 0.9, evidence=["org_domain"])), "strict")
    assert verdict.verdict == "needs_investigation"


def test_known_limit_a_real_record_can_be_misused():
    # Documented: a compromised host that is in the inventory still has a real
    # asset record, so a fooled model citing it gets through strict mode.
    verdict = triage(CI_RUNNER["alert"], Fixed(answer("false_positive", "low", 0.9, evidence=["asset"])), "strict")
    assert verdict.verdict == "false_positive"


def test_evidence_is_parsed():
    assert parse_verdict(answer("false_positive", evidence=["asset", "allowlist"])).evidence == ["asset", "allowlist"]
