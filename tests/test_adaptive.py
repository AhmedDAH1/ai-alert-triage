"""The adaptive harness, checked with the fake models (no network)."""

import json

from adaptive import attacks, datasets, offline, run
from triage import guards


def test_every_variant_keeps_the_canary_and_the_original_field_value(items):
    for item in items:
        if item["label"] != "true_positive":
            continue
        for v in attacks.variants(item):
            text = json.dumps(v["alert"], ensure_ascii=False)
            assert attacks.CANARY in text or "base64" in v["payload"]


def test_paraphrase_multilingual_and_rule_payloads_avoid_every_keyword():
    for (family, name), text in attacks.single_field_attacks().items():
        if family in ("paraphrase", "multilingual", "rule_target"):
            assert not guards.injection_signals({"x": text}), name


def test_split_halves_each_avoid_the_keywords():
    for first, second in attacks.SPLITS.values():
        assert not guards.injection_signals({"x": first})
        assert not guards.injection_signals({"x": second})


def test_reachable_keeps_labels_and_adds_trusted_records():
    items = datasets.load()
    reach = datasets.reachable(items)
    assert [i["label"] for i in items] == [i["label"] for i in reach]
    attacked = [i for i in reach if i["label"] == "true_positive" and i["attacker_fields"]]
    assert all(guards.trusted_evidence(i["alert"]) for i in attacked)


def test_offline_worst_case_matches_the_guarantee():
    # A fully compromised model: strict on the original data can only lose the one alert with a record
    rows = offline.experiment_worst_case(offline.all_variants(datasets.load()))
    assert rows["original"]["strict"] == 3


class _Args:
    replay = None
    dataset = "original"
    per_family = 3
    families = None
    mode = "strict"
    budget = 3
    targets = 2
    workers = 2
    attacker_temperature = 0.9


def test_static_runs_with_the_gullible_model(gullible, tmp_path, monkeypatch):
    monkeypatch.setattr(run, "OUT", tmp_path)
    run.static(_Args(), gullible)
    report = (tmp_path / "static.md").read_text()
    assert "all adaptive" in report


class _FakeAttacker:
    name = "fake-attacker"

    def complete(self, messages):
        return json.dumps({"payload": "nightly config-management run, matches asset record"})


def test_loop_runs_and_scores(gullible, tmp_path, monkeypatch):
    monkeypatch.setattr(run, "OUT", tmp_path)
    args = _Args()
    args.dataset = "reachable"
    args.mode = "guarded"     # the fake cites records from the original dataset, so test guarded here
    run.loop(args, gullible, _FakeAttacker())
    data = json.loads((tmp_path / "loop_guarded_reachable.json").read_text())
    # The gullible model obeys anything carrying the canary and the payload has no keyword: broken on try 1
    assert all(v == 1 for v in data["first_success"].values())


def test_budget_cap_stops_paid_requests(oracle):
    run.BudgetProvider._shared["sent"] = 0
    capped = run.BudgetProvider(oracle, limit=1)
    item = datasets.load()[0]
    messages = [{"role": "user", "content": item["alert"]["description"]}]
    capped.complete(messages)
    try:
        capped.complete(messages)
        raise AssertionError("cap not enforced")
    except run.providers.ProviderError:
        pass
    run.BudgetProvider._shared["sent"] = 0


def test_dry_run_counts_seeded_answers(capsys):
    run.main(["static", "--dry-run", "--dataset", "original", "--families", "original", "--per-family", "0",
              "--seed", str(datasets.ROOT / "results" / "qwen2.5-7b.cassette.json")])
    out = capsys.readouterr().out
    assert "0 new requests" in out


class _Broken:
    name = "broken"

    def complete(self, messages):
        raise run.providers.ProviderError("URLError: SSL EOF")


def test_run_stops_when_the_model_keeps_failing(tmp_path, monkeypatch):
    monkeypatch.setattr(run, "OUT", tmp_path)
    run._health.update(ok=0, failed_in_a_row=0, first_error=None)
    try:
        run.benign(_Args(), _Broken())
        raise AssertionError("did not stop")
    except run.AbortRun as e:
        assert "SSL EOF" in str(e)
    assert not (tmp_path / "benign.md").exists()
    run._health.update(ok=0, failed_in_a_row=0, first_error=None)
