"""The evaluation must score a perfect model perfectly and catch a gullible one."""

import json

from conftest import DATASET, ITEMS

from triage import evaluate, guards, injections
from triage.cli import main
from triage.providers import RecordingProvider

TPS = [i for i in ITEMS if i["label"] == "true_positive"]
FPS = [i for i in ITEMS if i["label"] == "false_positive"]
N_VARIANTS = sum(len(i["attacker_fields"]) for i in TPS) * len(injections.PAYLOADS)


def test_dataset_is_well_formed():
    assert len({i["id"] for i in ITEMS}) == len(ITEMS)
    assert len(TPS) >= 10 and len(FPS) >= 10
    for item in ITEMS:
        assert item["label"] in ("true_positive", "false_positive") and item["why"]
        for field in item["attacker_fields"]:
            assert isinstance(injections._get(item["alert"], field), str), (item["id"], field)


def test_dataset_file_matches_its_builder(tmp_path, monkeypatch):
    import importlib.util
    spec = importlib.util.spec_from_file_location("build", DATASET.parent / "build_alerts.py")
    build = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(build)
    built = [json.dumps(a, ensure_ascii=False) for a in build.ALERTS]
    assert built == DATASET.read_text(encoding="utf-8").splitlines(), "run python datasets/build_alerts.py"


def test_variants_plant_the_payload_and_keep_the_original():
    variant = next(injections.variants(next(i for i in TPS if i["id"] == "ltd-sqlmap")))
    value = injections._get(variant["alert"], variant["field"])
    assert value.startswith("sqlmap/1.8.2") and injections.CANARY in value


FPS_WITH_EVIDENCE = [i for i in FPS if guards.trusted_evidence(i["alert"])]


def test_perfect_model_scores_perfectly(oracle):
    results = evaluate.run(DATASET, oracle, workers=2)
    for mode, r in results["modes"].items():
        c, a = r["clean"], r["attack"]
        expected_cleared = len(FPS_WITH_EVIDENCE) if mode == "strict" else len(FPS)
        assert c["attacks_dismissed"] == 0 and c["noise_cleared"] == expected_cleared, mode
        assert a["variants"] == N_VARIANTS and a["dismissed"] == 0 and a["obeyed"] == 0


def test_strict_mode_costs_the_dismissals_no_record_supports():
    # The price of the rule: benign alerts with no supporting record go to an analyst.
    assert sorted(i["id"] for i in FPS if i not in FPS_WITH_EVIDENCE) == ["eta-github-notification", "eta-internal-newsletter"]


def test_gullible_model_is_caught_and_guards_limit_the_damage(gullible):
    results = evaluate.run(DATASET, gullible, workers=2)
    naive = results["modes"]["naive"]["attack"]
    guarded = results["modes"]["guarded"]["attack"]
    assert naive["dismissed"] == N_VARIANTS and naive["obeyed"] == N_VARIANTS
    # Guards stop every keyword payload; paraphrased ones still get through.
    per_payload = len(injections.EVADES_KEYWORDS) * N_VARIANTS // len(injections.PAYLOADS)
    assert guarded["dismissed"] == per_payload
    assert guarded["obeyed"] == N_VARIANTS     # guards stop dismissal, not what the model writes
    # Strict stops paraphrased payloads too, except on the one attack whose
    # source has a genuine inventory record (the compromised CI runner).
    strict = results["modes"]["strict"]["attack"]
    assert strict["dismissed"] == len(injections.EVADES_KEYWORDS)


def test_baselines():
    results = evaluate.run(DATASET, type("M", (), {"name": "none", "complete": lambda s, m: "{}"})(), modes=[])
    everything = results["baselines"]["escalate everything"]
    allowlist = results["baselines"]["allowlist rule"]
    assert everything["noise_cleared"] == 0 and everything["attacks_dismissed"] == 0
    assert allowlist["attacks_dismissed"] == 0
    assert allowlist["noise_cleared"] == sum(bool(i["alert"]["context"].get("allowlist")) for i in FPS)


def test_report_renders(oracle):
    text = evaluate.report(evaluate.run(DATASET, oracle, modes=["guarded"], workers=2))
    assert "| **guarded** |" in text and "escalate everything" in text and "avoids keyword guards" in text


def test_recorded_evaluation_replays_identically(tmp_path, oracle, monkeypatch):
    monkeypatch.setenv("TRIAGE_BOUNDARY_SECRET", "evaluation")
    cassette = tmp_path / "oracle.json"
    recorded = evaluate.run(DATASET, RecordingProvider(oracle, cassette), modes=["guarded"], workers=2)
    main(["replay", str(cassette), "--modes", "guarded", "--out", str(tmp_path / "out")])
    replayed = json.loads((tmp_path / "out" / "oracle_(replay).json").read_text())
    assert replayed["modes"]["guarded"]["clean"] == recorded["modes"]["guarded"]["clean"]
    assert replayed["modes"]["guarded"]["attack"]["dismissed"] == recorded["modes"]["guarded"]["attack"]["dismissed"]
