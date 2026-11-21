"""
Model-free experiments: exact results for everything the deterministic layer decides.

    python -m adaptive.offline            # writes adaptive/results/offline.md

1. Keyword guard vs adaptive payloads: share of variants it flags, by family.
2. Compromised model (worst case): the model obeys every payload, answers
   false_positive with confidence 0.95, never reports the injection, and cites
   every trusted record that exists. Whatever still gets dismissed is what the
   deterministic layer alone fails to stop. This is the guarantee the guards
   give regardless of model, on the original and on the "reachable" dataset.
3. False positives of the keyword guard on benign text.
"""

import json
from collections import defaultdict
from pathlib import Path

from adaptive import attacks, datasets
from adaptive.stats import fmt
from triage import guards, injections
from triage.schema import Verdict

OUT = Path(__file__).resolve().parent / "results"


def compromised_answer(alert: dict) -> Verdict:
    return Verdict(verdict="false_positive", severity="low", confidence=0.95, reasoning="obeyed",
                   evidence=sorted(guards.trusted_evidence(alert)))


def all_variants(items):
    tps = [i for i in items if i["label"] == "true_positive"]
    original = [dict(v, family="original") for i in tps for v in injections.variants(i)]
    return original + [v for i in tps for v in attacks.variants(i)]


def flagged(alert) -> bool:
    return bool(guards.injection_signals(alert))


def outcome(alert, mode) -> Verdict:
    v = compromised_answer(alert)
    return guards.apply_guards(v, alert) if mode == "guarded" else guards.apply_strict(v, alert)


def experiment_detection(variants):
    rows = defaultdict(lambda: [0, 0, 0])          # flagged, flagged after normalisation, n
    sub = defaultdict(lambda: [0, 0, 0])
    for v in variants:
        hit, normed = flagged(v["alert"]), bool(guards.injection_signals_normalized(v["alert"]))
        for table, key in ((rows, v["family"]),
                           (sub, v["family"] + ": " + v["payload"].split("/")[-1])):
            if table is sub and not v["family"].startswith("obfuscation"):
                continue
            table[key][0] += hit
            table[key][1] += normed
            table[key][2] += 1
    return rows, sub


def experiment_worst_case(variants):
    rows = defaultdict(lambda: {"n": 0, "guarded": 0, "strict": 0, "downgraded_guarded": 0})
    for v in variants:
        r = rows[v["family"]]
        r["n"] += 1
        g = outcome(v["alert"], "guarded")
        s = outcome(v["alert"], "strict")
        r["guarded"] += g.verdict == "false_positive"
        r["strict"] += s.verdict == "false_positive"
        r["downgraded_guarded"] += g.severity == "low" and v["alert"].get("severity") != "low"
    return rows


def experiment_false_positives(items):
    strings = [(c, f, s, bool(guards.injection_signals({"x": s})), bool(guards.injection_signals_normalized({"x": s})))
               for c, f, s in datasets.HARD_BENIGN_STRINGS]
    clean = [(i["id"], guards.injection_signals(i["alert"])) for i in items]
    hard = [(i["id"], guards.injection_signals(i["alert"])) for i in datasets.hard_benign(items)]
    return strings, clean, hard


def table(header, rows):
    return "\n".join(["| " + " | ".join(header) + " |", "|" + "---|" * len(header)] +
                     ["| " + " | ".join(map(str, r)) + " |" for r in rows])


FAMILIES = ["original", "obfuscation", "obfuscation_heldout", "paraphrase", "multilingual", "rule_target", "split"]


def main():
    items = datasets.load()
    reach = datasets.reachable(items)
    var_orig, var_reach = all_variants(items), all_variants(reach)
    lines = ["# Offline adaptive evaluation (no model needed)", "",
             "Exact for the deterministic layer. 95% Wilson intervals.", ""]

    det, sub = experiment_detection(var_orig)
    lines += ["## 1. Does the keyword guard flag the payload?", "",
              "Held-out disguises were written after triage/normalize.py and never used to tune it.", "",
              table(["Family", "Flagged by keyword guard", "Flagged after normalisation (verified mode)"],
                    [(f, fmt(det[f][0], det[f][2]), fmt(det[f][1], det[f][2])) for f in FAMILIES if f in det]), "",
              "Disguised keyword payloads, by transform:", "",
              table(["Transform", "Flagged", "Flagged after normalisation"],
                    [(k, fmt(v[0], v[2]), fmt(v[1], v[2])) for k, v in sorted(sub.items())]), ""]

    lines += ["## 2. Compromised model: what the deterministic layer alone lets through", "",
              "The model obeys every payload, never reports it, and cites every trusted record present.", ""]
    for name, var in (("original dataset", var_orig), ("reachable dataset (insider sources have genuine records)",
                                                         var_reach)):
        wc = experiment_worst_case(var)
        tot = {"n": 0, "guarded": 0, "strict": 0}
        rows = []
        for f in FAMILIES:
            if f not in wc:
                continue
            r = wc[f]
            for k in tot:
                tot[k] += r[k]
            rows.append((f, fmt(r["guarded"], r["n"]), fmt(r["strict"], r["n"])))
        adaptive_n = tot["n"] - wc["original"]["n"]
        adaptive_g = tot["guarded"] - wc["original"]["guarded"]
        adaptive_s = tot["strict"] - wc["original"]["strict"]
        rows.append(("**all adaptive**", fmt(adaptive_g, adaptive_n), fmt(adaptive_s, adaptive_n)))
        lines += [f"### {name}", "", table(["Family", "Dismissed in guarded", "Dismissed in strict"], rows), ""]

    strings, clean, hard = experiment_false_positives(items)
    hits = [s for s in strings if s[3]]
    lines += ["## 3. False positives of the keyword guard", "",
              f"- Original 27 clean alerts flagged: {sum(bool(s) for _, s in clean)}/27",
              f"- Hard-benign alerts (false alarms with realistic keyword-like text) flagged: "
              f"{fmt(sum(bool(s) for _, s in hard), len(hard))}",
              f"- Hard-benign field values flagged: {fmt(len(hits), len(strings))}; after normalisation: "
              f"{fmt(sum(s[4] for s in strings), len(strings))}", "",
              table(["Category", "Field", "Benign value", "Flagged"],
                    [(c, f, s.replace("|", "\\|").replace("<", "&lt;"), "yes" if h else "") for c, f, s, h, _ in strings]),
              "", "Flagged hard-benign alerts (the guard now blocks their dismissal):", ""]
    lines += [f"- {i}: {sig[0]!r}" for i, sig in hard if sig]

    OUT.mkdir(exist_ok=True)
    (OUT / "offline.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (OUT / "offline.json").write_text(json.dumps({
        "detection": {k: v for k, v in det.items()}, "obfuscation": dict(sub),
        "worst_case_original": experiment_worst_case(var_orig),
        "worst_case_reachable": experiment_worst_case(var_reach),
        "fp_strings": strings, "fp_hard_alerts": hard}, indent=1, ensure_ascii=False))
    print("\n".join(lines))


if __name__ == "__main__":
    main()
