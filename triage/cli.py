"""
Command line.

    triage alert   <alert.json>               triage one alert, print the verdict
    triage eval    [--modes ...] [--record F]  run the evaluation, write a report
    triage replay  <cassette.json>             re-run an evaluation from recorded answers

Provider: --provider deepseek|deepseek-pro|kimi|ollama (or TRIAGE_BASE_URL and
TRIAGE_MODEL), with the API key in TRIAGE_API_KEY. The key is read from the
environment only, never from a file or the command line.
"""

import argparse
import json
import os
import sys
from pathlib import Path

from triage import evaluate, providers
from triage.engine import MODES, triage

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "datasets" / "alerts.jsonl"
# Fixed during evaluation so prompts, and therefore recorded answers, repeat exactly
EVAL_BOUNDARY_SECRET = "evaluation"  # noqa: S105 - not a credential


def _provider(args):
    try:
        return providers.from_settings(args.provider, args.model, args.base_url)
    except ValueError as e:
        sys.exit(f"error: {e}")


def cmd_alert(args):
    alert = json.loads(Path(args.file).read_text(encoding="utf-8"))
    alert = alert.get("alert", alert)       # accepts a dataset line or a bare alert
    verdict = triage(alert, _provider(args), args.mode)
    print(json.dumps(verdict.to_dict(), indent=2, ensure_ascii=False))


def _write_outputs(results, out):
    out.mkdir(parents=True, exist_ok=True)
    slug = results["model"].replace("/", "_").replace(":", "_").replace(" ", "_")
    (out / f"{slug}.json").write_text(json.dumps(results, indent=1, ensure_ascii=False))
    (out / f"{slug}.md").write_text(evaluate.report(results))
    print(evaluate.report(results))
    print(f"Saved {out / (slug + '.md')} and {slug}.json")


def _progress(done, total):
    if done == total or done % 10 == 0:
        print(f"\r  {done}/{total} answers", end="" if done < total else "\n", file=sys.stderr, flush=True)


def cmd_eval(args):
    os.environ["TRIAGE_BOUNDARY_SECRET"] = EVAL_BOUNDARY_SECRET
    provider = _provider(args)
    if args.record:
        provider = providers.RecordingProvider(provider, Path(args.record))
    results = evaluate.run(args.dataset, provider, modes=args.modes, workers=args.workers, progress=_progress)
    _write_outputs(results, Path(args.out))


def cmd_replay(args):
    os.environ["TRIAGE_BOUNDARY_SECRET"] = EVAL_BOUNDARY_SECRET
    provider = providers.ReplayProvider(Path(args.cassette))
    results = evaluate.run(args.dataset, provider, modes=args.modes, workers=1)
    _write_outputs(results, Path(args.out))


def main(argv=None):
    parser = argparse.ArgumentParser(prog="triage", description="AI triage for security alerts, measured and attacked.")
    sub = parser.add_subparsers(dest="command", required=True)

    def provider_args(p):
        p.add_argument("--provider", choices=sorted(providers.PRESETS), help="model provider preset")
        p.add_argument("--model", help="override the preset's model name")
        p.add_argument("--base-url", help="override the preset's API address")

    p = sub.add_parser("alert", help="triage one alert")
    p.add_argument("file")
    p.add_argument("--mode", choices=MODES, default="guarded")
    provider_args(p)
    p.set_defaults(func=cmd_alert)

    for name, func in (("eval", cmd_eval), ("replay", cmd_replay)):
        p = sub.add_parser(name, help="run the evaluation" if name == "eval" else "re-run an evaluation from a cassette")
        if name == "replay":
            p.add_argument("cassette")
        else:
            provider_args(p)
            p.add_argument("--record", metavar="CASSETTE", help="save every answer, for replay in CI")
            p.add_argument("--workers", type=int, default=4, help="parallel requests (default 4)")
        p.add_argument("--dataset", default=str(DATASET))
        p.add_argument("--modes", nargs="+", choices=MODES, default=list(MODES))
        p.add_argument("--out", default=str(ROOT / "results"))
        p.set_defaults(func=func)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
