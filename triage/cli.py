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
        provider = providers.from_settings(args.provider, args.model, args.base_url)
    except ValueError as e:
        sys.exit(f"error: {e}")
    print(f"Model {provider.name} at {getattr(provider, 'url', '?')}", file=sys.stderr)   # a wrong target is obvious
    return provider


def cmd_alert(args):
    alert = json.loads(Path(args.file).read_text(encoding="utf-8"))
    alert = alert.get("alert", alert)       # accepts a dataset line or a bare alert
    verdict = triage(alert, _provider(args), args.mode)
    print(json.dumps(verdict.to_dict(), indent=2, ensure_ascii=False))


def _report_name(results, cassette=None):
    """results/<name>.cassette.json, <name>.md and <name>.json belong together."""
    if cassette:
        return Path(cassette).name.removesuffix(".json").removesuffix(".cassette")
    return results["model"].replace("/", "_").replace(":", "_").replace(" ", "_")


def _write_outputs(results, out, slug):
    out.mkdir(parents=True, exist_ok=True)
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
    final = Path(args.record) if args.record else None
    if final:
        # Recorded into a .partial file and renamed only when the run completes,
        # so an interrupted run never leaves a cassette that looks finished.
        partial = final.with_name(final.name + ".partial")
        provider = providers.RecordingProvider(provider, partial)
        if provider.resumed:
            print(f"Resuming {partial.name}: {provider.resumed} answers already recorded", file=sys.stderr)
    results = evaluate.run(args.dataset, provider, modes=args.modes, workers=args.workers, progress=_progress)
    if final and provider.failed:
        # Unanswered prompts would be scored as "needs investigation" and look like caution
        sys.exit(f"error: {provider.failed} prompts got no answer (timeout or outage), so no report was written.\n"
                 f"The {len(provider.answers['answers'])} answers so far are saved in {partial}; "
                 "run the same command again to ask only the missing ones (for a local model, try --workers 1).")
    if final:
        partial.replace(final)
    _write_outputs(results, Path(args.out), _report_name(results, final))


def cmd_replay(args):
    os.environ["TRIAGE_BOUNDARY_SECRET"] = EVAL_BOUNDARY_SECRET
    provider = providers.ReplayProvider(Path(args.cassette))
    results = evaluate.run(args.dataset, provider, modes=args.modes, workers=1)
    if provider.missing:
        # An unfinished recording, or one made with other prompts: its numbers would be wrong
        sys.exit(f"error: {args.cassette} has no answer for {provider.missing} prompts; "
                 "it is unfinished or from another release")
    _write_outputs(results, Path(args.out), _report_name(results, args.cassette))


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
