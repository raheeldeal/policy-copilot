"""Run the eval set across models and write a results table.

Usage: uv run python -m evals.run --models anthropic/claude-sonnet-5.5 deepseek/deepseek-v4.1-flash
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from evals.cases import CASES
from policy_copilot.generate import generate
from policy_copilot.policy import matches

RESULTS = Path(__file__).parent / "results"


def score(case: dict, res) -> tuple[bool, str]:
    """Return (passed, failure_category)."""
    if res.error:
        return False, "unparseable_output"
    d = res.draft
    if case.get("expect_clarification"):
        return (bool(d.clarification_needed) and d.policy is None), "should_have_asked"
    if d.policy is None:
        if case.get("allow_clarification") and d.clarification_needed:
            return True, ""
        return False, "asked_instead_of_answering"
    if res.lint_errors:
        return False, "lint_error"
    if d.policy.effect != case["gold"]["effect"]:
        return False, "wrong_effect"
    for label, ctx, expected in case["fixtures"]:
        outcome = matches(d.policy, ctx)
        if outcome == "ERROR":
            return False, f"runtime_error ({label})"
        if (outcome == "MATCH") != expected:
            return False, ("too_permissive" if outcome == "MATCH" else "too_strict") + f" ({label})"
    return True, ""


def run_model(model: str) -> list[dict]:
    def one(case):
        res = generate(case["request"], model)
        passed, why = score(case, res)
        return {"case": case["id"], "passed": passed, "failure": why, "latency_s": round(res.latency_s, 2),
                "cost_usd": res.cost_usd, "repaired": res.repaired, "warnings": res.lint_warnings,
                "policy": res.draft.policy.model_dump() if res.draft and res.draft.policy else None,
                "clarification": res.draft.clarification_needed if res.draft else None, "raw": res.raw}
    with ThreadPoolExecutor(max_workers=6) as pool:
        return list(pool.map(one, CASES))


def summarize(model: str, rows: list[dict]) -> dict:
    lat = sorted(r["latency_s"] for r in rows)
    return {"model": model, "pass": sum(r["passed"] for r in rows), "total": len(rows),
            "p50_latency_s": statistics.median(lat), "p95_latency_s": lat[int(0.95 * (len(lat) - 1))],
            "cost_usd": round(sum(r["cost_usd"] for r in rows), 4),
            "repairs": sum(r["repaired"] for r in rows),
            "failures": Counter(r["failure"].split(" (")[0] for r in rows if not r["passed"])}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="+", required=True)
    args = ap.parse_args()
    RESULTS.mkdir(exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    out = {}
    for model in args.models:
        rows = run_model(model)
        out[model] = {"summary": summarize(model, rows), "rows": rows}
    (RESULTS / f"{stamp}.json").write_text(json.dumps(out, indent=2, default=str))

    print("| Model | Pass | p50 s | p95 s | Cost $ | Repairs | Top failures |")
    print("| --- | --- | --- | --- | --- | --- | --- |")
    for model, data in out.items():
        s = data["summary"]
        top = ", ".join(f"{k} x{v}" for k, v in s["failures"].most_common(3)) or "none"
        print(f"| {model} | {s['pass']}/{s['total']} | {s['p50_latency_s']:.1f} | {s['p95_latency_s']:.1f} | "
              f"{s['cost_usd']:.4f} | {s['repairs']} | {top} |")
    for model, data in out.items():
        for r in data["rows"]:
            if not r["passed"]:
                print(f"FAIL {model} {r['case']}: {r['failure']}")
    print(f"\nFull results: {RESULTS / (stamp + '.json')}")


if __name__ == "__main__":
    main()
