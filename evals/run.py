"""Run the eval set across models, check release gates, and append to quality history.

Usage:
  uv run python -m evals.run --models anthropic/claude-sonnet-5.5 deepseek/deepseek-v4.1-flash --repeats 3
"""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import subprocess
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from evals.acceptance import check
from evals.cases import CASES
from policy_copilot.generate import SYSTEM_PROMPT, generate
from policy_copilot.policy import matches

RESULTS = Path(__file__).parent / "results"
HISTORY = Path(__file__).parent / "history.jsonl"
SAFETY_IDS = {c["id"] for c in CASES if c["id"].startswith("safe-")}


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


def run_model(model: str, repeats: int) -> list[dict]:
    def one(job):
        case, rep = job
        res = generate(case["request"], model)
        passed, why = score(case, res)
        return {"case": case["id"], "repeat": rep, "passed": passed, "failure": why,
                "latency_s": round(res.latency_s, 2), "cost_usd": res.cost_usd, "repaired": res.repaired,
                "warnings": res.lint_warnings,
                "policy": res.draft.policy.model_dump() if res.draft and res.draft.policy else None,
                "clarification": res.draft.clarification_needed if res.draft else None, "raw": res.raw}
    jobs = [(c, r) for r in range(repeats) for c in CASES]
    with ThreadPoolExecutor(max_workers=6) as pool:
        return list(pool.map(one, jobs))


def summarize(model: str, rows: list[dict]) -> dict:
    lat = sorted(r["latency_s"] for r in rows)
    by_case = defaultdict(list)
    for r in rows:
        by_case[r["case"]].append(r["passed"])
    failures = Counter(r["failure"].split(" (")[0] for r in rows if not r["passed"])
    safety = [r["passed"] for r in rows if r["case"] in SAFETY_IDS]
    return {
        "model": model,
        "attempts": len(rows),
        "pass_rate": round(sum(r["passed"] for r in rows) / len(rows), 3),
        "consistency": round(sum(len(set(v)) == 1 for v in by_case.values()) / len(by_case), 3),
        "safety_pass_rate": round(sum(safety) / len(safety), 3) if safety else 1.0,
        "too_permissive": failures.get("too_permissive", 0),
        "unparseable_output": failures.get("unparseable_output", 0),
        "p50_latency_s": statistics.median(lat),
        "p95_latency_s": lat[int(0.95 * (len(lat) - 1))],
        "cost_per_request_usd": round(sum(r["cost_usd"] for r in rows) / len(rows), 5),
        "repairs": sum(r["repaired"] for r in rows),
        "failures": dict(failures),
    }


def git_sha() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], text=True).strip()
    except Exception:
        return "unknown"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="+", required=True)
    ap.add_argument("--repeats", type=int, default=3, help="runs per case, to measure consistency")
    args = ap.parse_args()
    RESULTS.mkdir(exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    prompt_hash = hashlib.sha256(SYSTEM_PROMPT.encode()).hexdigest()[:8]
    out, any_ship = {}, False

    print("| Model | Pass | Consistency | Safety | Too permissive | p95 s | $/req | Ship? |")
    print("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for model in args.models:
        rows = run_model(model, args.repeats)
        s = summarize(model, rows)
        ship, reasons = check(s)
        any_ship |= ship
        out[model] = {"summary": s, "ship": ship, "reasons": reasons, "rows": rows}
        print(f"| {model} | {s['pass_rate']:.0%} | {s['consistency']:.0%} | {s['safety_pass_rate']:.0%} | "
              f"{s['too_permissive']} | {s['p95_latency_s']:.1f} | {s['cost_per_request_usd']:.4f} | "
              f"{'yes' if ship else 'no'} |")
        with HISTORY.open("a") as f:
            f.write(json.dumps({"time": stamp, "git": git_sha(), "prompt": prompt_hash,
                                "repeats": args.repeats, **s, "ship": ship}) + "\n")

    for model, data in out.items():
        for reason in data["reasons"]:
            print(f"GATE {model}: {reason}")
        for r in data["rows"]:
            if not r["passed"]:
                print(f"FAIL {model} {r['case']} (rep {r['repeat']}): {r['failure']}")
    (RESULTS / f"{stamp}.json").write_text(json.dumps(out, indent=2, default=str))
    print(f"\nFull results: {RESULTS / (stamp + '.json')}  |  history: {HISTORY}")
    sys.exit(0 if any_ship else 1)


if __name__ == "__main__":
    main()
