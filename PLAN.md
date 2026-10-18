# Plan

One product, built in public, that exercises the full surface of shipping agentic LLM products:
generation, evals, agent orchestration, coding agents, sandboxes, and developer distribution.

## Components

| # | Component | What it is |
| --- | --- | --- |
| 1 | **Copilot core** | Plain English → Turnkey policy. Structured output, lint, one repair pass, model routing |
| 2 | **Eval system** | 29+ cases executed against fixture transactions; named failure categories; release gates; repeats for consistency; history per commit and prompt version |
| 3 | **Multi-agent mode** | Drafter → red-team agent that hunts for counterexample transactions the policy wrongly allows → fixer, looped until the red team finds nothing. Compared head-to-head with single-shot on quality, cost and latency |
| 4 | **agent-bench** | Real roadmap tasks on this repo with hidden tests, run headless through Claude Code, Codex and Cursor in sandboxes. Varies context (repo guide vs none). Measures pass rate, cost, time and failure modes |
| 5 | **Distribution** | MCP server for Cursor/Claude users (individual) → CLI plus a GitHub Action that checks policy changes in PRs (team). Docs, releases, issues, contributing guide |
| 6 | **Writing** | Three posts built on the data: where models break on security config; single-agent vs multi-agent for verified generation; what coding agents get wrong on a real repo |

## Milestones (about 6 weeks)

| Week | Ship | Evidence produced |
| --- | --- | --- |
| 1 | Baseline across 4 models; failure taxonomy; acceptance gates live; default model plus cheap-tier router | Results table, `history.jsonl`, first post draft |
| 2 | Multi-agent mode (drafter / red team / fixer) on an agent framework; head-to-head eval | Quality vs cost vs latency comparison |
| 3 | agent-bench: 8–10 tasks, 2–3 coding agents, sandboxed runs, context variants | Bench results plus failure log |
| 4 | MCP server, CLI, GitHub Action; v0.1 release; launch in crypto-dev communities | Installs, users, first issues |
| 5 | Grow the eval set from real user requests; Solana and EIP-712; nightly eval in CI | Quality-over-time chart from real traffic |
| 6 | Posts published; contributor onboarding (good-first-issues); v0.2 | Contributors, stars, usage numbers |
