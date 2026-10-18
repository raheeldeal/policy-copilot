# policy-copilot

Plain English → [Turnkey](https://docs.turnkey.com/concepts/policies/language) wallet policies, with an eval harness that executes every generated policy against test transactions before it ships.

> "Allow user-1111 to send less than 1 ETH to 0xa1a1… on mainnet"
> → `activity.kind == 'SIGN_TRANSACTION' && eth.tx.chain_id == 1 && eth.tx.to == '0xa1a1…' && eth.tx.value < 1000000000000000000`

Unofficial; not affiliated with Turnkey.

## Why this is hard

Policies are security-critical config. A policy that parses but is one character too loose (`<=` vs `<`, a missing `chain_id`, an allowlist check on the wrong field) silently grants access. So the bar isn't "looks right"; it's "behaves right on real requests."

## How it works

1. **Generate:** any model via OpenRouter returns a structured draft: a policy, or a clarification question when the request is too vague to encode safely.
2. **Lint:** static checks (parse errors, unknown identifiers, consensus/condition misuse, always-true ALLOW, missing chain scope, mixed-case addresses). Lint errors trigger one repair pass.
3. **Evaluate:** an independent implementation of the policy expression language runs the policy against fixtures, which are request contexts the policy must allow or block.

## Evals

`evals/cases.py` has 29 cases across access control, export, Ethereum signing and safety. Safety cases cover vague requests, prompt injection and unbounded amounts. Each case has a reference policy and 2–4 fixtures. A generated policy passes only if it lints clean, has the right effect and gets every fixture right.

Failures are categorized as `too_permissive`, `too_strict`, `runtime_error`, `lint_error`, `wrong_effect`, `should_have_asked`, `asked_instead_of_answering` and `unparseable_output`. The categories are the point: "where the model breaks" is a measured, named list, not a vibe.

```bash
uv run pytest                      # reference policies must pass their own fixtures
uv run python -m evals.run --models anthropic/claude-sonnet-5.5 deepseek/deepseek-v4.1-flash
```

Results (pass rate, p50/p95 latency, cost, repairs, failure categories) are written to `evals/results/`.

## Assumptions to verify against Turnkey's engine

- 0x-hex strings compare case-insensitively in this evaluator.
- Fixture activity shapes (`kind`, `type`, `resource`, `action`, `params`) follow the docs' examples. Signing is targeted via `activity.kind`.
- `&&` / `||` don't short-circuit (per the docs), and any evaluation error makes the outcome ERROR.

## Roadmap

- [ ] Baseline across 3–4 models; pick a default and a cheap router tier
- [ ] Solana and EIP-712 cases
- [ ] MCP server so Claude/Cursor users can draft and check policies in-editor
- [ ] Grow the eval set from real user requests
