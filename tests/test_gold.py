"""The reference policies must pass their own fixtures, or the eval set is wrong."""

import pytest

from evals.cases import CASES
from policy_copilot.expr import PolicyError, evaluate, parse
from policy_copilot.policy import Policy, lint, matches

GOLD = [c for c in CASES if c.get("gold")]


@pytest.mark.parametrize("case", GOLD, ids=[c["id"] for c in GOLD])
def test_gold_passes_fixtures(case):
    policy = Policy(policyName=case["id"], **case["gold"])
    errors, _ = lint(policy)
    assert errors == []
    for label, ctx, expected in case["fixtures"]:
        assert matches(policy, ctx) == ("MATCH" if expected else "NO_MATCH"), label


def test_no_short_circuit():
    # Turnkey evaluates both sides of && / ||, so an error on the right still errors.
    with pytest.raises(PolicyError):
        evaluate(parse("false && activity.missing == 1"), {"activity": {}})


def test_double_quotes_rejected():
    with pytest.raises(PolicyError):
        parse('activity.kind == "SIGN_TRANSACTION"')


def test_over_permissive_allow_is_an_error():
    errors, _ = lint(Policy(policyName="x", effect="EFFECT_ALLOW", condition="true"))
    assert errors
