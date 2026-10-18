"""Policy schema, outcome evaluation and safety lint."""

from __future__ import annotations

import re
from typing import Literal, Optional

from pydantic import BaseModel, Field

from .expr import ROOTS, PolicyError, evaluate, free_names, parse


class Policy(BaseModel):
    policyName: str
    effect: Literal["EFFECT_ALLOW", "EFFECT_DENY"]
    consensus: Optional[str] = None
    condition: Optional[str] = None
    notes: str = ""


class Draft(BaseModel):
    """What the model returns: a policy, or a request for clarification."""

    policy: Optional[Policy] = None
    clarification_needed: Optional[str] = Field(
        None, description="Set instead of policy when the request is too vague or unsafe to encode."
    )
    assumptions: list[str] = []


def matches(policy: Policy, ctx: dict) -> str:
    """MATCH if consensus and condition both hold, NO_MATCH if either is false, ERROR on any failure."""
    try:
        for expr in (policy.consensus, policy.condition):
            if expr is None or not expr.strip():
                continue
            if evaluate(parse(expr), ctx) is not True:
                return "NO_MATCH"
        return "MATCH"
    except PolicyError:
        return "ERROR"


ADDR_RE = re.compile(r"'0x[0-9a-fA-F]{40}'")


def lint(policy: Policy) -> tuple[list[str], list[str]]:
    """Static checks. Returns (errors, warnings). Errors mean the policy should not ship."""
    errors, warnings = [], []
    for field in ("consensus", "condition"):
        expr = getattr(policy, field)
        if expr is None or not expr.strip():
            continue
        try:
            names = free_names(parse(expr))
        except PolicyError as e:
            errors.append(f"{field}: parse error: {e}")
            continue
        unknown = names - ROOTS
        if unknown:
            errors.append(f"{field}: unknown identifiers {sorted(unknown)}")
        if field == "consensus" and names - {"approvers", "credentials"}:
            errors.append("consensus may only reference approvers and credentials")
        if field == "condition" and names & {"approvers", "credentials"}:
            errors.append("condition must not reference approvers/credentials; move that to consensus")
        for addr in ADDR_RE.findall(expr):
            if addr != addr.lower():
                warnings.append(f"{field}: mixed-case address {addr}; prefer lowercase")

    cond = (policy.condition or "").strip()
    if policy.effect == "EFFECT_ALLOW":
        if cond in ("", "true"):
            errors.append("ALLOW policy with an empty or always-true condition is over-permissive")
        if not (policy.consensus or "").strip():
            warnings.append("ALLOW policy has no consensus: any user in the org can trigger it")
        if "eth.tx" in cond and "chain_id" not in cond:
            warnings.append("ALLOW on eth.tx without chain_id applies on every EVM chain")
    return errors, warnings
