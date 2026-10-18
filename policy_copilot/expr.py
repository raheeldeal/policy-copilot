"""Parser and evaluator for a subset of the Turnkey policy language.

Covers what the eval set needs: field access, indexing and slicing, comparisons,
`in`, `&&` / `||` / `!`, list literals, and the list functions any / all / filter /
count / contains. Like Turnkey's engine, `&&` and `||` do NOT short-circuit: an error
in any clause errors the whole expression.

This is an independent re-implementation for testing generated policies. It is not
Turnkey's engine; see README "Assumptions" for behaviors to verify against the real one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

ROOTS = {
    "activity", "approvers", "credentials", "eth", "solana", "tron", "bitcoin", "tempo",
    "wallet", "wallets", "wallet_account", "private_key", "time",
}
LIST_FUNCS = {"any", "all", "filter"}
OTHER_FUNCS = {"count", "contains"}


class PolicyError(Exception):
    """Parse or evaluation error. Evaluation errors make the policy outcome ERROR."""


# ---------- tokenizer ----------

TOKEN_RE = re.compile(
    r"\s*(?:"
    r"(?P<num>\d+)"
    r"|(?P<str>'[^']*')"
    r"|(?P<op>&&|\|\||==|!=|<=|>=|\.\.|[<>!().,\[\]])"
    r"|(?P<ident>[A-Za-z_][A-Za-z0-9_]*)"
    r")"
)


@dataclass
class Tok:
    kind: str
    val: str


def tokenize(src: str) -> list[Tok]:
    if '"' in src:
        raise PolicyError("double-quoted strings are not allowed; use single quotes")
    toks, pos = [], 0
    src = src.rstrip()
    while pos < len(src):
        m = TOKEN_RE.match(src, pos)
        if not m or m.end() == pos:
            raise PolicyError(f"unexpected character at {pos}: {src[pos:pos + 10]!r}")
        pos = m.end()
        kind = m.lastgroup
        toks.append(Tok(kind, m.group(kind)))
    toks.append(Tok("eof", ""))
    return toks


# ---------- parser (AST = tuples) ----------

class Parser:
    def __init__(self, src: str):
        self.toks = tokenize(src)
        self.i = 0

    def peek(self) -> Tok:
        return self.toks[self.i]

    def take(self, val: str | None = None) -> Tok:
        t = self.toks[self.i]
        if val is not None and t.val != val:
            raise PolicyError(f"expected {val!r}, got {t.val!r}")
        self.i += 1
        return t

    def parse(self):
        node = self.or_()
        if self.peek().kind != "eof":
            raise PolicyError(f"unexpected token {self.peek().val!r}")
        return node

    def or_(self):
        node = self.and_()
        while self.peek().val == "||":
            self.take()
            node = ("or", node, self.and_())
        return node

    def and_(self):
        node = self.not_()
        while self.peek().val == "&&":
            self.take()
            node = ("and", node, self.not_())
        return node

    def not_(self):
        if self.peek().val == "!":
            self.take()
            return ("not", self.not_())
        return self.cmp()

    def cmp(self):
        node = self.postfix()
        t = self.peek()
        if t.val in ("==", "!=", "<", "<=", ">", ">=") or (t.kind == "ident" and t.val == "in"):
            self.take()
            return ("cmp", t.val, node, self.postfix())
        return node

    def postfix(self):
        node = self.primary()
        while True:
            t = self.peek()
            if t.val == ".":
                self.take()
                name = self.take().val
                if self.peek().val == "(":
                    self.take()
                    if name in LIST_FUNCS:
                        var = self.take()
                        if var.kind != "ident":
                            raise PolicyError(f"{name}() needs a variable name first")
                        self.take(",")
                        body = self.or_()
                        self.take(")")
                        node = ("listfn", name, node, var.val, body)
                    elif name in OTHER_FUNCS:
                        args = []
                        if self.peek().val != ")":
                            args.append(self.or_())
                        self.take(")")
                        node = ("fn", name, node, args)
                    else:
                        raise PolicyError(f"unknown function {name}()")
                else:
                    node = ("attr", node, name)
            elif t.val == "[":
                self.take()
                start = self.or_()
                if self.peek().val == "..":
                    self.take()
                    end = self.or_()
                    self.take("]")
                    node = ("slice", node, start, end)
                else:
                    self.take("]")
                    node = ("index", node, start)
            else:
                return node

    def primary(self):
        t = self.take()
        if t.kind == "num":
            return ("lit", int(t.val))
        if t.kind == "str":
            return ("lit", t.val[1:-1])
        if t.val == "(":
            node = self.or_()
            self.take(")")
            return node
        if t.val == "[":
            items = []
            while self.peek().val != "]":
                items.append(self.or_())
                if self.peek().val == ",":
                    self.take()
            self.take("]")
            return ("list", items)
        if t.kind == "ident":
            if t.val in ("true", "false"):
                return ("lit", t.val == "true")
            return ("name", t.val)
        raise PolicyError(f"unexpected token {t.val!r}")


def parse(src: str):
    if not src or not src.strip():
        raise PolicyError("empty expression")
    return Parser(src).parse()


def free_names(node, bound=frozenset()) -> set[str]:
    """Top-level identifiers the expression reads, excluding lambda variables."""
    kind = node[0]
    if kind == "name":
        return set() if node[1] in bound else {node[1]}
    if kind == "lit":
        return set()
    if kind == "listfn":
        return free_names(node[2], bound) | free_names(node[4], bound | {node[3]})
    out = set()
    for child in node[1:]:
        if isinstance(child, tuple):
            out |= free_names(child, bound)
        elif isinstance(child, list):
            for c in child:
                out |= free_names(c, bound)
    return out


# ---------- evaluator ----------

def _norm(v):
    # Assumption (verify against Turnkey): 0x-hex strings compare case-insensitively.
    if isinstance(v, str) and v.startswith("0x"):
        return v.lower()
    return v


def evaluate(node, env: dict[str, Any]):
    kind = node[0]
    if kind == "lit":
        return node[1]
    if kind == "list":
        return [evaluate(n, env) for n in node[1]]
    if kind == "name":
        if node[1] not in env:
            raise PolicyError(f"unknown name {node[1]!r}")
        return env[node[1]]
    if kind == "attr":
        obj = evaluate(node[1], env)
        if not isinstance(obj, dict) or node[2] not in obj:
            raise PolicyError(f"field {node[2]!r} not present")
        return obj[node[2]]
    if kind == "index":
        obj, key = evaluate(node[1], env), evaluate(node[2], env)
        try:
            return obj[key]
        except (KeyError, IndexError, TypeError):
            raise PolicyError(f"bad index {key!r}")
    if kind == "slice":
        obj, a, b = evaluate(node[1], env), evaluate(node[2], env), evaluate(node[3], env)
        if not isinstance(obj, (str, list)):
            raise PolicyError("slice on non-sequence")
        return obj[a:b]
    if kind == "not":
        v = evaluate(node[1], env)
        if not isinstance(v, bool):
            raise PolicyError("! on non-bool")
        return not v
    if kind in ("and", "or"):
        a, b = evaluate(node[1], env), evaluate(node[2], env)  # no short-circuit
        if not (isinstance(a, bool) and isinstance(b, bool)):
            raise PolicyError(f"{kind} on non-bool")
        return (a and b) if kind == "and" else (a or b)
    if kind == "cmp":
        op, a, b = node[1], _norm(evaluate(node[2], env)), _norm(evaluate(node[3], env))
        if op == "in":
            if not isinstance(b, list):
                raise PolicyError("'in' needs a list on the right")
            return a in [_norm(x) for x in b]
        if op in ("==", "!="):
            if type(a) is not type(b):
                raise PolicyError(f"type mismatch: {type(a).__name__} {op} {type(b).__name__}")
            return (a == b) if op == "==" else (a != b)
        if not (isinstance(a, int) and isinstance(b, int)) or isinstance(a, bool) or isinstance(b, bool):
            raise PolicyError(f"ordering comparison {op} needs numbers")
        return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]
    if kind == "listfn":
        name, seq, var, body = node[1], evaluate(node[2], env), node[3], node[4]
        if not isinstance(seq, list):
            raise PolicyError(f"{name}() on non-list")
        results = [(item, evaluate(body, {**env, var: item})) for item in seq]
        if any(not isinstance(r, bool) for _, r in results):
            raise PolicyError(f"{name}() predicate must return bool")
        if name == "any":
            return any(r for _, r in results)
        if name == "all":
            return all(r for _, r in results)
        return [item for item, r in results if r]
    if kind == "fn":
        name, obj = node[1], evaluate(node[2], env)
        args = [evaluate(a, env) for a in node[3]]
        if name == "count":
            if not isinstance(obj, list):
                raise PolicyError("count() on non-list")
            return len(obj)
        if name == "contains":
            if not isinstance(obj, list) or len(args) != 1:
                raise PolicyError("contains() needs a list and one argument")
            return _norm(args[0]) in [_norm(x) for x in obj]
    raise PolicyError(f"cannot evaluate {kind}")
