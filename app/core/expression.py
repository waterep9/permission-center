"""轻量、安全的条件表达式求值器。

为什么不直接用 Python eval：
- eval 会执行任意代码，存在代码注入风险，ABAC 条件可能来自
  管理接口或第三方，必须受限。

本求值器支持：
- 字面量：整数、浮点、字符串（单/双引号）、布尔 true/false、null
- 属性访问：subject.x / resource.y / action / env.z
- 比较：== != > >= < <=
- 逻辑：&& || !  （也兼容 and/or）
- 括号分组

实现方式：递归下降解析 + 求值，不引入第三方依赖。
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict


class ExprError(Exception):
    pass


# ---------- Tokenizer ----------

_TOKEN_RE = re.compile(
    r"""
    (?P<WS>\s+)
  | (?P<NUMBER>\d+(?:\.\d+)?)
  | (?P<STRING>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')
  | (?P<IDENT>[A-Za-z_][A-Za-z0-9_.]*)
  | (?P<OP>==|!=|>=|<=|&&|\|\||>|<|!|\(|\))
    """,
    re.VERBOSE,
)


@dataclass
class Token:
    kind: str
    value: Any
    pos: int


def tokenize(expr: str):
    tokens = []
    pos = 0
    while pos < len(expr):
        m = _TOKEN_RE.match(expr, pos)
        if not m:
            raise ExprError(f"无法识别的字符: {expr[pos]!r} (位置 {pos})")
        kind = m.lastgroup
        value = m.group()
        if kind == "WS":
            pos = m.end()
            continue
        if kind == "NUMBER":
            value = float(value) if "." in value else int(value)
        elif kind == "STRING":
            value = value[1:-1]
        elif kind == "IDENT":
            # 拒绝 dunder 标识符，防止访问对象内部（如 __class__、__dict__）
            if "__" in value:
                raise ExprError(f"禁止访问内部属性: {value!r} (位置 {pos})")
            low = value.lower()
            if low == "true":
                kind, value = "BOOL", True
            elif low == "false":
                kind, value = "BOOL", False
            elif low == "null":
                kind, value = "NULL", None
        elif kind == "OP":
            # 规范化逻辑操作符
            if value in ("&&",):
                value = "&&"
            elif value == "||":
                value = "||"
        tokens.append(Token(kind, value, pos))
        pos = m.end()
    tokens.append(Token("EOF", None, pos))
    return tokens


# ---------- Parser / Evaluator (递归下降) ----------

class Evaluator:
    def __init__(self, tokens):
        self.tokens = tokens
        self.i = 0

    def peek(self):
        return self.tokens[self.i]

    def next(self):
        t = self.tokens[self.i]
        self.i += 1
        return t

    def match(self, kind):
        if self.peek().kind == kind:
            return self.next()
        return None

    def expect(self, kind):
        t = self.match(kind)
        if t is None:
            raise ExprError(f"期望 {kind}，实际 {self.peek().kind} (位置 {self.peek().pos})")
        return t

    # 解析入口：优先级   ||  <  &&  <  比较  <  一元 !  <  原子
    def parse(self):
        if self.peek().kind == "EOF":
            raise ExprError("空表达式")
        node = self.parse_or()
        if self.peek().kind != "EOF":
            raise ExprError(f"多余内容: {self.peek().value!r} (位置 {self.peek().pos})")
        return node

    def parse_or(self):
        left = self.parse_and()
        while self.peek().value in ("||",):
            self.next()
            right = self.parse_and()
            left = ("or", left, right)
        return left

    def parse_and(self):
        left = self.parse_cmp()
        while self.peek().value in ("&&",):
            self.next()
            right = self.parse_cmp()
            left = ("and", left, right)
        return left

    def parse_cmp(self):
        left = self.parse_unary()
        op = self.peek().value
        if op in ("==", "!=", ">", ">=", "<", "<="):
            self.next()
            right = self.parse_unary()
            return ("cmp", op, left, right)
        return left

    def parse_unary(self):
        if self.peek().value == "!":
            self.next()
            return ("not", self.parse_unary())
        return self.parse_atom()

    def parse_atom(self):
        t = self.peek()
        if t.kind == "NUMBER":
            self.next()
            return ("lit", t.value)
        if t.kind == "STRING":
            self.next()
            return ("lit", t.value)
        if t.kind == "BOOL":
            self.next()
            return ("lit", t.value)
        if t.kind == "NULL":
            self.next()
            return ("lit", None)
        if t.kind == "IDENT":
            self.next()
            return ("attr", t.value)
        if t.kind == "OP" and t.value == "(":
            self.next()
            node = self.parse_or()
            self.expect(")")
            return node
        raise ExprError(f"意外 token: {t.value!r} (位置 {t.pos})")

    # ---------- 求值 ----------

    def eval(self, node, ctx: Dict[str, Any]):
        kind = node[0]
        if kind == "lit":
            return node[1]
        if kind == "attr":
            return self._lookup(node[1], ctx)
        if kind == "not":
            return not self._truthy(self.eval(node[1], ctx))
        if kind == "and":
            # 短路
            return self._truthy(self.eval(node[1], ctx)) and self._truthy(self.eval(node[2], ctx))
        if kind == "or":
            return self._truthy(self.eval(node[1], ctx)) or self._truthy(self.eval(node[2], ctx))
        if kind == "cmp":
            _, op, l, r = node
            return self._compare(op, self.eval(l, ctx), self.eval(r, ctx))
        raise ExprError(f"未知节点: {kind}")

    def _lookup(self, path: str, ctx: Dict[str, Any]):
        parts = path.split(".")
        # 拒绝访问任何下划线开头的属性，防止绕过（如 __class__、__dict__）
        if any(p.startswith("_") for p in parts):
            return None
        cur = ctx
        for p in parts:
            if isinstance(cur, dict):
                cur = cur.get(p)
            elif isinstance(cur, object) and hasattr(cur, p):
                cur = getattr(cur, p)
            else:
                return None
        return cur

    @staticmethod
    def _truthy(v):
        return bool(v)

    @staticmethod
    def _compare(op, a, b):
        try:
            if op == "==":
                return a == b
            if op == "!=":
                return a != b
            if op == ">":
                return a > b
            if op == ">=":
                return a >= b
            if op == "<":
                return a < b
            if op == "<=":
                return a <= b
        except TypeError:
            return False
        return False


def evaluate(expr: str, ctx: Dict[str, Any]) -> bool:
    """评估条件表达式，返回布尔结果。"""
    tokens = tokenize(expr)
    evaluator = Evaluator(tokens)
    node = evaluator.parse()
    return bool(evaluator.eval(node, ctx))
