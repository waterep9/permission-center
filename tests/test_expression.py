"""表达式求值器单元测试。"""
import pytest

from app.core.expression import evaluate, ExprError


def test_literal_and_comparison():
    assert evaluate("5 > 3", {}) is True
    assert evaluate("3 >= 5", {}) is False
    assert evaluate("1 == 1", {}) is True
    assert evaluate("1 != 2", {}) is True


def test_string_and_bool():
    assert evaluate('"a" == "a"', {}) is True
    assert evaluate("true && true", {}) is True
    assert evaluate("false || true", {}) is True
    assert evaluate("!false", {}) is True


def test_attribute_lookup():
    ctx = {"subject": {"level": 5, "dept": "eng"}, "resource": {"owner_id": 42}}
    assert evaluate("subject.level >= 3", ctx) is True
    assert evaluate("subject.dept == 'eng'", ctx) is True
    assert evaluate("resource.owner_id == 42", ctx) is True


def test_cross_attribute():
    ctx = {"subject": {"id": 7}, "resource": {"owner_id": 7}}
    assert evaluate("resource.owner_id == subject.id", ctx) is True


def test_logic_combination():
    ctx = {"subject": {"level": 5}, "resource": {"sensitive": True}}
    assert evaluate("subject.level >= 3 && resource.sensitive == true", ctx) is True
    assert evaluate("subject.level >= 10 || resource.sensitive == true", ctx) is True


def test_missing_attribute_is_none():
    assert evaluate("subject.unknown == null", {}) is True


def test_invalid_expression_raises():
    with pytest.raises(ExprError):
        evaluate("", {})
    with pytest.raises(ExprError):
        evaluate("1 +", {})
    with pytest.raises(ExprError):
        evaluate("__import__('os')", {})


def test_no_code_execution():
    # 确保不含危险函数调用
    with pytest.raises(ExprError):
        evaluate("subject.__class__", {})
