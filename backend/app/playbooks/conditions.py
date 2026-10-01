"""
SOAR Playbook Engine Deterministic Condition Evaluator.

Evaluates step execution pre-conditions against workflow context variables using
comparison operators (==, !=, >, >=, <, <=, IN, CONTAINS) and logical compositions (AND, OR).
Includes severity hierarchy awareness and safe handling of missing context properties.
"""

from typing import Dict, Any, List, Union


class ConditionEvaluator:
    """Deterministic condition evaluation engine for playbook steps."""

    SEVERITY_WEIGHTS: Dict[str, int] = {
        "INFORMATIONAL": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    @classmethod
    def evaluate(cls, conditions: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Evaluate a conditions payload against the execution context. Empty conditions evaluate to True."""
        if not conditions:
            return True

        # Check if root is a logical compound operator (AND / OR)
        operator = str(conditions.get("operator", "AND")).upper()
        rules = conditions.get("rules")

        if isinstance(rules, list):
            if operator == "OR":
                return any(cls._evaluate_single_rule(rule, context) for rule in rules)
            else:  # AND by default
                return all(cls._evaluate_single_rule(rule, context) for rule in rules)

        # Single rule dictionary case
        if "field" in conditions and "operator" in conditions:
            return cls._evaluate_single_rule(conditions, context)

        return True

    @classmethod
    def _evaluate_single_rule(cls, rule: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Evaluate a single rule dictionary against context."""
        if not isinstance(rule, dict):
            return False

        # Nested compound rule recursion
        if "rules" in rule:
            return cls.evaluate(rule, context)

        field = rule.get("field")
        op = str(rule.get("operator", "==")).upper()
        expected = rule.get("value")

        if not field:
            return True  # Malformed rule defaults to passing or ignoring

        actual = context.get(field)
        if actual is None:
            # Also check case-insensitive context keys
            actual = next((v for k, v in context.items() if k.lower() == str(field).lower()), None)

        if actual is None:
            return False

        return cls._compare(actual, op, expected)

    @classmethod
    def _compare(cls, actual: Any, op: str, expected: Any) -> bool:
        """Execute typed operator comparison."""
        # Convert Enum instances to string values if applicable
        if hasattr(actual, "value"):
            actual = actual.value
        if hasattr(expected, "value"):
            expected = expected.value

        actual_str = str(actual).upper()
        expected_str = str(expected).upper()

        # Severity level hierarchy special handling
        if actual_str in cls.SEVERITY_WEIGHTS and expected_str in cls.SEVERITY_WEIGHTS:
            act_w = cls.SEVERITY_WEIGHTS[actual_str]
            exp_w = cls.SEVERITY_WEIGHTS[expected_str]
            if op == "==":
                return act_w == exp_w
            elif op == "!=":
                return act_w != exp_w
            elif op == ">":
                return act_w > exp_w
            elif op == ">=":
                return act_w >= exp_w
            elif op == "<":
                return act_w < exp_w
            elif op == "<=":
                return act_w <= exp_w

        # Numeric comparison attempt
        try:
            act_num = float(actual)
            exp_num = float(expected)
            if op == "==":
                return act_num == exp_num
            elif op == "!=":
                return act_num != exp_num
            elif op == ">":
                return act_num > exp_num
            elif op == ">=":
                return act_num >= exp_num
            elif op == "<":
                return act_num < exp_num
            elif op == "<=":
                return act_num <= exp_num
        except (ValueError, TypeError):
            pass

        # String / Sequence operations
        if op in ("==", "EQUALS"):
            return actual_str == expected_str
        elif op in ("!=", "NOT_EQUALS"):
            return actual_str != expected_str
        elif op == "IN":
            if isinstance(expected, (list, tuple, set)):
                expected_list = [str(x).upper() for x in expected]
                return actual_str in expected_list
            return actual_str in expected_str
        elif op == "CONTAINS":
            if isinstance(actual, (list, tuple, set)):
                actual_list = [str(x).upper() for x in actual]
                return expected_str in actual_list
            return expected_str in actual_str

        return False
