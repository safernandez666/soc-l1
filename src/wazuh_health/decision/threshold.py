"""Configurable threshold evaluator with streak support."""
from __future__ import annotations

import re
from collections import defaultdict, deque

from pydantic import BaseModel, ConfigDict

from src.wazuh_health.contracts import ProbeResult, ThresholdHit
from src.wazuh_health.contracts.probes import ProbeName, Severity

_OP_RE = re.compile(
    r"value\s*(?P<op>[<>]=?|==)\s*(?P<num>-?\d+(?:\.\d+)?)\s*"
    r"(?:streak\s*>=\s*(?P<streak>\d+))?"
)


class ThresholdRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    metric: str
    rule: str
    severity: Severity


class ThresholdEngine:
    def __init__(self, *, rules: dict[ProbeName, list[ThresholdRule]]) -> None:
        self._rules = rules
        self._streaks: dict[tuple, deque] = defaultdict(lambda: deque(maxlen=10))

    @staticmethod
    def _check(rule: str, value: float | int) -> tuple[bool, int]:
        m = _OP_RE.match(rule.strip())
        if not m:
            return (False, 1)
        op = m.group("op")
        num = float(m.group("num"))
        streak = int(m.group("streak") or 1)
        if op == "<":
            ok = value < num
        elif op == "<=":
            ok = value <= num
        elif op == ">":
            ok = value > num
        elif op == ">=":
            ok = value >= num
        elif op == "==":
            ok = value == num
        else:
            ok = False
        return (ok, streak)

    def evaluate(self, result: ProbeResult) -> list[ThresholdHit]:
        hits: list[ThresholdHit] = []
        for rule in self._rules.get(result.probe, []):
            if rule.metric not in result.metrics:
                continue
            value = result.metrics[rule.metric]
            ok, streak_required = self._check(rule.rule, value)
            key = (result.probe, rule.metric, rule.rule)
            history = self._streaks[key]
            history.append(ok)
            recent = list(history)[-streak_required:]
            if len(recent) == streak_required and all(recent):
                hits.append(ThresholdHit(
                    probe=result.probe,
                    metric=rule.metric,
                    value=value,
                    rule=rule.rule,
                    severity=rule.severity,
                ))
        return hits
