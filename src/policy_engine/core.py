from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Sequence


class PolicyError(Exception):
    pass


class PolicySyntaxError(PolicyError):
    pass


class ConflictingPolicyError(PolicyError):
    pass


class Effect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class Subject:
    subject_id: str
    attributes: dict[str, Any] = field(default_factory=dict)

    def attr(self, name: str) -> Any:
        return self.attributes.get(name)


@dataclass(frozen=True)
class Resource:
    resource_type: str
    resource_id: str
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def qualified(self) -> str:
        return f"{self.resource_type}:{self.resource_id}"


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    effect: Effect
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    subject_condition: Callable[[Subject], bool] | None = None
    environment_condition: Callable[[dict[str, Any]], bool] | None = None
    priority: int = 0

    def __post_init__(self) -> None:
        if not self.actions or not self.resources:
            raise PolicySyntaxError(f"rule {self.rule_id!r} needs at least one action and resource")

    def matches_action(self, action: str) -> bool:
        return any(a == "*" or fnmatch.fnmatch(action, a) for a in self.actions)

    def matches_resource(self, resource: Resource) -> bool:
        qualified = resource.qualified
        return any(
            r == "*" or fnmatch.fnmatch(qualified, r) or fnmatch.fnmatch(resource.resource_type, r)
            for r in self.resources
        )

    def matches_subject(self, subject: Subject) -> bool:
        if self.subject_condition is None:
            return True
        return bool(self.subject_condition(subject))

    def matches_environment(self, env: dict[str, Any]) -> bool:
        if self.environment_condition is None:
            return True
        return bool(self.environment_condition(env))


DEFAULT_DENY = Effect.DENY


class PolicyEngine:
    def __init__(self, default_effect: Effect = DEFAULT_DENY,
                 deny_overrides: bool = True) -> None:
        self._rules: dict[str, PolicyRule] = {}
        self._default = default_effect
        self._deny_overrides = deny_overrides

    def add_rule(self, rule: PolicyRule) -> "PolicyEngine":
        if rule.rule_id in self._rules:
            raise ConflictingPolicyError(f"rule id reused: {rule.rule_id!r}")
        self._rules[rule.rule_id] = rule
        return self

    def remove_rule(self, rule_id: str) -> bool:
        return self._rules.pop(rule_id, None) is not None

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def matching_rules(self, subject: Subject, resource: Resource,
                       action: str, env: dict[str, Any] | None = None) -> list[PolicyRule]:
        environment = env or {}
        matched = [
            rule for rule in self._rules.values()
            if rule.matches_action(action)
            and rule.matches_resource(resource)
            and rule.matches_subject(subject)
            and rule.matches_environment(environment)
        ]
        matched.sort(key=lambda r: r.priority, reverse=True)
        return matched

    def authorize(self, subject: Subject, resource: Resource, action: str,
                  env: dict[str, Any] | None = None) -> tuple[Effect, list[str]]:
        matched = self.matching_rules(subject, resource, action, env)
        evaluated_ids = [rule.rule_id for rule in matched]
        if not matched:
            return self._default, []
        if self._deny_overrides:
            for rule in matched:
                if rule.effect == Effect.DENY:
                    return Effect.DENY, [rule.rule_id]
        first = matched[0]
        return first.effect, evaluated_ids

    def is_allowed(self, subject: Subject, resource: Resource, action: str,
                   env: dict[str, Any] | None = None) -> bool:
        effect, _ = self.authorize(subject, resource, action, env)
        return effect == Effect.ALLOW


def attribute_equals(attribute_name: str, expected: Any) -> Callable[[Subject], bool]:
    def condition(subject: Subject) -> bool:
        return subject.attr(attribute_name) == expected
    return condition


def attribute_in_group(attribute_name: str, group: set[Any]) -> Callable[[Subject], bool]:
    def condition(subject: Subject) -> bool:
        return subject.attr(attribute_name) in group
    return condition


def env_flag_enabled(flag: str) -> Callable[[dict[str, Any]], bool]:
    def condition(env: dict[str, Any]) -> bool:
        return bool(env.get(flag))
    return condition


def time_window_condition(start_hour: int, end_hour: int) -> Callable[[dict[str, Any]], bool]:
    pattern = re.compile(r"^\d{1,2}$")
    def condition(env: dict[str, Any]) -> bool:
        hour_value = env.get("hour")
        if hour_value is None or not pattern.match(str(hour_value)):
            return False
        hour = int(hour_value)
        return start_hour <= hour < end_hour
    return condition
