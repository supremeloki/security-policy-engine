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
