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
