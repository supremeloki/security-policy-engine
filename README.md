# policy-engine

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A policy-as-code engine: attribute-based access control with allow/deny effects, wildcard resources, subject/environment conditions, and deny-overrides semantics — the policy layer of the security evolution chain.

## 🚀 Overview

Hard-coded permissions don't survive organizational change. `policy-engine` externalizes them as `PolicyRule` objects: which actions on which resource patterns, gated by optional **subject conditions** (attribute equality/group membership) and **environment conditions** (feature flags, time windows). The engine evaluates all matching rules with priority ordering and classic ABAC semantics — explicit DENY beats ALLOW when `deny_overrides` is on; no match falls back to default-deny.

## ✨ Features

- **ABAC rules:** effect + actions + resources + optional subject/env conditions
- **Wildcard matching:** `fnmatch` patterns over `type:id` qualified names (`document:*`, `*`)
- **Priority evaluation:** higher-priority rules evaluated first
- **Deny-overrides:** any matching DENY wins regardless of priority (configurable)
- **Default-deny posture:** unmatched requests denied by construction
- **Condition helpers:** `attribute_equals`, `attribute_in_group`, `env_flag_enabled`, `time_window_condition`
- **Zero dependencies**

## 🚧 Structure

```
security-policy-engine/
├── src/policy_engine/
│   ├── __init__.py
│   └── core.py
├── tests/
│   └── test_core.py
├── README.md
└── pyproject.toml
```

## 📦 Installation

```bash
git clone https://github.com/supremeloki/security-policy-engine.git
cd security-policy-engine
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
```

## 📋 Requirements

- Python 3.11+
- No runtime dependencies

## 🏃 Quick Start

```python
from policy_engine import (
    Effect, PolicyEngine, PolicyRule,
    Resource, Subject, attribute_equals,
)

engine = PolicyEngine()
engine.add_rule(PolicyRule(
    rule_id="admins-full",
    effect=Effect.ALLOW,
    actions=("*",),
    resources=("*",),
    subject_condition=attribute_equals("role", "admin"),
))
engine.add_rule(PolicyRule(
    rule_id="deny-delete",
    effect=Effect.DENY,
    actions=("delete",),
    resources=("document:*",),
    priority=10,
))

admin = Subject("a1", attributes={"role": "admin"})
print(engine.is_allowed(admin, Resource("document", "d1"), "read"))
```

## 🔧 Error Handling

```text
PolicyError
├── PolicySyntaxError       # rule without actions/resources
└── ConflictingPolicyError  # duplicate rule ids
```

Authorization never raises — unmatched requests return the default effect.

## 🧪 Testing

```bash
pytest tests/ -v
```

## 📝 Code Quality

- Full type hints (`X | None` style), frozen subjects/resources/rules
- Zero comments — names carry the meaning
- Deny-override precedence explicitly tested

## 📄 License

MIT — see [LICENSE](LICENSE).

## 👤 Author

**Kooroush Masoumi** - [kooroushmasoumi@gmail.com](mailto:kooroushmasoumi@gmail.com)

---

⭐ Star this repo if you find it useful!
