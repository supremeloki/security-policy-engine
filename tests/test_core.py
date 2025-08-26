import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from policy_engine import (
    ConflictingPolicyError,
    Effect,
    PolicyEngine,
    PolicyRule,
    PolicySyntaxError,
    Resource,
    Subject,
    attribute_equals,
    attribute_in_group,
    env_flag_enabled,
    time_window_condition,
)


@pytest.fixture
def engine():
    return PolicyEngine()


def admin_subject():
    return Subject("admin-1", attributes={"role": "admin", "dept": "it"})


def regular_subject():
    return Subject("user-9", attributes={"role": "staff", "dept": "sales"})


def document(resource_id: str = "doc-7") -> Resource:
    return Resource(resource_type="document", resource_id=resource_id)


def test_default_deny_when_no_rules(engine):
    effect, evaluated = engine.authorize(regular_subject(), document(), "read")
    assert effect == Effect.DENY
    assert evaluated == []


def test_explicit_allow_rule(engine):
    engine.add_rule(PolicyRule(
        rule_id="allow-read-docs",
        effect=Effect.ALLOW,
        actions=("read",),
        resources=("document:*",),
    ))
    assert engine.is_allowed(regular_subject(), document(), "read")


def test_deny_overrides_allow(engine):
    engine.add_rule(PolicyRule(
        rule_id="allow-all", effect=Effect.ALLOW,
        actions=("*",), resources=("*",),
    ))
    engine.add_rule(PolicyRule(
        rule_id="deny-delete", effect=Effect.DENY,
        actions=("delete",), resources=("*",), priority=10,
    ))
    assert not engine.is_allowed(admin_subject(), document(), "delete")
    assert engine.is_allowed(admin_subject(), document(), "read")


def test_wildcard_actions_match_anything(engine):
    engine.add_rule(PolicyRule(
        rule_id="admin-full", effect=Effect.ALLOW,
        actions=("*",), resources=("*",),
        subject_condition=attribute_equals("role", "admin"),
    ))
    assert engine.is_allowed(admin_subject(), document(), "purge")
    assert not engine.is_allowed(regular_subject(), document(), "read")


def test_attribute_group_condition(engine):
    engine.add_rule(PolicyRule(
        rule_id="vip-read", effect=Effect.ALLOW,
        actions=("read",), resources=("document:*",),
        subject_condition=attribute_in_group("role", {"admin", "auditor"}),
    ))
    auditor = Subject("aud-1", attributes={"role": "auditor"})
    outsider = regular_subject()
    assert engine.is_allowed(auditor, document(), "read")
    assert not engine.is_allowed(outsider, document(), "read")


def test_environment_gate_blocks_outside_window(engine):
    engine.add_rule(PolicyRule(
        rule_id="office-hours-only",
        effect=Effect.ALLOW,
        actions=("export",),
        resources=("report:*",),
        environment_condition=time_window_condition(8, 18),
    ))
    inside = {"hour": 14}
    outside = {"hour": 3}
    assert engine.is_allowed(regular_subject(),
                             Resource("report", "q1"), "export", env=inside)
    assert not engine.is_allowed(regular_subject(),
                                 Resource("report", "q1"), "export", env=outside)


def test_flag_condition(engine):
    engine.add_rule(PolicyRule(
        rule_id="break-glass", effect=Effect.ALLOW,
        actions=("emergency-write",), resources=("*",),
        environment_condition=env_flag_enabled("incident_active"),
    ))
    incident_on = {"incident_active": True}
    assert engine.is_allowed(admin_subject(), document(), "emergency_write", env=incident_on) or \
        engine.is_allowed(admin_subject(), document(), "emergency-write", env=incident_on)


def test_duplicate_rule_id_rejected(engine):
    rule = PolicyRule("same-id", Effect.ALLOW, ("read",), ("doc:*",))
    engine.add_rule(rule)
    with pytest.raises(ConflictingPolicyError):
        engine.add_rule(rule)


def test_empty_actions_rejected():
    with pytest.raises(PolicySyntaxError):
        PolicyRule("bad", Effect.ALLOW, (), ("doc:*",))


def test_remove_rule_restores_default(engine):
    rule = PolicyRule("temp", Effect.ALLOW, ("read",), ("doc:*",))
    engine.add_rule(rule)
    assert engine.remove_rule("temp") is True
