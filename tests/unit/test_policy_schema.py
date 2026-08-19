from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from pytest_mock import MockerFixture

from interbolt.errors import InterboltConfigError, PolicyEvaluationError
from interbolt.models.core import Action, Capability, Mode, TrustLevel
from interbolt.policy import default_policy
from interbolt.policy import schema as schema_module
from interbolt.policy.schema import (
    AgentDeclaration,
    Defaults,
    PolicyDocument,
    SinkRule,
    SourceDeclaration,
    _split_sink_key,
    compute_policy_fingerprint,
    load_policy_document,
    validate_policy,
)

_MINIMAL_VALID_YAML = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks: {}
"""

_POLICY_WITH_SINK = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.send_email:
    rules:
      - name: allow_all
        action: allow
"""

_POLICY_WITH_CATCH_ALL_THEN_DEAD = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    rules:
      - name: catch_all
        action: allow
      - name: dead_rule
        when: 'true'
        action: block
"""

_POLICY_WITH_INVALID_CEL = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    rules:
      - name: bad_rule
        when: '%%% not valid CEL'
        action: block
"""

_POLICY_WITH_NON_COMPUTABLE_TRIFECTA = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    rules:
      - name: bad_trifecta
        when: 'trifecta.contains("reaches_external")'
        action: block
"""

_POLICY_WITH_UNKNOWN_TRIFECTA_LEG = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    rules:
      - name: bad_leg
        when: 'trifecta.contains("bogus_leg")'
        action: block
"""

_POLICY_WITH_CAPABILITIES_SECTION_BUT_LEG_UNDECLARED = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    capabilities: [reads_private]
    rules:
      - name: never_matches
        when: 'trifecta.contains("reaches_external")'
        action: block
"""

_POLICY_WITH_DECLARED_CAPABILITY_LEG_IS_CLEAN = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    capabilities: [reaches_external]
    rules:
      - name: matches
        when: 'trifecta.contains("reaches_external")'
        action: block
"""

_POLICY_WITH_RUN_TRIFECTA_NO_CAPABILITIES_SECTION = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    rules:
      - name: bad_run_leg
        when: 'run.trifecta.exists(leg, leg == "reads_private")'
        action: block
"""

_POLICY_WITH_RUN_TRIFECTA_LEG_UNDECLARED_WARNING = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    capabilities: [reads_private]
    rules:
      - name: never_matches
        when: 'run.trifecta.contains("reaches_external")'
        action: block
"""

_POLICY_WITH_UNDECLARED_SINK_CAPABILITIES_WARNING = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    rules:
      - name: allow_all
        action: allow
  default.other_tool:
    capabilities: [reads_private]
"""

_POLICY_WITH_EMPTY_CAPABILITIES_LIST_SUPPRESSES_WARNING = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    capabilities: []
    rules:
      - name: allow_all
        action: allow
"""

_POLICY_WITH_UNKNOWN_CAPABILITY_STRING = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    capabilities: [bogus_capability]
    rules:
      - name: allow_all
        action: allow
"""

_POLICY_WITH_SOURCE_EQUALITY = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    rules:
      - name: source_check
        when: 't.source == "web_search"'
        action: block
"""

_POLICY_WITH_SOURCE_INEQUALITY = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    rules:
      - name: source_check
        when: 't.source != "web_search"'
        action: block
"""

_POLICY_WITH_LINEAGE_ONLY = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    rules:
      - name: lineage_check
        when: 't.lineage.exists(s, s == "web_search")'
        action: block
"""

_POLICY_SCHEMA_ERROR = """\
not_a_valid_field: true
"""

_POLICY_WITH_NON_COMPUTABLE_AGENT_FIELD = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    rules:
      - name: bad_agent_field
        when: 'agent.role == "billing"'
        action: block
"""

_POLICY_WITH_AGENT_ID_ONLY = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    rules:
      - name: agent_id_only
        when: 'agent.id == "x"'
        action: block
"""

_POLICY_WITH_AGENT_FIELD_INSIDE_STRING_LITERAL = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    rules:
      - name: path_literal
        when: >-
          args.path == "/etc/agent.conf" &&
          taint.exists(t, t.trust == "untrusted")
        action: block
"""

_POLICY_WITH_RUN_FIELD_INSIDE_STRING_LITERAL = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    rules:
      - name: contains_literal
        when: 'args.path.contains("run.foobar")'
        action: block
"""

_POLICY_WITH_IDENTITY_ONLY_ALLOW_SIGNAL_WORD_IN_LITERAL = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    rules:
      - name: suppressed
        when: 'agent.id == "mailer" && args.note == "no sources here"'
        action: allow
"""

_POLICY_WITH_RUN_FIELD_VIOLATION_OUTSIDE_LITERAL = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    rules:
      - name: real_violation
        when: 'agent.id == "x" && run.bogus'
        action: block
"""

_POLICY_WITH_TWO_RUN_FIELD_VIOLATIONS = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    rules:
      - name: real_violation
        when: 'run.a && run.b'
        action: block
"""

_POLICY_WITH_ALL_FOUR_RUN_FIELDS = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    rules:
      - name: run_fields
        when: >-
          run.tainted && run.sources.exists(s, s == "x") &&
          run.untrusted_sources.exists(s, s == "x") &&
          run.ingested_by.exists(a, a == "x")
        action: block
"""

_POLICY_WITH_RUN_SOURCES_ALL_ALLOW = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    rules:
      - name: vacuous_run_allow
        when: 'agent.id == "x" && run.sources.all(s, s == "web_search")'
        action: allow
"""

_POLICY_WITH_RUN_SOURCES_ALL_BLOCK = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    rules:
      - name: run_sources_all_block
        when: 'run.sources.all(s, s == "web_search")'
        action: block
"""

_POLICY_WITH_IDENTITY_ONLY_ALLOW_RUN_INGESTED_BY = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    rules:
      - name: identity_only_allow_ingested_by
        when: 'agent.id == "x" && run.ingested_by.exists(a, a == "y")'
        action: allow
"""

_POLICY_WITH_IDENTITY_ALLOW_RUN_UNTRUSTED_SOURCES = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    rules:
      - name: identity_allow_untrusted_sources
        when: 'agent.id == "x" && run.untrusted_sources.exists(s, s == "web_search")'
        action: allow
"""

_POLICY_WITH_IDENTITY_ONLY_ALLOW = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    rules:
      - name: identity_only_allow
        when: 'agent.id == "x"'
        action: allow
"""

_POLICY_WITH_IDENTITY_AND_TAINT_ALLOW = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    rules:
      - name: identity_and_taint
        when: 'agent.id == "x" && max_trust == "trusted"'
        action: allow
"""

_POLICY_WITH_VACUOUS_TAINT_ALL_ALLOW = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    rules:
      - name: vacuous_allow
        when: 'agent.id == "x" && taint.all(t, t.trust == "trusted")'
        action: allow
"""

_POLICY_WITH_TAINT_ALL_BLOCK = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    rules:
      - name: taint_all_block
        when: 'taint.all(t, t.trust == "trusted")'
        action: block
"""

_POLICY_WITH_AGENT_GROUPS_ONLY = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
agents:
  billing-agent:
    groups: [payer]
sinks:
  default.tool:
    rules:
      - name: group_gated
        when: 'agent.groups.exists(g, g == "payer")'
        action: block
"""

_POLICY_WITH_UNDECLARED_GROUP = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    rules:
      - name: undeclared_group
        when: 'agent.groups.exists(g, g == "ghost")'
        action: block
"""

_POLICY_WITH_UNDECLARED_GROUP_ANY_SPELLING = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    rules:
      - name: undeclared_group
        when: 'agent.groups.any(g, g == "ghost")'
        action: block
"""

_POLICY_WITH_UNDECLARED_GROUP_BEHIND_NESTED_CALL = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    rules:
      - name: undeclared_group
        when: >-
          agent.groups.exists(g, g.startsWith("team-") && g == "team-payer")
        action: block
"""

_POLICY_WITH_BAD_AGENT_ID_CHARSET = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
agents:
  "bad id!":
    groups: []
sinks: {}
"""

_POLICY_WITH_BAD_GROUP_NAME_CHARSET = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
agents:
  billing-agent:
    groups: ["bad group!"]
sinks: {}
"""

_POLICY_WITH_UNKNOWN_AGENT_ENTRY_KEY = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
agents:
  billing-agent:
    groups: []
    permissions: [admin]
sinks: {}
"""

_POLICY_WITH_GROUP_RULE_SHADOWS_ID_RULE = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
agents:
  billing-agent:
    groups: [payer]
sinks:
  payments.send_payment:
    rules:
      - name: payers_need_approval
        when: 'agent.groups.exists(g, g == "payer")'
        action: require_approval
      - name: billing_agent_blocked
        when: 'agent.id == "billing-agent"'
        action: block
"""

_POLICY_WITH_ID_RULE_THEN_GROUP_RULE_NOT_SOLE_MEMBER = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
agents:
  billing-agent:
    groups: [payer]
  another-agent:
    groups: [payer]
sinks:
  payments.send_payment:
    rules:
      - name: billing_agent_blocked
        when: 'agent.id == "billing-agent"'
        action: block
      - name: payers_need_approval
        when: 'agent.groups.exists(g, g == "payer")'
        action: require_approval
"""

_POLICY_WITH_ID_RULE_SHADOWS_SOLE_GROUP_MEMBER = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
agents:
  billing-agent:
    groups: [payer]
sinks:
  payments.send_payment:
    rules:
      - name: billing_agent_blocked
        when: 'agent.id == "billing-agent"'
        action: block
      - name: payers_need_approval
        when: 'agent.groups.exists(g, g == "payer")'
        action: require_approval
"""

_POLICY_WITH_AGENT_NOT_IN_SHADOWING_GROUP = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
agents:
  billing-agent:
    groups: [payer]
  support-agent:
    groups: [internal]
sinks:
  payments.send_payment:
    rules:
      - name: payers_need_approval
        when: 'agent.groups.exists(g, g == "payer")'
        action: require_approval
      - name: support_blocked
        when: 'agent.id == "support-agent"'
        action: block
"""

_POLICY_WITH_TAINT_CONJUNCT_NOT_IDENTITY_ONLY = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
agents:
  billing-agent:
    groups: [payer]
sinks:
  payments.send_payment:
    rules:
      - name: payers_need_approval
        when: >
          agent.groups.exists(g, g == "payer") &&
          taint.exists(t, t.trust == "untrusted")
        action: require_approval
      - name: billing_agent_blocked
        when: 'agent.id == "billing-agent"'
        action: block
"""

_POLICY_WITH_NEGATED_GROUP_SHADOWS_NEGATED_ID = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
agents:
  billing-agent:
    groups: [payer]
sinks:
  payments.send_payment:
    rules:
      - name: not_payer_allowed
        when: '!agent.groups.exists(g, g == "payer")'
        action: block
      - name: not_billing_blocked
        when: 'agent.id != "billing-agent"'
        action: block
"""

_POLICY_WITH_UNDECLARED_AGENT_ID_NOT_SHADOWED_BY_GROUP = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
agents:
  billing-agent:
    groups: [payer]
sinks:
  payments.send_payment:
    rules:
      - name: payers_need_approval
        when: 'agent.groups.exists(g, g == "payer")'
        action: require_approval
      - name: ghost_blocked
        when: 'agent.id != "ghost-agent"'
        action: block
"""

_POLICY_WITH_SHADOWING_RULES_IN_DIFFERENT_SINKS = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
agents:
  billing-agent:
    groups: [payer]
sinks:
  payments.send_payment:
    rules:
      - name: payers_need_approval
        when: 'agent.groups.exists(g, g == "payer")'
        action: require_approval
      - name: default1
        action: allow
  default.other_tool:
    rules:
      - name: billing_agent_blocked
        when: 'agent.id == "billing-agent"'
        action: block
      - name: default2
        action: allow
"""

_POLICY_WITH_UNRECOGNIZED_PREDICATE_SHAPE = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
agents:
  billing-agent:
    groups: [payer]
sinks:
  payments.send_payment:
    rules:
      - name: run_gate
        when: 'run.tainted'
        action: require_approval
      - name: billing_agent_blocked
        when: 'agent.id == "billing-agent"'
        action: block
"""

_POLICY_WITH_ZERO_ARG_DOTTED_CALL = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
agents:
  billing-agent:
    groups: [payer]
sinks:
  payments.send_payment:
    rules:
      - name: zero_arg_call_rule
        when: 'agent.groups.size() && agent.id == "billing-agent"'
        action: block
"""

_POLICY_WITH_VERSION_1_0 = """\
version: "1.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    - name: allow_all
      action: allow
"""

_POLICY_WITH_BARE_RULE_LIST_SINK_UNDER_2_0 = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    - name: allow_all
      action: allow
"""

_POLICY_WITH_UNSUPPORTED_VERSION = """\
version: "3.0"
defaults:
  sink_action: allow
sources: []
sinks: {}
"""

_POLICY_WITH_MISSPELLED_SINK_ENTRY_KEY = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    rulez:
      - name: allow_all
        action: allow
"""

_POLICY_WITH_CAPABILITIES_ONLY_SINK = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.read_inbox:
    capabilities: [reads_private]
"""


class TestSplitSinkKey:
    def test_valid_dotted(self) -> None:
        ns, tool = _split_sink_key("ns.tool")
        assert ns == "ns"
        assert tool == "tool"

    def test_no_dot_raises(self) -> None:
        with pytest.raises(InterboltConfigError, match="dotted"):
            _split_sink_key("nodot")

    def test_dotted_namespace_raises(self) -> None:
        # rpartition on "a.b.c" -> namespace="a.b", tool="c"
        # namespace "a.b" contains a dot -> error
        with pytest.raises(InterboltConfigError):
            _split_sink_key("a.b.c")


class TestLoadPolicyDocument:
    def test_valid_yaml_returns_document(self, mocker: MockerFixture) -> None:
        mocker.patch("builtins.open", mocker.mock_open(read_data=_MINIMAL_VALID_YAML))
        doc = load_policy_document("fake.yaml")
        assert doc.version == "2.0"
        assert doc.defaults.sink_action == Action.ALLOW

    def test_os_error_raises_policy_evaluation_error(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch("builtins.open", side_effect=OSError("not found"))
        with pytest.raises(PolicyEvaluationError, match="not found"):
            load_policy_document("fake.yaml")

    def test_invalid_yaml_raises_policy_evaluation_error(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch("builtins.open", mocker.mock_open(read_data=": bad: yaml: :"))
        with pytest.raises(PolicyEvaluationError):
            load_policy_document("fake.yaml")

    def test_schema_error_raises_policy_evaluation_error(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch("builtins.open", mocker.mock_open(read_data=_POLICY_SCHEMA_ERROR))
        with pytest.raises(PolicyEvaluationError):
            load_policy_document("fake.yaml")

    def test_fail_mode_optional_not_in_yaml(self, mocker: MockerFixture) -> None:
        mocker.patch("builtins.open", mocker.mock_open(read_data=_MINIMAL_VALID_YAML))
        doc = load_policy_document("fake.yaml")
        assert doc.defaults.fail_mode is None

    def test_fail_mode_explicit_in_yaml(self, mocker: MockerFixture) -> None:
        yaml_with_fail_mode = """\
version: "2.0"
defaults:
  sink_action: allow
  fail_mode: enforce
sources: []
sinks: {}
"""
        mocker.patch("builtins.open", mocker.mock_open(read_data=yaml_with_fail_mode))
        doc = load_policy_document("fake.yaml")
        assert doc.defaults.fail_mode == Mode.ENFORCE

    def test_sink_with_no_capabilities_key_is_undeclared(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch("builtins.open", mocker.mock_open(read_data=_POLICY_WITH_SINK))
        doc = load_policy_document("fake.yaml")
        assert doc.sinks["default.send_email"].capabilities is None

    def test_empty_capability_list_is_legal(self, mocker: MockerFixture) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(
                read_data=_POLICY_WITH_EMPTY_CAPABILITIES_LIST_SUPPRESSES_WARNING
            ),
        )
        doc = load_policy_document("fake.yaml")
        assert doc.sinks["default.tool"].capabilities == ()

    def test_unknown_capability_string_raises_naming_valid_values(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_UNKNOWN_CAPABILITY_STRING),
        )
        with pytest.raises(PolicyEvaluationError) as exc_info:
            load_policy_document("fake.yaml")
        message = str(exc_info.value)
        assert "reads_private" in message
        assert "reaches_external" in message

    def test_capabilities_only_entry_has_no_rules(self, mocker: MockerFixture) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_CAPABILITIES_ONLY_SINK),
        )
        doc = load_policy_document("fake.yaml")
        declaration = doc.sinks["default.read_inbox"]
        assert declaration.capabilities == (Capability.READS_PRIVATE,)
        assert declaration.rules == ()


class TestVersionGate:
    def test_version_1_0_raises_interbolt_config_error(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            "builtins.open", mocker.mock_open(read_data=_POLICY_WITH_VERSION_1_0)
        )
        with pytest.raises(InterboltConfigError, match='version "1.0"') as exc_info:
            load_policy_document("fake.yaml")
        message = str(exc_info.value)
        assert "capabilities:" in message
        assert "rules:" in message

    def test_bare_rule_list_sink_under_2_0_raises_interbolt_config_error(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_BARE_RULE_LIST_SINK_UNDER_2_0),
        )
        with pytest.raises(InterboltConfigError, match="rules:"):
            load_policy_document("fake.yaml")

    def test_unsupported_version_raises_policy_evaluation_error(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_UNSUPPORTED_VERSION),
        )
        with pytest.raises(PolicyEvaluationError):
            load_policy_document("fake.yaml")

    def test_misspelled_sink_entry_key_rejected(self, mocker: MockerFixture) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_MISSPELLED_SINK_ENTRY_KEY),
        )
        with pytest.raises(PolicyEvaluationError):
            load_policy_document("fake.yaml")

    def test_version_1_0_validate_returns_problem_never_raises(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            "builtins.open", mocker.mock_open(read_data=_POLICY_WITH_VERSION_1_0)
        )
        problems = validate_policy("fake.yaml")
        assert any('version "1.0"' in p for p in problems)

    def test_bare_rule_list_sink_under_2_0_validate_returns_problem_never_raises(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_BARE_RULE_LIST_SINK_UNDER_2_0),
        )
        problems = validate_policy("fake.yaml")
        assert any("rules:" in p for p in problems)


class TestValidatePolicy:
    def test_valid_returns_empty_list(self, mocker: MockerFixture) -> None:
        mocker.patch("builtins.open", mocker.mock_open(read_data=_MINIMAL_VALID_YAML))
        problems = validate_policy("fake.yaml")
        assert problems == []

    def test_os_error_returns_problem_never_raises(self, mocker: MockerFixture) -> None:
        mocker.patch("builtins.open", side_effect=OSError("no file"))
        problems = validate_policy("fake.yaml")
        assert len(problems) == 1
        assert "no file" in problems[0]

    def test_dead_rule_after_catch_all(self, mocker: MockerFixture) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_CATCH_ALL_THEN_DEAD),
        )
        problems = validate_policy("fake.yaml")
        assert any("unreachable" in p for p in problems)

    def test_invalid_cel_expression(self, mocker: MockerFixture) -> None:
        mocker.patch(
            "builtins.open", mocker.mock_open(read_data=_POLICY_WITH_INVALID_CEL)
        )
        problems = validate_policy("fake.yaml")
        assert any("invalid CEL" in p for p in problems)

    def test_capability_leg_referenced_when_no_sink_declares_capabilities(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_NON_COMPUTABLE_TRIFECTA),
        )
        problems = validate_policy("fake.yaml")
        assert any(
            "never computed until at least one sink declares it under "
            "`capabilities:`" in p
            for p in problems
        )

    def test_unknown_trifecta_leg_is_an_error(self, mocker: MockerFixture) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_UNKNOWN_TRIFECTA_LEG),
        )
        problems = validate_policy("fake.yaml")
        assert any("is not a trifecta leg" in p for p in problems)

    def test_capability_leg_no_tool_declares_is_a_warning(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(
                read_data=_POLICY_WITH_CAPABILITIES_SECTION_BUT_LEG_UNDECLARED
            ),
        )
        problems = validate_policy("fake.yaml")
        assert any(
            p.startswith("warning:") and "reaches_external" in p for p in problems
        )

    def test_declared_capability_leg_reference_is_clean(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_DECLARED_CAPABILITY_LEG_IS_CLEAN),
        )
        problems = validate_policy("fake.yaml")
        assert not any("trifecta leg" in p for p in problems)

    def test_run_trifecta_leg_referenced_when_no_sink_declares_capabilities(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(
                read_data=_POLICY_WITH_RUN_TRIFECTA_NO_CAPABILITIES_SECTION
            ),
        )
        problems = validate_policy("fake.yaml")
        assert any(
            "never computed until at least one sink declares it under "
            "`capabilities:`" in p
            for p in problems
        )

    def test_run_trifecta_leg_no_tool_declares_is_a_warning(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(
                read_data=_POLICY_WITH_RUN_TRIFECTA_LEG_UNDECLARED_WARNING
            ),
        )
        problems = validate_policy("fake.yaml")
        assert any(
            p.startswith("warning:") and "reaches_external" in p for p in problems
        )

    def test_undeclared_sink_warns_once_another_sink_declares_capabilities(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(
                read_data=_POLICY_WITH_UNDECLARED_SINK_CAPABILITIES_WARNING
            ),
        )
        problems = validate_policy("fake.yaml")
        assert any(
            p.startswith("warning:") and "default.tool" in p and "capabilities" in p
            for p in problems
        )

    def test_empty_capability_list_suppresses_undeclared_sink_warning(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(
                read_data=_POLICY_WITH_EMPTY_CAPABILITIES_LIST_SUPPRESSES_WARNING
            ),
        )
        problems = validate_policy("fake.yaml")
        assert not any("capabilities" in p for p in problems)

    def test_no_sink_declaring_capabilities_produces_no_undeclared_sink_warning(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch("builtins.open", mocker.mock_open(read_data=_POLICY_WITH_SINK))
        problems = validate_policy("fake.yaml")
        assert not any("capabilities" in p for p in problems)

    def test_schema_error_returns_field_problems(self, mocker: MockerFixture) -> None:
        mocker.patch("builtins.open", mocker.mock_open(read_data=_POLICY_SCHEMA_ERROR))
        problems = validate_policy("fake.yaml")
        assert len(problems) > 0

    def test_two_catch_alls_produces_unreachable_problem(
        self, mocker: MockerFixture
    ) -> None:
        yaml_two_catch_alls = """\
version: "2.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    rules:
      - name: first_catch_all
        action: allow
      - name: second_catch_all
        action: block
"""
        mocker.patch("builtins.open", mocker.mock_open(read_data=yaml_two_catch_alls))
        problems = validate_policy("fake.yaml")
        assert any("unreachable" in p for p in problems)

    def test_source_equality_produces_warning(self, mocker: MockerFixture) -> None:
        mocker.patch(
            "builtins.open", mocker.mock_open(read_data=_POLICY_WITH_SOURCE_EQUALITY)
        )
        problems = validate_policy("fake.yaml")
        assert any(p.startswith("warning:") and "t.lineage" in p for p in problems)

    def test_source_inequality_produces_warning(self, mocker: MockerFixture) -> None:
        mocker.patch(
            "builtins.open", mocker.mock_open(read_data=_POLICY_WITH_SOURCE_INEQUALITY)
        )
        problems = validate_policy("fake.yaml")
        assert any(p.startswith("warning:") for p in problems)

    def test_lineage_usage_is_not_flagged(self, mocker: MockerFixture) -> None:
        mocker.patch(
            "builtins.open", mocker.mock_open(read_data=_POLICY_WITH_LINEAGE_ONLY)
        )
        problems = validate_policy("fake.yaml")
        assert problems == []

    def test_source_equality_warning_does_not_block_otherwise_valid_policy(
        self, mocker: MockerFixture
    ) -> None:
        # A warning-only problem list; the CLI (not validate_policy itself)
        # decides the exit code split between warnings and errors.
        mocker.patch(
            "builtins.open", mocker.mock_open(read_data=_POLICY_WITH_SOURCE_EQUALITY)
        )
        problems = validate_policy("fake.yaml")
        assert all(p.startswith("warning:") for p in problems)

    def test_non_computable_agent_field(self, mocker: MockerFixture) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_NON_COMPUTABLE_AGENT_FIELD),
        )
        problems = validate_policy("fake.yaml")
        assert any(
            not p.startswith("warning:") and "agent.'role'" in p for p in problems
        )

    def test_agent_id_block_rule_is_valid(self, mocker: MockerFixture) -> None:
        mocker.patch(
            "builtins.open", mocker.mock_open(read_data=_POLICY_WITH_AGENT_ID_ONLY)
        )
        problems = validate_policy("fake.yaml")
        assert problems == []

    def test_agent_field_inside_string_literal_not_flagged(
        self, mocker: MockerFixture
    ) -> None:
        # "/etc/agent.conf" is a string literal, not a reference to an
        # agent.conf field; the regex lint must not match inside quotes.
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_AGENT_FIELD_INSIDE_STRING_LITERAL),
        )
        problems = validate_policy("fake.yaml")
        assert problems == []

    def test_run_field_inside_string_literal_not_flagged(
        self, mocker: MockerFixture
    ) -> None:
        # "run.foobar" here is the argument to contains(), not a run.foobar
        # field reference.
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_RUN_FIELD_INSIDE_STRING_LITERAL),
        )
        problems = validate_policy("fake.yaml")
        assert problems == []

    def test_run_field_violation_outside_literal_still_flagged(
        self, mocker: MockerFixture
    ) -> None:
        # Guards against blanking string literals from swallowing a genuine
        # run.<field> violation that appears outside of any literal.
        mocker.patch(
            "builtins.open",
            mocker.mock_open(
                read_data=_POLICY_WITH_RUN_FIELD_VIOLATION_OUTSIDE_LITERAL
            ),
        )
        problems = validate_policy("fake.yaml")
        matches = [
            p for p in problems if not p.startswith("warning:") and "run.'bogus'" in p
        ]
        # A single `run.bogus` reference must be reported exactly once, not
        # once per grammar precedence level the AST walk passes through.
        assert len(matches) == 1

    def test_two_distinct_run_field_violations_each_flagged_once(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_TWO_RUN_FIELD_VIOLATIONS),
        )
        problems = validate_policy("fake.yaml")
        a_matches = [p for p in problems if "run.'a'" in p]
        b_matches = [p for p in problems if "run.'b'" in p]
        assert len(a_matches) == 1
        assert len(b_matches) == 1

    def test_all_four_run_fields_validate_clean(self, mocker: MockerFixture) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_ALL_FOUR_RUN_FIELDS),
        )
        problems = validate_policy("fake.yaml")
        assert not any(not p.startswith("warning:") for p in problems)

    def test_run_nonsense_field_errors_with_widened_field_list(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(
                read_data=_POLICY_WITH_RUN_FIELD_VIOLATION_OUTSIDE_LITERAL
            ),
        )
        problems = validate_policy("fake.yaml")
        matches = [p for p in problems if "run.'bogus'" in p]
        assert len(matches) == 1
        assert "computable fields are" in matches[0]
        assert "'ingested_by'" in matches[0]
        assert "'sources'" in matches[0]
        assert "'tainted'" in matches[0]
        assert "'untrusted_sources'" in matches[0]

    def test_run_sources_all_in_allow_rule_warns(self, mocker: MockerFixture) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_RUN_SOURCES_ALL_ALLOW),
        )
        problems = validate_policy("fake.yaml")
        assert any(
            p.startswith("warning:") and "run.sources.all(" in p for p in problems
        )

    def test_run_sources_all_in_block_rule_not_flagged(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_RUN_SOURCES_ALL_BLOCK),
        )
        problems = validate_policy("fake.yaml")
        assert problems == []

    def test_identity_only_allow_with_run_ingested_by_still_warns(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(
                read_data=_POLICY_WITH_IDENTITY_ONLY_ALLOW_RUN_INGESTED_BY
            ),
        )
        problems = validate_policy("fake.yaml")
        assert any(
            p.startswith("warning:") and "unconditional access" in p for p in problems
        )

    def test_identity_allow_with_run_untrusted_sources_not_flagged(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(
                read_data=_POLICY_WITH_IDENTITY_ALLOW_RUN_UNTRUSTED_SOURCES
            ),
        )
        problems = validate_policy("fake.yaml")
        assert not any("unconditional access" in p for p in problems)

    def test_identity_only_allow_produces_warning(self, mocker: MockerFixture) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_IDENTITY_ONLY_ALLOW),
        )
        problems = validate_policy("fake.yaml")
        assert any(
            p.startswith("warning:") and "unconditional access" in p for p in problems
        )

    def test_identity_only_allow_not_flagged_when_taint_present(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_IDENTITY_AND_TAINT_ALLOW),
        )
        problems = validate_policy("fake.yaml")
        assert not any("unconditional access" in p for p in problems)

    def test_identity_only_allow_flagged_despite_signal_word_in_literal(
        self, mocker: MockerFixture
    ) -> None:
        # "no sources here" is a string literal that happens to contain the
        # substring "sources"; it is not a taint/max_trust/sources/run.
        # condition and must not suppress the identity-only-allow warning.
        mocker.patch(
            "builtins.open",
            mocker.mock_open(
                read_data=_POLICY_WITH_IDENTITY_ONLY_ALLOW_SIGNAL_WORD_IN_LITERAL
            ),
        )
        problems = validate_policy("fake.yaml")
        assert any(
            p.startswith("warning:") and "unconditional access" in p for p in problems
        )

    def test_vacuous_taint_all_in_allow_produces_warning(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_VACUOUS_TAINT_ALL_ALLOW),
        )
        problems = validate_policy("fake.yaml")
        assert any(p.startswith("warning:") and "taint.all" in p for p in problems)

    def test_taint_all_in_block_rule_not_flagged(self, mocker: MockerFixture) -> None:
        # The vacuous-fold hazard is allow-specific; a block rule using
        # taint.all(...) is not gated on identity and does not over-grant.
        mocker.patch(
            "builtins.open", mocker.mock_open(read_data=_POLICY_WITH_TAINT_ALL_BLOCK)
        )
        problems = validate_policy("fake.yaml")
        assert problems == []

    def test_agent_groups_field_is_computable(self, mocker: MockerFixture) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_AGENT_GROUPS_ONLY),
        )
        problems = validate_policy("fake.yaml")
        assert problems == []

    def test_undeclared_group_in_exists_produces_warning(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_UNDECLARED_GROUP),
        )
        problems = validate_policy("fake.yaml")
        assert any(p.startswith("warning:") and "'ghost'" in p for p in problems)

    def test_any_spelling_rejected_at_error_level_not_undeclared_group_warning(
        self, mocker: MockerFixture
    ) -> None:
        # agent.groups.any(...) is no longer a recognized alias for
        # agent.groups.exists(...); it must fail CEL compilation at error
        # level rather than fall through to the undeclared-group warning.
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_UNDECLARED_GROUP_ANY_SPELLING),
        )
        problems = validate_policy("fake.yaml")
        assert any(not p.startswith("warning:") and "exists" in p for p in problems)
        assert not any(p.startswith("warning:") and "'ghost'" in p for p in problems)

    def test_undeclared_group_behind_nested_call_is_still_found(
        self, mocker: MockerFixture
    ) -> None:
        # A regex spanning "exists(...)" by matching to the first ")" would
        # truncate at startsWith("team-")'s closing paren and both misread
        # "team-" as a group reference and miss the real, undeclared
        # "team-payer" reference that follows it. The AST walk sees the
        # `.exists(...)` call's actual argument boundary regardless of what
        # nested calls appear inside the predicate.
        mocker.patch(
            "builtins.open",
            mocker.mock_open(
                read_data=_POLICY_WITH_UNDECLARED_GROUP_BEHIND_NESTED_CALL
            ),
        )
        problems = validate_policy("fake.yaml")
        assert any(p.startswith("warning:") and "'team-payer'" in p for p in problems)
        assert not any(p.startswith("warning:") and "'team-'" in p for p in problems)

    def test_agents_entry_bad_id_charset_rejected(self, mocker: MockerFixture) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_BAD_AGENT_ID_CHARSET),
        )
        problems = validate_policy("fake.yaml")
        assert len(problems) > 0

    def test_agents_entry_bad_group_name_charset_rejected(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_BAD_GROUP_NAME_CHARSET),
        )
        problems = validate_policy("fake.yaml")
        assert len(problems) > 0

    def test_agents_entry_unknown_key_rejected(self, mocker: MockerFixture) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_UNKNOWN_AGENT_ENTRY_KEY),
        )
        problems = validate_policy("fake.yaml")
        assert len(problems) > 0

    def test_group_rule_shadows_later_id_rule(self, mocker: MockerFixture) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_GROUP_RULE_SHADOWS_ID_RULE),
        )
        problems = validate_policy("fake.yaml")
        assert any(
            not p.startswith("warning:")
            and "billing_agent_blocked" in p
            and "unreachable" in p
            and "payers_need_approval" in p
            and "member of group 'payer'" in p
            for p in problems
        )

    def test_id_rule_before_group_rule_not_reported(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(
                read_data=_POLICY_WITH_ID_RULE_THEN_GROUP_RULE_NOT_SOLE_MEMBER
            ),
        )
        problems = validate_policy("fake.yaml")
        assert not any("unreachable" in p for p in problems)

    def test_id_rule_shadows_group_rule_when_sole_member(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_ID_RULE_SHADOWS_SOLE_GROUP_MEMBER),
        )
        problems = validate_policy("fake.yaml")
        assert any(
            "payers_need_approval" in p
            and "unreachable" in p
            and "billing_agent_blocked" in p
            for p in problems
        )

    def test_group_rule_not_shadowing_when_agent_not_member(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_AGENT_NOT_IN_SHADOWING_GROUP),
        )
        problems = validate_policy("fake.yaml")
        assert not any("unreachable" in p for p in problems)

    def test_taint_conjunct_skips_shadowing_check(self, mocker: MockerFixture) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_TAINT_CONJUNCT_NOT_IDENTITY_ONLY),
        )
        problems = validate_policy("fake.yaml")
        assert not any("unreachable" in p for p in problems)

    def test_negated_group_rule_shadows_negated_id_rule(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_NEGATED_GROUP_SHADOWS_NEGATED_ID),
        )
        problems = validate_policy("fake.yaml")
        assert any(
            "not_billing_blocked" in p
            and "unreachable" in p
            and "not_payer_allowed" in p
            for p in problems
        )

    def test_undeclared_agent_id_not_shadowed_by_group_rule(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(
                read_data=_POLICY_WITH_UNDECLARED_AGENT_ID_NOT_SHADOWED_BY_GROUP
            ),
        )
        problems = validate_policy("fake.yaml")
        assert not any("unreachable" in p for p in problems)

    def test_shadowing_check_scoped_per_sink(self, mocker: MockerFixture) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_SHADOWING_RULES_IN_DIFFERENT_SINKS),
        )
        problems = validate_policy("fake.yaml")
        assert not any("unreachable" in p for p in problems)

    def test_unrecognized_predicate_shape_not_reported(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_UNRECOGNIZED_PREDICATE_SHAPE),
        )
        problems = validate_policy("fake.yaml")
        assert not any("unreachable" in p for p in problems)

    def test_zero_arg_dotted_call_does_not_crash_shadowing_check(
        self, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_ZERO_ARG_DOTTED_CALL),
        )
        problems = validate_policy("fake.yaml")
        assert not any("unreachable" in p for p in problems)


class TestDefaultsModel:
    def test_fail_mode_defaults_to_none(self) -> None:
        d = Defaults()
        assert d.fail_mode is None

    def test_fail_mode_can_be_set_explicitly(self) -> None:
        d = Defaults(fail_mode=Mode.DRY_RUN)
        assert d.fail_mode == Mode.DRY_RUN

    def test_source_trust_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Defaults.model_validate({"source_trust": TrustLevel.UNTRUSTED})

    def test_sink_action_default(self) -> None:
        d = Defaults()
        assert d.sink_action == Action.REQUIRE_APPROVAL


class TestSourceDeclaration:
    def test_construction(self) -> None:
        sd = SourceDeclaration(name="my_source", trust=TrustLevel.TRUSTED)
        assert sd.name == "my_source"
        assert sd.trust == TrustLevel.TRUSTED

    def test_unknown_key_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SourceDeclaration.model_validate(
                {"name": "my_source", "trust": TrustLevel.TRUSTED, "priority": 1}
            )


class TestAgentDeclaration:
    def test_default_groups_is_empty(self) -> None:
        decl = AgentDeclaration()
        assert decl.groups == ()

    def test_construction_with_groups(self) -> None:
        decl = AgentDeclaration(groups=("payer", "internal"))
        assert decl.groups == ("payer", "internal")

    def test_unknown_key_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AgentDeclaration.model_validate({"groups": [], "permissions": ["admin"]})

    def test_is_frozen(self) -> None:
        decl = AgentDeclaration(groups=("payer",))
        with pytest.raises((ValidationError, TypeError)):
            decl.groups = ()

    def test_bad_group_name_charset_raises(self) -> None:
        with pytest.raises(ValidationError):
            AgentDeclaration(groups=("bad group!",))


class TestSinkRule:
    def test_with_when(self) -> None:
        rule = SinkRule(name="r", when='args.x == "y"', action=Action.BLOCK)
        assert rule.when == 'args.x == "y"'

    def test_without_when(self) -> None:
        rule = SinkRule(name="default", action=Action.ALLOW)
        assert rule.when is None

    def test_require_endorsement_alone_is_valid(self) -> None:
        rule = SinkRule(
            name="r", require_endorsement="recipient_allowlisted", action=Action.BLOCK
        )
        assert rule.require_endorsement == "recipient_allowlisted"
        assert rule.when is None

    def test_when_and_require_endorsement_together_raises(self) -> None:
        with pytest.raises(ValueError, match="mutually exclusive"):
            SinkRule(
                name="r",
                when="true",
                require_endorsement="recipient_allowlisted",
                action=Action.BLOCK,
            )

    def test_unknown_key_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SinkRule.model_validate(
                {"name": "r", "wehn": 'args.x == "y"', "action": Action.BLOCK}
            )


class TestPolicyDocument:
    def test_unknown_key_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyDocument.model_validate(
                {
                    "version": "2.0",
                    "defaults": {"sink_action": "allow"},
                    "sources": [],
                    "sinks": {},
                    "notes": "not a real field",
                }
            )


class TestComputePolicyFingerprint:
    _BASE_YAML = """\
version: "2.0"
defaults:
  sink_action: allow
sources:
  - name: web_search
    trust: untrusted
sinks:
  default.tool:
    rules:
      - name: block_untrusted
        when: 'taint.exists(t, t.trust == "untrusted")'
        action: block
      - name: default
        action: allow
"""

    def _fingerprint_of(self, mocker: MockerFixture, yaml_text: str) -> str:
        mocker.patch("builtins.open", mocker.mock_open(read_data=yaml_text))
        document = load_policy_document("fake.yaml")
        return compute_policy_fingerprint(document)

    def test_is_sha256_prefixed(self, mocker: MockerFixture) -> None:
        fingerprint = self._fingerprint_of(mocker, self._BASE_YAML)
        assert fingerprint.startswith("sha256:")
        assert len(fingerprint) == len("sha256:") + 64

    def test_same_document_twice_same_fingerprint(self, mocker: MockerFixture) -> None:
        first = self._fingerprint_of(mocker, self._BASE_YAML)
        second = self._fingerprint_of(mocker, self._BASE_YAML)
        assert first == second

    def test_whitespace_and_comment_only_edit_unchanged(
        self, mocker: MockerFixture
    ) -> None:
        commented = (
            self._BASE_YAML.replace("version:", "# a helpful comment\nversion:")
            + "\n\n"
        )
        original = self._fingerprint_of(mocker, self._BASE_YAML)
        edited = self._fingerprint_of(mocker, commented)
        assert original == edited

    def test_semantic_edit_changes_fingerprint(self, mocker: MockerFixture) -> None:
        changed = self._BASE_YAML.replace("action: block", "action: require_approval")
        original = self._fingerprint_of(mocker, self._BASE_YAML)
        edited = self._fingerprint_of(mocker, changed)
        assert original != edited

    def test_mapping_key_reorder_unchanged(self, mocker: MockerFixture) -> None:
        reordered = """\
version: "2.0"
sources:
  - trust: untrusted
    name: web_search
sinks:
  default.tool:
    rules:
      - when: 'taint.exists(t, t.trust == "untrusted")'
        name: block_untrusted
        action: block
      - name: default
        action: allow
defaults:
  sink_action: allow
"""
        original = self._fingerprint_of(mocker, self._BASE_YAML)
        edited = self._fingerprint_of(mocker, reordered)
        assert original == edited

    def test_rule_reorder_within_sink_changes_fingerprint(
        self, mocker: MockerFixture
    ) -> None:
        reordered_rules = """\
version: "2.0"
defaults:
  sink_action: allow
sources:
  - name: web_search
    trust: untrusted
sinks:
  default.tool:
    rules:
      - name: default
        action: allow
      - name: block_untrusted
        when: 'taint.exists(t, t.trust == "untrusted")'
        action: block
"""
        original = self._fingerprint_of(mocker, self._BASE_YAML)
        edited = self._fingerprint_of(mocker, reordered_rules)
        assert original != edited

    def test_default_policy_fingerprint_stable_across_calls(self) -> None:
        assert default_policy().fingerprint == default_policy().fingerprint

    def test_agents_section_changes_fingerprint(self, mocker: MockerFixture) -> None:
        with_agents = self._BASE_YAML + (
            "agents:\n  billing-agent:\n    groups: [payer]\n"
        )
        original = self._fingerprint_of(mocker, self._BASE_YAML)
        edited = self._fingerprint_of(mocker, with_agents)
        assert original != edited


class TestSchemaJsonMatchesModel:
    def test_schema_json_on_disk_matches_live_model(self) -> None:
        schema_path = Path(schema_module.__file__).parent / "schema.json"
        on_disk = json.loads(schema_path.read_text())
        assert on_disk == PolicyDocument.model_json_schema()
