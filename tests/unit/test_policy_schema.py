from __future__ import annotations

import pytest
from pydantic import ValidationError
from pytest_mock import MockerFixture

from interbolt.errors import InterboltConfigError, PolicyEvaluationError
from interbolt.models.core import Action, Mode, TrustLevel
from interbolt.policy import default_policy
from interbolt.policy.schema import (
    Defaults,
    SinkRule,
    SourceDeclaration,
    _split_sink_key,
    compute_policy_fingerprint,
    load_policy_document,
    validate_policy,
)

_MINIMAL_VALID_YAML = """\
version: "1.0"
defaults:
  sink_action: allow
sources: []
sinks: {}
"""

_POLICY_WITH_SINK = """\
version: "1.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.send_email:
    - name: allow_all
      action: allow
"""

_POLICY_WITH_CATCH_ALL_THEN_DEAD = """\
version: "1.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    - name: catch_all
      action: allow
    - name: dead_rule
      when: 'true'
      action: block
"""

_POLICY_WITH_INVALID_CEL = """\
version: "1.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    - name: bad_rule
      when: '%%% not valid CEL'
      action: block
"""

_POLICY_WITH_NON_COMPUTABLE_TRIFECTA = """\
version: "1.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    - name: bad_trifecta
      when: 'trifecta.contains("reaches_external")'
      action: block
"""

_POLICY_WITH_SOURCE_EQUALITY = """\
version: "1.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    - name: source_check
      when: 't.source == "web_search"'
      action: block
"""

_POLICY_WITH_SOURCE_INEQUALITY = """\
version: "1.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    - name: source_check
      when: 't.source != "web_search"'
      action: block
"""

_POLICY_WITH_LINEAGE_ONLY = """\
version: "1.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    - name: lineage_check
      when: 't.lineage.exists(s, s == "web_search")'
      action: block
"""

_POLICY_SCHEMA_ERROR = """\
not_a_valid_field: true
"""

_POLICY_WITH_NON_COMPUTABLE_AGENT_FIELD = """\
version: "1.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    - name: bad_agent_field
      when: 'agent.role == "billing"'
      action: block
"""

_POLICY_WITH_AGENT_ID_ONLY = """\
version: "1.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    - name: agent_id_only
      when: 'agent.id == "x"'
      action: block
"""

_POLICY_WITH_IDENTITY_ONLY_ALLOW = """\
version: "1.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    - name: identity_only_allow
      when: 'agent.id == "x"'
      action: allow
"""

_POLICY_WITH_IDENTITY_AND_TAINT_ALLOW = """\
version: "1.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    - name: identity_and_taint
      when: 'agent.id == "x" && max_trust == "trusted"'
      action: allow
"""

_POLICY_WITH_VACUOUS_TAINT_ALL_ALLOW = """\
version: "1.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    - name: vacuous_allow
      when: 'agent.id == "x" && taint.all(t, t.trust == "trusted")'
      action: allow
"""

_POLICY_WITH_TAINT_ALL_BLOCK = """\
version: "1.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
    - name: taint_all_block
      when: 'taint.all(t, t.trust == "trusted")'
      action: block
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
        assert doc.version == "1.0"
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
version: "1.0"
defaults:
  sink_action: allow
  fail_mode: enforce
sources: []
sinks: {}
"""
        mocker.patch("builtins.open", mocker.mock_open(read_data=yaml_with_fail_mode))
        doc = load_policy_document("fake.yaml")
        assert doc.defaults.fail_mode == Mode.ENFORCE


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

    def test_non_computable_trifecta_leg(self, mocker: MockerFixture) -> None:
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data=_POLICY_WITH_NON_COMPUTABLE_TRIFECTA),
        )
        problems = validate_policy("fake.yaml")
        assert any("not computed" in p for p in problems)

    def test_schema_error_returns_field_problems(self, mocker: MockerFixture) -> None:
        mocker.patch("builtins.open", mocker.mock_open(read_data=_POLICY_SCHEMA_ERROR))
        problems = validate_policy("fake.yaml")
        assert len(problems) > 0

    def test_two_catch_alls_produces_unreachable_problem(
        self, mocker: MockerFixture
    ) -> None:
        yaml_two_catch_alls = """\
version: "1.0"
defaults:
  sink_action: allow
sources: []
sinks:
  default.tool:
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


class TestComputePolicyFingerprint:
    _BASE_YAML = """\
version: "1.0"
defaults:
  sink_action: allow
sources:
  - name: web_search
    trust: untrusted
sinks:
  default.tool:
    - name: block_untrusted
      when: 'taint.any(t, t.trust == "untrusted")'
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
version: "1.0"
sources:
  - trust: untrusted
    name: web_search
sinks:
  default.tool:
    - when: 'taint.any(t, t.trust == "untrusted")'
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
version: "1.0"
defaults:
  sink_action: allow
sources:
  - name: web_search
    trust: untrusted
sinks:
  default.tool:
    - name: default
      action: allow
    - name: block_untrusted
      when: 'taint.any(t, t.trust == "untrusted")'
      action: block
"""
        original = self._fingerprint_of(mocker, self._BASE_YAML)
        edited = self._fingerprint_of(mocker, reordered_rules)
        assert original != edited

    def test_default_policy_fingerprint_stable_across_calls(self) -> None:
        assert default_policy().fingerprint == default_policy().fingerprint
