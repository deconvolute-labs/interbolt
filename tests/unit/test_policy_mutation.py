"""Mechanical perturbations of a correct policy must never be silent.

Every mutation of the reference policy has to be caught somewhere: rejected at
load, reported by `validate`, or visible in a `Decision`. A mutation caught by
none of the three is a silent policy defect, and that is what each test here
fails on.

There is no allowlist of expected-silent mutants. The reference policy and the
probe corpus are shaped so that no mutation is silent, and `TestReferencePolicy`
asserts the properties that make that true, so widening the policy without
widening the probes fails loudly instead of weakening the suite.
"""

from __future__ import annotations

import copy
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NamedTuple

import pytest
import yaml

from interbolt import NullReporter, Policy, configure, taint
from interbolt.errors import InterboltConfigError, PolicyEvaluationError
from interbolt.models.core import Action
from interbolt.policy.schema import validate_policy

REFERENCE_PATH = Path(__file__).parent.parent / "policies" / "mutation_reference.yaml"

Document = dict[str, Any]
Signature = tuple[str, str | None]
Path_ = tuple[str, ...]

# Keys directly under these are integrator-chosen names (tool names, agent
# ids), so renaming one is a real policy edit rather than something
# `extra="forbid"` should reject.
_FREE_FORM_PARENTS = frozenset({("sinks",), ("agents",)})

# Long enough that it cannot collide with a key any policy model declares.
_MANGLE_SUFFIX = "_not_a_policy_key"
_RENAME_SUFFIX = "_renamed"

_REFERENCE: Document = yaml.safe_load(REFERENCE_PATH.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------


class Probe(NamedTuple):
    tool: str
    args: dict[str, Any]
    agent_id: str


def _probes() -> tuple[Probe, ...]:
    """One probe per rule in the reference policy, plus one falling through.

    Rebuilt per call so each run gets its own labels rather than sharing
    value ids across every mutant in the session.
    """
    web = taint("from the web", source="web_search")
    kb = taint("from the knowledge base", source="internal_kb")
    undeclared = taint("from an undeclared source", source="scraper")
    billing = "billing-agent"
    support = "support-agent"
    return (
        Probe("crm.query_customers", {"q": web}, billing),
        Probe("crm.query_customers", {"q": undeclared}, billing),
        Probe("crm.query_customers", {"q": kb}, billing),
        Probe("email.send_email", {"to": "a@external.com", "body": web}, billing),
        Probe("email.send_email", {"to": "a@internal.com", "body": web}, billing),
        Probe("email.send_email", {"to": "a@internal.com", "body": "plain"}, billing),
        Probe("fs.write", {"path": "notes.txt", "data": web}, billing),
        Probe("fs.write", {"path": "notes.txt", "data": web}, support),
        Probe("fs.write", {"path": "notes.txt", "data": "plain"}, billing),
        Probe("default.unlisted", {"x": "plain"}, billing),
    )


def _signatures(policy: Policy) -> tuple[Signature, ...]:
    """Run the probe corpus against `policy` and return what each one decided."""
    runtime = configure(policy=policy, reporter=NullReporter(), mode="enforce")
    return tuple(
        (decision.action.value, decision.matched_rule)
        for index, probe in enumerate(_probes())
        for decision in [
            runtime.check(
                tool=probe.tool,
                args=probe.args,
                agent_id=probe.agent_id,
                run_id=f"mutation-probe-{index}",
            )
        ]
    )


# ---------------------------------------------------------------------------
# Baseline and the observation harness
# ---------------------------------------------------------------------------


class Baseline(NamedTuple):
    signatures: tuple[Signature, ...]
    problems: frozenset[str]


@pytest.fixture(scope="module")
def baseline() -> Baseline:
    policy = Policy.from_file(str(REFERENCE_PATH))
    return Baseline(
        signatures=_signatures(policy),
        problems=frozenset(validate_policy(str(REFERENCE_PATH))),
    )


@pytest.fixture(autouse=True)
def _isolate_runtime(reset_runtime: None) -> None:
    """Keep this module's many `configure()` calls out of the process-global slot."""


@pytest.fixture(autouse=True)
def _pin_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stop an ambient mode override from collapsing every probe onto allow."""
    monkeypatch.delenv("INTERBOLT_MODE", raising=False)
    monkeypatch.delenv("INTERBOLT_AUDIT", raising=False)


@dataclass(frozen=True)
class Observation:
    """How a mutant differs observably from the reference policy."""

    rejected: str | None = None
    new_problems: tuple[str, ...] = ()
    signature_diff: str | None = None

    @property
    def observed(self) -> bool:
        return bool(self.rejected or self.new_problems or self.signature_diff)


def _write(document: Document, tmp_path: Path) -> Path:
    path = tmp_path / "mutant.yaml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


def _observe(document: Document, tmp_path: Path, baseline: Baseline) -> Observation:
    path = _write(document, tmp_path)
    try:
        policy = Policy.from_file(str(path))
    except (InterboltConfigError, PolicyEvaluationError) as exc:
        return Observation(rejected=str(exc))
    new_problems = tuple(
        problem
        for problem in validate_policy(str(path))
        if problem not in baseline.problems
    )
    signatures = _signatures(policy)
    return Observation(
        new_problems=new_problems,
        signature_diff=(
            None
            if signatures == baseline.signatures
            else f"{baseline.signatures} -> {signatures}"
        ),
    )


def _assert_observable(mutant: Mutant, tmp_path: Path, baseline: Baseline) -> None:
    observation = _observe(mutant.document, tmp_path, baseline)
    assert observation.observed, (
        f"mutation {mutant.id!r} is invisible: the policy loads, validate "
        f"reports nothing new, and every probe still decides "
        f"{baseline.signatures}"
    )


def _assert_decision_changed(
    mutant: Mutant, tmp_path: Path, baseline: Baseline
) -> None:
    observation = _observe(mutant.document, tmp_path, baseline)
    assert observation.rejected is None, (
        f"mutation {mutant.id!r} was expected to change a decision but was "
        f"rejected at load: {observation.rejected}"
    )
    assert observation.signature_diff is not None, (
        f"mutation {mutant.id!r} left every probe deciding {baseline.signatures}"
    )


# ---------------------------------------------------------------------------
# Mutation catalog
# ---------------------------------------------------------------------------


class Mutant(NamedTuple):
    id: str
    document: Document


def _mutant_id(mutant: Mutant) -> str:
    return mutant.id


def _schema_key_paths(node: object, prefix: Path_ = ()) -> Iterator[Path_]:
    """Every schema-keyed mapping key in `node`, deepest last.

    Keys under a free-form parent are skipped, since those are names the
    integrator chose rather than keys a policy model declares.
    """
    if isinstance(node, dict):
        free_form = prefix in _FREE_FORM_PARENTS
        for key, value in node.items():
            child = (*prefix, str(key))
            if not free_form:
                yield child
            yield from _schema_key_paths(value, child)
    elif isinstance(node, list):
        for index, item in enumerate(node):
            yield from _schema_key_paths(item, (*prefix, str(index)))


def _model_mapping_paths(node: object, prefix: Path_ = ()) -> Iterator[Path_]:
    """Every mapping in `node` that a policy model validates.

    A free-form parent is itself a plain dict-typed field rather than a
    model, so adding a key to it declares another sink or agent instead of
    violating a schema.
    """
    if isinstance(node, dict):
        if prefix not in _FREE_FORM_PARENTS:
            yield prefix
        for key, value in node.items():
            yield from _model_mapping_paths(value, (*prefix, str(key)))
    elif isinstance(node, list):
        for index, item in enumerate(node):
            yield from _model_mapping_paths(item, (*prefix, str(index)))


def _node_at(document: Document, path: Path_) -> Any:  # noqa: ANN401
    """The value `path` points at."""
    node: Any = document
    for part in path:
        node = node[int(part)] if isinstance(node, list) else node[part]
    return node


def _container_at(document: Document, path: Path_) -> Any:  # noqa: ANN401
    """The dict or list holding `path`'s last element."""
    return _node_at(document, path[:-1])


def _copy() -> Document:
    return copy.deepcopy(_REFERENCE)


def _rules(document: Document) -> Iterator[tuple[str, list[dict[str, Any]]]]:
    for sink_key, declaration in document["sinks"].items():
        yield sink_key, declaration["rules"]


def _rename_key_mutants() -> list[Mutant]:
    mutants = []
    for path in _schema_key_paths(_REFERENCE):
        document = _copy()
        container = _container_at(document, path)
        container[path[-1] + _MANGLE_SUFFIX] = container.pop(path[-1])
        mutants.append(Mutant(".".join(path), document))
    return mutants


def _add_unknown_key_mutants() -> list[Mutant]:
    """Renaming a key only reaches `extra="forbid"` on a model with an optional field.

    On a model whose fields are all required, a rename trips the
    missing-field path instead and would pass even with the model left
    permissive, so an unknown key has to be added outright.
    """
    mutants = []
    for path in _model_mapping_paths(_REFERENCE):
        document = _copy()
        _node_at(document, path)[_MANGLE_SUFFIX] = "unexpected"
        mutants.append(Mutant(".".join(path) or "<document>", document))
    return mutants


def _rename_identifier_mutants() -> list[Mutant]:
    mutants = []
    for sink_key in _REFERENCE["sinks"]:
        document = _copy()
        document["sinks"][sink_key + _RENAME_SUFFIX] = document["sinks"].pop(sink_key)
        mutants.append(Mutant(f"sink:{sink_key}", document))
    for agent_id in _REFERENCE["agents"]:
        document = _copy()
        document["agents"][agent_id + _RENAME_SUFFIX] = document["agents"].pop(agent_id)
        mutants.append(Mutant(f"agent:{agent_id}", document))
    for agent_id, declaration in _REFERENCE["agents"].items():
        for index, group in enumerate(declaration["groups"]):
            document = _copy()
            document["agents"][agent_id]["groups"][index] = group + _RENAME_SUFFIX
            mutants.append(Mutant(f"group:{agent_id}.{group}", document))
    # An untrusted declaration's name is inert; TestUntrustedSourceIsInert
    # asserts that directly instead.
    for index, source in enumerate(_REFERENCE["sources"]):
        if source["trust"] != "trusted":
            continue
        document = _copy()
        document["sources"][index]["name"] = source["name"] + _RENAME_SUFFIX
        mutants.append(Mutant(f"source:{source['name']}", document))
    return mutants


def _drop_when_mutants() -> list[Mutant]:
    mutants = []
    for sink_key, rules in _rules(_REFERENCE):
        for index, rule in enumerate(rules):
            if "when" not in rule:
                continue
            document = _copy()
            del document["sinks"][sink_key]["rules"][index]["when"]
            mutants.append(Mutant(f"{sink_key}.{rule['name']}", document))
    return mutants


def _change_action_mutants() -> list[Mutant]:
    mutants = []
    for sink_key, rules in _rules(_REFERENCE):
        for index, rule in enumerate(rules):
            for action in Action:
                if action.value == rule["action"]:
                    continue
                document = _copy()
                document["sinks"][sink_key]["rules"][index]["action"] = action.value
                mutants.append(
                    Mutant(f"{sink_key}.{rule['name']}->{action.value}", document)
                )
    for action in Action:
        if action.value == _REFERENCE["defaults"]["sink_action"]:
            continue
        document = _copy()
        document["defaults"]["sink_action"] = action.value
        mutants.append(Mutant(f"defaults.sink_action->{action.value}", document))
    return mutants


def _swap_rules_mutants() -> list[Mutant]:
    mutants = []
    for sink_key, rules in _rules(_REFERENCE):
        for index in range(len(rules) - 1):
            document = _copy()
            mutated = document["sinks"][sink_key]["rules"]
            mutated[index], mutated[index + 1] = mutated[index + 1], mutated[index]
            mutants.append(
                Mutant(
                    f"{sink_key}.{rules[index]['name']}<->{rules[index + 1]['name']}",
                    document,
                )
            )
    return mutants


def _delete_rule_mutants() -> list[Mutant]:
    mutants = []
    for sink_key, rules in _rules(_REFERENCE):
        for index, rule in enumerate(rules):
            document = _copy()
            del document["sinks"][sink_key]["rules"][index]
            mutants.append(Mutant(f"{sink_key}.{rule['name']}", document))
    return mutants


def _delete_sink_mutants() -> list[Mutant]:
    mutants = []
    for sink_key in _REFERENCE["sinks"]:
        document = _copy()
        del document["sinks"][sink_key]
        mutants.append(Mutant(sink_key, document))
    return mutants


def _flip_trust_mutants() -> list[Mutant]:
    mutants = []
    for index, source in enumerate(_REFERENCE["sources"]):
        flipped = "trusted" if source["trust"] == "untrusted" else "untrusted"
        document = _copy()
        document["sources"][index]["trust"] = flipped
        mutants.append(Mutant(f"{source['name']}->{flipped}", document))
    return mutants


def _delete_source_mutants() -> list[Mutant]:
    # Deleting an untrusted declaration is inert by the default-deny rule;
    # TestUntrustedSourceIsInert asserts that directly instead.
    mutants = []
    for index, source in enumerate(_REFERENCE["sources"]):
        if source["trust"] != "trusted":
            continue
        document = _copy()
        del document["sources"][index]
        mutants.append(Mutant(source["name"], document))
    return mutants


def _drop_capability_mutants() -> list[Mutant]:
    mutants = []
    for sink_key, declaration in _REFERENCE["sinks"].items():
        for index, capability in enumerate(declaration["capabilities"]):
            document = _copy()
            del document["sinks"][sink_key]["capabilities"][index]
            mutants.append(Mutant(f"{sink_key}:{capability}", document))
    return mutants


def _drop_capabilities_key_mutants() -> list[Mutant]:
    mutants = []
    for sink_key in _REFERENCE["sinks"]:
        document = _copy()
        del document["sinks"][sink_key]["capabilities"]
        mutants.append(Mutant(sink_key, document))
    return mutants


_RENAME_KEY = _rename_key_mutants()
_ADD_UNKNOWN_KEY = _add_unknown_key_mutants()
_RENAME_IDENTIFIER = _rename_identifier_mutants()
_DROP_WHEN = _drop_when_mutants()
_CHANGE_ACTION = _change_action_mutants()
_SWAP_RULES = _swap_rules_mutants()
_DELETE_RULE = _delete_rule_mutants()
_DELETE_SINK = _delete_sink_mutants()
_FLIP_TRUST = _flip_trust_mutants()
_DELETE_SOURCE = _delete_source_mutants()
_DROP_CAPABILITY = _drop_capability_mutants()
_DROP_CAPABILITIES_KEY = _drop_capabilities_key_mutants()


# ---------------------------------------------------------------------------
# The properties that let the suite run without an allowlist
# ---------------------------------------------------------------------------


class TestReferencePolicy:
    def test_validates_clean(self) -> None:
        assert validate_policy(str(REFERENCE_PATH)) == []

    def test_every_rule_is_reached_by_a_probe(self, baseline: Baseline) -> None:
        reached: dict[str, set[str | None]] = {}
        for probe, signature in zip(_probes(), baseline.signatures, strict=True):
            reached.setdefault(probe.tool, set()).add(signature[1])
        for sink_key, rules in _rules(_REFERENCE):
            assert reached.get(sink_key) == {rule["name"] for rule in rules}, sink_key

    def test_a_probe_falls_through_to_the_default(self, baseline: Baseline) -> None:
        assert (_REFERENCE["defaults"]["sink_action"], None) in baseline.signatures

    def test_actions_within_a_sink_are_distinct(self) -> None:
        for sink_key, rules in _rules(_REFERENCE):
            actions = [rule["action"] for rule in rules]
            assert len(set(actions)) == len(actions), sink_key

    def test_every_sink_ends_in_a_catch_all(self) -> None:
        for sink_key, rules in _rules(_REFERENCE):
            assert "when" not in rules[-1], sink_key
            assert all("when" in rule for rule in rules[:-1]), sink_key

    def test_catch_all_action_differs_from_the_default(self) -> None:
        default_action = _REFERENCE["defaults"]["sink_action"]
        for sink_key, rules in _rules(_REFERENCE):
            assert rules[-1]["action"] != default_action, sink_key

    def test_every_declared_capability_is_read_by_a_rule(self) -> None:
        conditions = [
            rule["when"]
            for _key, rules in _rules(_REFERENCE)
            for rule in rules
            if "when" in rule
        ]
        for sink_key, declaration in _REFERENCE["sinks"].items():
            for capability in declaration["capabilities"]:
                reference = f'trifecta.contains("{capability}")'
                assert any(reference in when for when in conditions), (
                    f"{sink_key} declares {capability} but no rule reads it, so "
                    "dropping it would be a silent mutation"
                )


# ---------------------------------------------------------------------------
# Mutation families
# ---------------------------------------------------------------------------


class TestRenameSchemaKey:
    """A misspelled key must fail at load rather than being silently ignored."""

    @pytest.mark.parametrize("mutant", _RENAME_KEY, ids=_mutant_id)
    def test_rejected_at_load(self, mutant: Mutant, tmp_path: Path) -> None:
        with pytest.raises((InterboltConfigError, PolicyEvaluationError)):
            Policy.from_file(str(_write(mutant.document, tmp_path)))


class TestAddUnknownKey:
    """An unknown key must fail at load rather than being silently ignored."""

    @pytest.mark.parametrize("mutant", _ADD_UNKNOWN_KEY, ids=_mutant_id)
    def test_rejected_at_load(self, mutant: Mutant, tmp_path: Path) -> None:
        with pytest.raises((InterboltConfigError, PolicyEvaluationError)):
            Policy.from_file(str(_write(mutant.document, tmp_path)))


class TestRenameIdentifier:
    @pytest.mark.parametrize("mutant", _RENAME_IDENTIFIER, ids=_mutant_id)
    def test_changes_a_decision(
        self, mutant: Mutant, tmp_path: Path, baseline: Baseline
    ) -> None:
        _assert_decision_changed(mutant, tmp_path, baseline)


class TestDropWhen:
    @pytest.mark.parametrize("mutant", _DROP_WHEN, ids=_mutant_id)
    def test_is_observable(
        self, mutant: Mutant, tmp_path: Path, baseline: Baseline
    ) -> None:
        _assert_observable(mutant, tmp_path, baseline)


class TestChangeAction:
    @pytest.mark.parametrize("mutant", _CHANGE_ACTION, ids=_mutant_id)
    def test_changes_a_decision(
        self, mutant: Mutant, tmp_path: Path, baseline: Baseline
    ) -> None:
        _assert_decision_changed(mutant, tmp_path, baseline)


class TestSwapRules:
    @pytest.mark.parametrize("mutant", _SWAP_RULES, ids=_mutant_id)
    def test_is_observable(
        self, mutant: Mutant, tmp_path: Path, baseline: Baseline
    ) -> None:
        _assert_observable(mutant, tmp_path, baseline)


class TestDeleteRule:
    @pytest.mark.parametrize("mutant", _DELETE_RULE, ids=_mutant_id)
    def test_changes_a_decision(
        self, mutant: Mutant, tmp_path: Path, baseline: Baseline
    ) -> None:
        _assert_decision_changed(mutant, tmp_path, baseline)


class TestDeleteSink:
    @pytest.mark.parametrize("mutant", _DELETE_SINK, ids=_mutant_id)
    def test_changes_a_decision(
        self, mutant: Mutant, tmp_path: Path, baseline: Baseline
    ) -> None:
        _assert_decision_changed(mutant, tmp_path, baseline)


class TestFlipSourceTrust:
    @pytest.mark.parametrize("mutant", _FLIP_TRUST, ids=_mutant_id)
    def test_changes_a_decision(
        self, mutant: Mutant, tmp_path: Path, baseline: Baseline
    ) -> None:
        _assert_decision_changed(mutant, tmp_path, baseline)


class TestDeleteTrustedSource:
    @pytest.mark.parametrize("mutant", _DELETE_SOURCE, ids=_mutant_id)
    def test_changes_a_decision(
        self, mutant: Mutant, tmp_path: Path, baseline: Baseline
    ) -> None:
        _assert_decision_changed(mutant, tmp_path, baseline)


class TestDropCapability:
    @pytest.mark.parametrize("mutant", _DROP_CAPABILITY, ids=_mutant_id)
    def test_is_observable(
        self, mutant: Mutant, tmp_path: Path, baseline: Baseline
    ) -> None:
        _assert_observable(mutant, tmp_path, baseline)


class TestDropCapabilitiesKey:
    @pytest.mark.parametrize("mutant", _DROP_CAPABILITIES_KEY, ids=_mutant_id)
    def test_is_reported_by_validate(
        self, mutant: Mutant, tmp_path: Path, baseline: Baseline
    ) -> None:
        observation = _observe(mutant.document, tmp_path, baseline)
        assert observation.new_problems, (
            f"dropping capabilities from {mutant.id!r} drew no validate warning"
        )


class TestUntrustedSourceIsInert:
    """The one carve-out, asserted rather than assumed.

    An undeclared source already resolves untrusted, and `t.lineage` matches
    the name recorded at the `taint()` call rather than the one in the table,
    so neither deleting nor renaming an untrusted declaration can change
    anything. This is why the two source families skip them.
    """

    def test_deleting_it_changes_nothing(
        self, tmp_path: Path, baseline: Baseline
    ) -> None:
        document = _copy()
        document["sources"] = [
            source for source in document["sources"] if source["trust"] != "untrusted"
        ]
        assert not _observe(document, tmp_path, baseline).observed

    def test_renaming_it_changes_nothing(
        self, tmp_path: Path, baseline: Baseline
    ) -> None:
        document = _copy()
        for source in document["sources"]:
            if source["trust"] == "untrusted":
                source["name"] += _RENAME_SUFFIX
        assert not _observe(document, tmp_path, baseline).observed
