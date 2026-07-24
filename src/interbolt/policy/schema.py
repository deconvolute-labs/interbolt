from __future__ import annotations

import hashlib
import json
import re

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    ValidationError,
    field_validator,
    model_validator,
)

from interbolt.constants import (
    AGENT_COMPUTABLE_FIELDS,
    RUN_COMPUTABLE_FIELDS,
    TRIFECTA_COMPUTABLE_LEGS,
)
from interbolt.errors import InterboltConfigError, PolicyEvaluationError
from interbolt.models.core import Action, Mode, TrustLevel
from interbolt.policy.cel import compile_cel_expression
from interbolt.policy.shadowing import find_identity_shadowing
from interbolt.utils.names import (
    split_qualified_name,
    validate_agent_id,
    validate_endorsement_kind,
    validate_group_name,
)

_TRIFECTA_LEG_PATTERN = re.compile(r"trifecta\.contains\(\s*[\"']([^\"']+)[\"']\s*\)")
_RUN_FIELD_PATTERN = re.compile(r"\brun\.(\w+)")
_AGENT_FIELD_PATTERN = re.compile(r"\bagent\.(\w+)")
_AGENT_GROUPS_MEMBERSHIP_PATTERN = re.compile(
    r"agent\.groups\.(?:exists|any)\(([^)]*)\)"
)
_STRING_LITERAL_PATTERN = re.compile(r"[\"']([^\"']+)[\"']")
_SOURCE_EQUALITY_PATTERN = re.compile(r"\bt\.source\s*(==|!=)")
_IDENTITY_ONLY_SIGNALS = ("taint", "max_trust", "sources", "run.")


class SourceDeclaration(BaseModel):
    """A declared ingress source and the trust level it resolves to."""

    model_config = ConfigDict(frozen=True)

    name: str
    trust: TrustLevel


class AgentDeclaration(BaseModel):
    """One declared agent's group membership.

    Carries no permissions itself; sink rules already grant those. A group
    is a label on the acting principal that a rule's `when:` can test via
    `agent.groups.exists(...)`.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    groups: tuple[str, ...] = ()

    @field_validator("groups")
    @classmethod
    def _validate_group_names(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for group in value:
            validate_group_name(group)
        return value


class Defaults(BaseModel):
    """Default-deny posture for sources and sinks not otherwise declared."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    sink_action: Action = Action.REQUIRE_APPROVAL
    fail_mode: Mode | None = None


class SinkRule(BaseModel):
    """One ordered rule within a sink's rule list. First match wins.

    `require_endorsement` is sugar for the common "gate untrusted data
    lacking this endorsement kind" shape: setting it compiles to the
    equivalent `when:` CEL text (`policy/schema.py:_require_endorsement_when`),
    so most rules needing this never hand-write CEL. Mutually exclusive with
    `when`; a rule may set at most one of the two.
    """

    model_config = ConfigDict(frozen=True)

    name: str
    when: str | None = None
    require_endorsement: str | None = None
    action: Action

    @field_validator("require_endorsement")
    @classmethod
    def _validate_require_endorsement_kind(cls, value: str | None) -> str | None:
        if value is not None:
            validate_endorsement_kind(value)
        return value

    @model_validator(mode="after")
    def _validate_when_xor_require_endorsement(self) -> SinkRule:
        if self.when is not None and self.require_endorsement is not None:
            raise ValueError(
                f"rule {self.name!r}: 'when' and 'require_endorsement' are "
                "mutually exclusive; set at most one"
            )
        return self


def _require_endorsement_when(kind: str) -> str:
    """Synthesize the `when:` text for a `require_endorsement: <kind>` rule.

    Compiles to exactly the kind-matching idiom: gate untrusted data that
    lacks the endorsement this sink requires, matching a source endorsed for
    one kind but not this one (the sanitizer-mismatch case).
    """
    return (
        'taint.any(t, t.trust == "untrusted" && '
        f'!t.endorsements.exists(k, k == "{kind}"))'
    )


def rule_when(rule: SinkRule) -> str | None:
    if rule.require_endorsement is not None:
        return _require_endorsement_when(rule.require_endorsement)
    return rule.when


def _split_sink_key(key: str) -> tuple[str, str]:
    parsed = split_qualified_name(key)
    if parsed is None:
        raise InterboltConfigError(
            f"sink key {key!r} must be a dotted 'namespace.tool' name"
        )
    return parsed


class PolicyDocument(BaseModel):
    """The validated shape of a policy YAML file."""

    model_config = ConfigDict(frozen=True)

    version: str
    defaults: Defaults
    sources: tuple[SourceDeclaration, ...] = ()
    agents: dict[str, AgentDeclaration] = {}
    sinks: dict[str, tuple[SinkRule, ...]]

    @field_validator("sinks")
    @classmethod
    def _validate_sink_keys(
        cls, value: dict[str, tuple[SinkRule, ...]]
    ) -> dict[str, tuple[SinkRule, ...]]:
        for key in value:
            _split_sink_key(key)
        return value

    @field_validator("agents")
    @classmethod
    def _validate_agent_ids(
        cls, value: dict[str, AgentDeclaration]
    ) -> dict[str, AgentDeclaration]:
        for agent_id in value:
            validate_agent_id(agent_id)
        return value


def compute_policy_fingerprint(document: PolicyDocument) -> str:
    """Hash a validated policy document into a stable, algorithm-prefixed fingerprint.

    Hashes the normalized document, not the compiled CEL objects (whose
    serialization is not guaranteed stable across `celpy` versions): a JSON
    dump of `document.model_dump(mode="json")` with sorted object keys, so
    two loads of the same file, or the same file with different key order or
    comments, hash identically, while a rule-order or value change (both
    semantic under first-match-wins policy evaluation) changes the hash.

    Args:
        document: The validated policy document to fingerprint.

    Returns:
        The fingerprint as `"sha256:<hex digest>"`.
    """
    payload = json.dumps(
        document.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    )
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_policy_document(path: str) -> PolicyDocument:
    """Load and validate a policy YAML file against `PolicyDocument`.

    Args:
        path: Filesystem path to the policy YAML file.

    Returns:
        The validated `PolicyDocument`.

    Raises:
        PolicyEvaluationError: If the file cannot be read, is not valid YAML,
            or does not conform to the policy schema.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except (OSError, yaml.YAMLError) as exc:
        raise PolicyEvaluationError(
            f"failed to read policy file {path!r}: {exc}"
        ) from exc
    try:
        return PolicyDocument.model_validate(data)
    except ValidationError as exc:
        raise PolicyEvaluationError(f"policy file {path!r} is invalid: {exc}") from exc


def validate_policy(path: str) -> list[str]:
    """Statically analyze a policy file: schema, CEL compilation, dead rules.

    Performs schema and CEL checks only, so it is safe to run in CI without
    executing the agent. See docs for the full set of
    checks and their limits.

    Args:
        path: Filesystem path to the policy YAML file.

    Returns:
        A list of human-readable problem descriptions, empty if the policy
        is valid. Every error is captured here instead of raised.
    """
    problems: list[str] = []
    try:
        with open(path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except (OSError, yaml.YAMLError) as exc:
        return [f"failed to read policy file {path!r}: {exc}"]

    try:
        document = PolicyDocument.model_validate(data)
    except ValidationError as exc:
        for error in exc.errors():
            location = ".".join(str(part) for part in error["loc"])
            problems.append(f"{location}: {error['msg']}")
        return problems

    declared_groups = frozenset(
        group for decl in document.agents.values() for group in decl.groups
    )
    declared_ids = frozenset(document.agents)
    id_to_groups = {
        agent_id: frozenset(decl.groups) for agent_id, decl in document.agents.items()
    }

    for sink_key, rules in document.sinks.items():
        catch_all_seen = False
        for rule in rules:
            if catch_all_seen:
                problems.append(
                    f"sink {sink_key!r}: rule {rule.name!r} is unreachable, "
                    "placed after an unconditional catch-all rule"
                )
            when = rule_when(rule)
            if when is None:
                if catch_all_seen:
                    problems.append(
                        f"sink {sink_key!r}: more than one unconditional catch-all rule"
                    )
                catch_all_seen = True
                continue
            try:
                compile_cel_expression(when)
            except Exception as exc:  # noqa: BLE001 -- surfacing any compile failure
                problems.append(
                    f"sink {sink_key!r}: rule {rule.name!r} "
                    f"has an invalid CEL expression: {exc}"
                )
            for leg in _TRIFECTA_LEG_PATTERN.findall(when):
                if leg not in TRIFECTA_COMPUTABLE_LEGS:
                    problems.append(
                        f"sink {sink_key!r}: rule {rule.name!r} references "
                        f"trifecta leg {leg!r}, which is not computed in v1 "
                        f"(trifecta.contains({leg!r}) always evaluates false); "
                        f"computable legs are {sorted(TRIFECTA_COMPUTABLE_LEGS)}"
                    )
            for field in _RUN_FIELD_PATTERN.findall(when):
                if field not in RUN_COMPUTABLE_FIELDS:
                    problems.append(
                        f"sink {sink_key!r}: rule {rule.name!r} references "
                        f"run.{field!r}, which does not exist; the only "
                        f"computable field is {sorted(RUN_COMPUTABLE_FIELDS)}"
                    )
            for field in _AGENT_FIELD_PATTERN.findall(when):
                if field not in AGENT_COMPUTABLE_FIELDS:
                    problems.append(
                        f"sink {sink_key!r}: rule {rule.name!r} references "
                        f"agent.{field!r}, which does not exist; the only "
                        f"computable field is {sorted(AGENT_COMPUTABLE_FIELDS)}"
                    )
            for match in _AGENT_GROUPS_MEMBERSHIP_PATTERN.finditer(when):
                for group in _STRING_LITERAL_PATTERN.findall(match.group(1)):
                    if group not in declared_groups:
                        problems.append(
                            f"warning: sink {sink_key!r}: rule {rule.name!r} "
                            f"references group {group!r} in an agent.groups "
                            "membership check, which is not declared for "
                            "any agent in the policy's 'agents' section"
                        )
            if _SOURCE_EQUALITY_PATTERN.search(when):
                problems.append(
                    f"warning: sink {sink_key!r}: rule {rule.name!r} compares "
                    "t.source directly; a merged label's source is only its "
                    "first contributor, so this can silently miss a value "
                    "formed by merging two differently-sourced inputs; use "
                    "t.lineage.any(s, s == ...) instead"
                )
            if (
                rule.action is Action.ALLOW
                and "agent." in when
                and not any(signal in when for signal in _IDENTITY_ONLY_SIGNALS)
            ):
                problems.append(
                    f"warning: sink {sink_key!r}: rule {rule.name!r} allows "
                    "based on agent identity alone, with no taint/max_trust/"
                    "sources/run.tainted condition; this grants unconditional "
                    "access to this sink for that agent regardless of "
                    "provenance"
                )
            if rule.action is Action.ALLOW and "taint.all(" in when:
                problems.append(
                    f"warning: sink {sink_key!r}: rule {rule.name!r} uses "
                    "taint.all(...) in an allow rule; taint.all evaluates "
                    "true on a call with zero labels (CEL's empty-list fold), "
                    "so this can allow an unlabeled or laundered call; use "
                    '!taint.any(t, t.trust == "untrusted") or combine with '
                    "size(taint) > 0 if labeled input is actually required"
                )

        whens = [rule_when(rule) for rule in rules]
        problems.extend(
            find_identity_shadowing(
                sink_key,
                rules,
                whens,
                declared_ids=declared_ids,
                id_to_groups=id_to_groups,
            )
        )

    return problems
