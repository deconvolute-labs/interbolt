from __future__ import annotations

import re

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from interbolt.constants import TRIFECTA_COMPUTABLE_LEGS
from interbolt.errors import InterboltConfigError, PolicyEvaluationError
from interbolt.models.core import Action, Mode, TrustLevel, validate_qualified_name_part

_TRIFECTA_LEG_PATTERN = re.compile(r"trifecta\.contains\(\s*[\"']([^\"']+)[\"']\s*\)")


class SourceDeclaration(BaseModel):
    """A declared ingress source and the trust level it resolves to."""

    model_config = ConfigDict(frozen=True)

    name: str
    trust: TrustLevel


class Defaults(BaseModel):
    """Default-deny posture for sources and sinks not otherwise declared."""

    model_config = ConfigDict(frozen=True)

    source_trust: TrustLevel = TrustLevel.UNTRUSTED
    sink_action: Action = Action.REQUIRE_APPROVAL
    fail_mode: Mode = Mode.ENFORCE


class SinkRule(BaseModel):
    """One ordered rule within a sink's rule list. First match wins."""

    model_config = ConfigDict(frozen=True)

    name: str
    when: str | None = None
    action: Action


def _split_sink_key(key: str) -> tuple[str, str]:
    namespace, separator, tool = key.rpartition(".")
    if not separator:
        raise InterboltConfigError(
            f"sink key {key!r} must be a dotted 'namespace.tool' name"
        )
    validate_qualified_name_part(namespace, part="namespace")
    validate_qualified_name_part(tool, part="tool")
    return namespace, tool


class PolicyDocument(BaseModel):
    """The validated shape of a policy YAML file."""

    model_config = ConfigDict(frozen=True)

    version: str
    defaults: Defaults
    sources: tuple[SourceDeclaration, ...] = ()
    sinks: dict[str, tuple[SinkRule, ...]]

    @field_validator("sinks")
    @classmethod
    def _validate_sink_keys(
        cls, value: dict[str, tuple[SinkRule, ...]]
    ) -> dict[str, tuple[SinkRule, ...]]:
        for key in value:
            _split_sink_key(key)
        return value


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

    Never executes an agent and never observes live taint; this is the
    dynamic counterpart's opposite number (`dry_run` + the audit flag, which
    are in-process instruments). Does not attempt to resolve whether every
    source name referenced inside a `when` expression is declared, since that
    would require walking the CEL AST for string-literal comparisons against
    `t.source`; out of scope for v1's static check.

    Rejects any `when` expression referencing a trifecta leg outside the
    v1-computable set (`{"from_untrusted"}`), since
    `trifecta.contains("reaches_external")` silently evaluates to `false` at
    runtime rather than failing: a rule built on it never fires, with no
    signal unless caught here.

    Args:
        path: Filesystem path to the policy YAML file.

    Returns:
        A list of human-readable problem descriptions. Empty if the policy is
        valid. Never raises.
    """
    from interbolt.policy.engine import compile_cel_expression

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

    for sink_key, rules in document.sinks.items():
        catch_all_seen = False
        for rule in rules:
            if catch_all_seen:
                problems.append(
                    f"sink {sink_key!r}: rule {rule.name!r} is unreachable, "
                    "placed after an unconditional catch-all rule"
                )
            if rule.when is None:
                if catch_all_seen:
                    problems.append(
                        f"sink {sink_key!r}: more than one unconditional catch-all rule"
                    )
                catch_all_seen = True
                continue
            try:
                compile_cel_expression(rule.when)
            except Exception as exc:  # noqa: BLE001 -- surfacing any compile failure
                problems.append(
                    f"sink {sink_key!r}: rule {rule.name!r} "
                    f"has an invalid CEL expression: {exc}"
                )
            for leg in _TRIFECTA_LEG_PATTERN.findall(rule.when):
                if leg not in TRIFECTA_COMPUTABLE_LEGS:
                    problems.append(
                        f"sink {sink_key!r}: rule {rule.name!r} references "
                        f"trifecta leg {leg!r}, which is not computed in v1 "
                        f"(trifecta.contains({leg!r}) always evaluates false); "
                        f"computable legs are {sorted(TRIFECTA_COMPUTABLE_LEGS)}"
                    )

    return problems
