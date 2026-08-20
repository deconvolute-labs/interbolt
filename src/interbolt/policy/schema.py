"""Policy document schema: the Pydantic models validated from a policy YAML file."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable

import lark
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
    TRIFECTA_FROM_UNTRUSTED,
    TRIFECTA_LEGS,
)
from interbolt.errors import InterboltConfigError, PolicyEvaluationError
from interbolt.models.core import Action, Capability, Mode, TrustLevel
from interbolt.policy.cel import compile_parsed, parse_cel_expression
from interbolt.policy.identity_ast import member_field, string_literal, unwrap_node
from interbolt.policy.shadowing import find_identity_shadowing
from interbolt.utils.names import (
    split_qualified_name,
    validate_agent_id,
    validate_endorsement_kind,
    validate_group_name,
)

_IDENTITY_ONLY_SIGNALS = (
    "taint",
    "max_trust",
    "sources",
    "run.tainted",
    "run.sources",
    "run.untrusted_sources",
    "run.trifecta",
)
_LITERAL_SPAN = re.compile(
    r"""[rRbB]{0,2}(?:'''(?:\\.|[^\\])*?'''|\"\"\"(?:\\.|[^\\])*?\"\"\""""
    r"""|'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*")""",
    re.S,
)


def _code_only(when: str) -> str:
    """Blank every string literal in `when` to spaces of the same length.

    So the text-level lints below cannot mistake a literal's contents for a
    CEL reference. Match offsets into the blanked text still map onto the
    original `when` string.

    This does not make the lints exact: they remain heuristics over CEL text
    rather than its AST, and a semantically equivalent expression written a
    different way can still slip past them. It removes only the
    literal-blindness failure mode, where quoted text was misread as code.
    """
    return _LITERAL_SPAN.sub(lambda m: " " * len(m.group()), when)


def _bare_ident(node: lark.Tree[lark.Token] | lark.Token) -> str | None:
    """Return `node`'s name if it is exactly a bare identifier."""
    node = unwrap_node(node)
    if isinstance(node, lark.Tree) and node.data == "ident":
        token = node.children[0]
        return token.value if isinstance(token, lark.Token) else None
    return None


def _call_args(
    tree: lark.Tree[lark.Token],
    method: str,
    matches_receiver: Callable[[lark.Tree[lark.Token] | lark.Token], bool],
) -> list[lark.Tree[lark.Token]]:
    """Find every `<receiver>.<method>(...)` call in `tree` whose receiver matches.

    `matches_receiver` is applied to the call's receiver node; the call is
    included only when it returns `True`.
    """
    matches: list[lark.Tree[lark.Token]] = []
    for subtree in tree.iter_subtrees():
        if subtree.data != "member_dot_arg" or len(subtree.children) != 3:
            continue
        receiver, method_token, exprlist_node = subtree.children
        if not (isinstance(method_token, lark.Token) and method_token.value == method):
            continue
        if not matches_receiver(receiver):
            continue
        if isinstance(exprlist_node, lark.Tree):
            matches.append(exprlist_node)
    return matches


def _string_literals_in(node: lark.Tree[lark.Token]) -> list[str]:
    """Every string literal value found anywhere within `node`."""
    literals = []
    for subtree in node.iter_subtrees():
        if subtree.data == "literal":
            value = string_literal(subtree)
            if value is not None:
                literals.append(value)
    return literals


def _bound_comparison_literals(exprlist: lark.Tree[lark.Token]) -> list[str]:
    """String literals compared for equality against an `.exists(...)` bound variable.

    Mirrors `identity_ast.recognize_groups_exists`'s bound-variable check, but
    walks every `==`/`!=` comparison in the predicate instead of requiring
    the predicate to be exactly one, so a disjunction of several membership
    checks is still fully covered. Deliberately narrower than "every literal
    in the call": a literal that's an argument to some other nested call
    (`g.startsWith("team-")`) is not a comparison against `g` and is not a
    membership reference.
    """
    if len(exprlist.children) != 2:
        return []
    bound_expr, predicate_expr = exprlist.children
    bound_ident = unwrap_node(bound_expr)
    if not (isinstance(bound_ident, lark.Tree) and bound_ident.data == "ident"):
        return []
    bound_token = bound_ident.children[0]
    if not (
        isinstance(bound_token, lark.Token) and isinstance(predicate_expr, lark.Tree)
    ):
        return []
    literals = []
    for subtree in predicate_expr.iter_subtrees():
        if subtree.data != "relation" or len(subtree.children) != 2:
            continue
        op_node, rhs_node = subtree.children
        if not (
            isinstance(op_node, lark.Tree)
            and op_node.data in ("relation_eq", "relation_ne")
        ):
            continue
        lhs = unwrap_node(op_node.children[0])
        if not (isinstance(lhs, lark.Tree) and lhs.data == "ident"):
            continue
        lhs_token = lhs.children[0]
        if not (
            isinstance(lhs_token, lark.Token) and lhs_token.value == bound_token.value
        ):
            continue
        literal = string_literal(rhs_node)
        if literal is not None:
            literals.append(literal)
    return literals


def _bare_fields(tree: lark.Tree[lark.Token], receiver: str) -> list[str]:
    """Every `<receiver>.<field>` bare access found anywhere in `tree`."""
    fields = []
    for subtree in tree.iter_subtrees():
        if subtree.data != "member_dot":
            continue
        field = member_field(subtree, receiver)
        if field is not None and field not in fields:
            fields.append(field)
    return fields


def _declared_capability_legs(document: PolicyDocument) -> frozenset[str]:
    """Every capability leg any sink entry in `document` declares."""
    return frozenset(
        capability.value
        for declaration in document.sinks.values()
        if declaration.capabilities is not None
        for capability in declaration.capabilities
    )


def _check_trifecta_leg(
    leg: str, document: PolicyDocument, *, sink_key: str, rule_name: str
) -> str | None:
    """The validate problem for referencing `leg` as a trifecta leg, or `None`.

    Applies uniformly to a leg literal found in `trifecta.contains(...)` and
    in `run.trifecta.contains(...)`/`run.trifecta.exists(...)`.
    """
    if leg not in TRIFECTA_LEGS:
        return (
            f"sink {sink_key!r}: rule {rule_name!r} references trifecta leg "
            f"{leg!r}, which is not a trifecta leg; the trifecta legs are "
            f"{sorted(TRIFECTA_LEGS)}"
        )
    if leg == TRIFECTA_FROM_UNTRUSTED:
        return None
    declared_legs = _declared_capability_legs(document)
    if not declared_legs:
        return (
            f"sink {sink_key!r}: rule {rule_name!r} references trifecta leg "
            f"{leg!r}, which is never computed until at least one sink "
            "declares it under `capabilities:`; this reference always "
            "evaluates false as this policy stands"
        )
    if leg not in declared_legs:
        return (
            f"warning: sink {sink_key!r}: rule {rule_name!r} references "
            f"trifecta leg {leg!r}, which no sink in the policy declares "
            "under `capabilities:`, so this reference can never match "
            "under this policy's current declarations"
        )
    return None


def _has_relation(tree: lark.Tree[lark.Token], receiver: str, field: str) -> bool:
    """Whether `tree` contains a `<receiver>.<field> ==`/`!=` comparison."""
    for subtree in tree.iter_subtrees():
        if subtree.data != "relation" or len(subtree.children) != 2:
            continue
        op_node, _rhs = subtree.children
        if (
            isinstance(op_node, lark.Tree)
            and op_node.data in ("relation_eq", "relation_ne")
            and member_field(op_node.children[0], receiver) == field
        ):
            return True
    return False


_BOOLEAN_RELATIONS = frozenset(
    {
        "relation_lt",
        "relation_le",
        "relation_ge",
        "relation_gt",
        "relation_eq",
        "relation_ne",
        "relation_in",
    }
)
_BOOLEAN_METHODS = frozenset(
    {"exists", "all", "exists_one", "contains", "startsWith", "endsWith", "matches"}
)
_BOOLEAN_RUN_FIELDS = frozenset({"tainted", "capability_evicted"})


def _is_boolean_shaped(node: lark.Tree[lark.Token] | lark.Token) -> bool:
    """Whether `node`'s CEL shape is guaranteed to evaluate to a boolean.

    A conservative allowlist over shapes that always produce `BoolType`:
    comparisons, `&&`/`||`, `!`-negation, a bare boolean literal, the
    boolean-returning macros/methods, the two bool-typed bare computable
    fields (`run.tainted`, `run.capability_evicted`), and a ternary whose
    both branches are themselves boolean-shaped. Everything else -- a bare
    field access, a literal, an arithmetic expression -- is unrecognized,
    even where it could coincidentally hold a boolean at runtime (a `bool(x)`
    conversion call, for example): false negatives here are silent, false
    positives break a policy that validates clean today.
    """
    node = unwrap_node(node)
    if not isinstance(node, lark.Tree):
        return False
    if node.data == "relation" and len(node.children) == 2:
        op_node = node.children[0]
        return isinstance(op_node, lark.Tree) and op_node.data in _BOOLEAN_RELATIONS
    if node.data in ("conditionalor", "conditionaland") and len(node.children) == 2:
        return True
    if node.data == "unary" and len(node.children) == 2:
        op_node = node.children[0]
        return isinstance(op_node, lark.Tree) and op_node.data == "unary_not"
    if node.data == "literal":
        token = node.children[0]
        return isinstance(token, lark.Token) and token.type == "BOOL_LIT"
    if node.data == "member_dot_arg" and len(node.children) == 3:
        method_token = node.children[1]
        return (
            isinstance(method_token, lark.Token)
            and method_token.value in _BOOLEAN_METHODS
        )
    if node.data == "member_dot":
        return member_field(node, "run") in _BOOLEAN_RUN_FIELDS
    if node.data == "expr" and len(node.children) == 3:
        return _is_boolean_shaped(node.children[1]) and _is_boolean_shaped(
            node.children[2]
        )
    return False


class SourceDeclaration(BaseModel):
    """A declared ingress source and the trust level it resolves to."""

    model_config = ConfigDict(frozen=True, extra="forbid")

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
    equivalent `when:` CEL text, so most rules needing this never
    hand-write CEL. Mutually exclusive with `when`; a rule may set at most
    one of the two.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

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


class SinkDeclaration(BaseModel):
    """One tool's declaration: what it does, and how calls to it are gated.

    Attributes:
        capabilities: What the tool does with the data it touches, which is
            what makes its `reads_private`/`reaches_external` trifecta legs
            computable. `None` means undeclared, which contributes no legs
            and draws a warning from `interbolt policy validate` once at
            least one sink in the policy declares capabilities. An empty tuple records
            that the tool has neither capability, distinct from `None`.
        rules: The sink's ordered rules, first match wins. An entry with no
            rules falls through to `defaults.sink_action`, exactly as a tool
            absent from `sinks` does.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    capabilities: tuple[Capability, ...] | None = None
    rules: tuple[SinkRule, ...] = ()


def _require_endorsement_when(kind: str) -> str:
    """Synthesize the `when:` text for a `require_endorsement: <kind>` rule.

    Compiles to exactly the kind-matching idiom: gate untrusted data that
    lacks the endorsement this sink requires, matching a source endorsed for
    one kind but not this one (the sanitizer-mismatch case).
    """
    return (
        f'taint.exists(t, t.trust == "untrusted" && '
        f'!t.endorsements.exists(k, k == "{kind}"))'
    )


def rule_when(rule: SinkRule) -> str | None:
    """Return `rule`'s effective CEL `when` text, synthesizing it if needed."""
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


_VERSION_PATTERN = re.compile(r"^2\.\d+$")

_VERSION_1_0_MIGRATION_MESSAGE = (
    'policy document version "1.0" is no longer supported: a `sinks:` '
    "entry is now a mapping with optional `capabilities:` and `rules:` keys "
    "rather than a bare rule list, and the top-level `capabilities:` section "
    'has moved inside each entry. Set `version: "2.x"` and rewrite each '
    "sink entry as `<tool>:\n  rules:\n    - ...`. See "
    "<https://docs.deconvolutelabs.com/docs/concepts/policies>"
)


def _check_not_pre_2_0_shape(data: object) -> None:
    """Raise `InterboltConfigError` if raw `data` is the pre-2.0 policy shape.

    Checked on the raw, not-yet-validated mapping rather than inside a
    Pydantic validator: `InterboltConfigError` subclasses `ValueError`, and a
    `ValueError` raised inside a Pydantic validator is caught and rewrapped
    as `pydantic.ValidationError`, which would prevent this specific,
    migration-pointing message from ever reaching a caller.
    """
    if not isinstance(data, dict):
        return
    version = data.get("version")
    sinks = data.get("sinks")
    is_old_version = version == "1.0"
    is_bare_rule_list = isinstance(sinks, dict) and any(
        isinstance(value, list) for value in sinks.values()
    )
    if is_old_version or is_bare_rule_list:
        raise InterboltConfigError(_VERSION_1_0_MIGRATION_MESSAGE)


class PolicyDocument(BaseModel):
    """The validated shape of a policy YAML file.

    Attributes:
        sinks: One `SinkDeclaration` per guarded tool, keyed by the dotted
            `namespace.tool` name. A tool absent from this mapping falls
            through to `defaults.sink_action` and contributes no trifecta
            capability legs.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: str
    defaults: Defaults
    sources: tuple[SourceDeclaration, ...] = ()
    agents: dict[str, AgentDeclaration] = {}
    sinks: dict[str, SinkDeclaration]

    @field_validator("version")
    @classmethod
    def _validate_version(cls, value: str) -> str:
        if not _VERSION_PATTERN.fullmatch(value):
            raise ValueError(
                f"policy document version {value!r} is not supported; the "
                'supported versions are "2.x" (for example "2.0")'
            )
        return value

    @field_validator("sinks")
    @classmethod
    def _validate_sink_keys(
        cls, value: dict[str, SinkDeclaration]
    ) -> dict[str, SinkDeclaration]:
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
        InterboltConfigError: If the file uses the pre-2.0 policy shape
            (`version: "1.0"`, or a `sinks:` entry written as a bare rule
            list).
    """
    try:
        with open(path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except (OSError, yaml.YAMLError) as exc:
        raise PolicyEvaluationError(
            f"failed to read policy file {path!r}: {exc}"
        ) from exc
    _check_not_pre_2_0_shape(data)
    try:
        return PolicyDocument.model_validate(data)
    except ValidationError as exc:
        raise PolicyEvaluationError(f"policy file {path!r} is invalid: {exc}") from exc


def validate_policy(path: str) -> list[str]:
    """Statically analyze a policy file: schema, CEL compilation, dead rules.

    Performs schema and CEL checks only, so it is safe to run in CI without
    executing the agent.

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
        _check_not_pre_2_0_shape(data)
    except InterboltConfigError as exc:
        return [str(exc)]

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

    any_tool_declares_capabilities = any(
        declaration.capabilities is not None for declaration in document.sinks.values()
    )

    for sink_key, declaration in document.sinks.items():
        rules = declaration.rules
        if any_tool_declares_capabilities and declaration.capabilities is None:
            problems.append(
                f"warning: sink {sink_key!r} does not declare "
                "`capabilities:`, so no trifecta capability leg is computed "
                "for it; declare its capabilities, or declare an empty list "
                "to record that it has none"
            )
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
            tree: lark.Tree[lark.Token] | None = None
            try:
                parsed_tree = parse_cel_expression(when)
            except Exception as exc:  # noqa: BLE001 -- surfacing any parse failure
                problems.append(
                    f"sink {sink_key!r}: rule {rule.name!r} "
                    f"has an invalid CEL expression: {exc}"
                )
            else:
                try:
                    compile_parsed(parsed_tree)
                except InterboltConfigError as exc:
                    problems.append(f"sink {sink_key!r}: rule {rule.name!r} {exc}")
                except Exception as exc:  # noqa: BLE001 -- surfacing any compile failure
                    problems.append(
                        f"sink {sink_key!r}: rule {rule.name!r} "
                        f"has an invalid CEL expression: {exc}"
                    )
                else:
                    tree = parsed_tree
            if tree is not None:
                for exprlist in _call_args(
                    tree, "contains", lambda r: _bare_ident(r) == "trifecta"
                ):
                    for leg in _string_literals_in(exprlist):
                        problem = _check_trifecta_leg(
                            leg, document, sink_key=sink_key, rule_name=rule.name
                        )
                        if problem is not None:
                            problems.append(problem)
                for exprlist in _call_args(
                    tree, "contains", lambda r: member_field(r, "run") == "trifecta"
                ):
                    for leg in _string_literals_in(exprlist):
                        problem = _check_trifecta_leg(
                            leg, document, sink_key=sink_key, rule_name=rule.name
                        )
                        if problem is not None:
                            problems.append(problem)
                for exprlist in _call_args(
                    tree, "exists", lambda r: member_field(r, "run") == "trifecta"
                ):
                    for leg in _bound_comparison_literals(exprlist):
                        problem = _check_trifecta_leg(
                            leg, document, sink_key=sink_key, rule_name=rule.name
                        )
                        if problem is not None:
                            problems.append(problem)
                for field in _bare_fields(tree, "run"):
                    if field not in RUN_COMPUTABLE_FIELDS:
                        problems.append(
                            f"sink {sink_key!r}: rule {rule.name!r} references "
                            f"run.{field!r}, which does not exist; the "
                            f"computable fields are {sorted(RUN_COMPUTABLE_FIELDS)}"
                        )
                for field in _bare_fields(tree, "agent"):
                    if field not in AGENT_COMPUTABLE_FIELDS:
                        problems.append(
                            f"sink {sink_key!r}: rule {rule.name!r} references "
                            f"agent.{field!r}, which does not exist; the only "
                            f"computable field is {sorted(AGENT_COMPUTABLE_FIELDS)}"
                        )
                for exprlist in _call_args(
                    tree,
                    "exists",
                    lambda r: member_field(r, "agent") == "groups",
                ):
                    for group in _bound_comparison_literals(exprlist):
                        if group not in declared_groups:
                            problems.append(
                                f"warning: sink {sink_key!r}: rule "
                                f"{rule.name!r} references group {group!r} "
                                "in an agent.groups membership check, which "
                                "is not declared for any agent in the "
                                "policy's 'agents' section"
                            )
                if _has_relation(tree, "t", "source"):
                    problems.append(
                        f"warning: sink {sink_key!r}: rule {rule.name!r} "
                        "compares t.source directly; a merged label's "
                        "source is only its first contributor, so this can "
                        "silently miss a value formed by merging two "
                        "differently-sourced inputs; use "
                        "t.lineage.exists(s, s == ...) instead"
                    )
                if not _is_boolean_shaped(tree):
                    problems.append(
                        f"warning: sink {sink_key!r}: rule {rule.name!r} has "
                        "a `when` clause that is not verifiably "
                        "boolean-shaped; at runtime a non-boolean result is "
                        "now an evaluation error rather than a silent "
                        "truthy match, so this rule may start blocking "
                        "calls instead of matching them"
                    )
                if rule.action is Action.ALLOW:
                    for field in (
                        "sources",
                        "untrusted_sources",
                        "ingested_by",
                        "trifecta",
                    ):

                        def _matches_run_field(
                            r: lark.Tree[lark.Token] | lark.Token, field: str = field
                        ) -> bool:
                            return member_field(r, "run") == field

                        if _call_args(tree, "all", _matches_run_field):
                            problems.append(
                                f"warning: sink {sink_key!r}: rule "
                                f"{rule.name!r} uses run.{field}.all(...) in "
                                "an allow rule; all evaluates true on a run "
                                "with no recorded ingress (CEL's empty-list "
                                "fold), so this can allow a call in a run "
                                "whose ingress was never recorded; use "
                                f"run.{field}.exists(...) instead"
                            )
            # The identity-only-allow and taint.all(...) checks below ask
            # about a rule's overall shape rather than resolving a specific
            # reference, which is genuinely fuzzy; they stay text heuristics
            # rather than AST recognizers for that reason.
            code = _code_only(when)
            if (
                rule.action is Action.ALLOW
                and "agent." in code
                and not any(signal in code for signal in _IDENTITY_ONLY_SIGNALS)
            ):
                problems.append(
                    f"warning: sink {sink_key!r}: rule {rule.name!r} allows "
                    "based on agent identity alone, with no taint/max_trust/"
                    "sources/run.tainted condition; this grants unconditional "
                    "access to this sink for that agent regardless of "
                    "provenance"
                )
            if rule.action is Action.ALLOW and "taint.all(" in code:
                problems.append(
                    f"warning: sink {sink_key!r}: rule {rule.name!r} uses "
                    "taint.all(...) in an allow rule; taint.all evaluates "
                    "true on a call with zero labels (CEL's empty-list fold), "
                    "so this can allow an unlabeled or laundered call; use "
                    '!taint.exists(t, t.trust == "untrusted") or combine with '
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
