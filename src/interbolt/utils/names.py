"""Identifier validation shared across the library: agent ids, groups, tool names."""

from __future__ import annotations

import re

from interbolt.errors import InterboltConfigError

_ENDORSEMENT_KIND_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")
_AGENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")
_GROUP_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")


def validate_agent_id(value: str) -> None:
    """Reject an agent id with characters outside the safe identifier set.

    Charset only. `agent_id` is a CEL-comparable value once exposed in the
    policy context (`agent.id`), so it is constrained the same way
    `validate_endorsement_kind` constrains an endorsement kind.

    Args:
        value: The candidate agent id.

    Raises:
        InterboltConfigError: If `value` contains a character outside
            `[A-Za-z0-9_.-]`, or is empty.
    """
    if not _AGENT_ID_PATTERN.match(value):
        raise InterboltConfigError(
            f"agent_id {value!r} must match {_AGENT_ID_PATTERN.pattern!r}"
        )


def validate_group_name(value: str) -> None:
    """Reject a group name with characters outside the safe identifier set.

    A group name is matched as a string literal inside a policy's `when:`
    CEL text (`agent.groups.any(g, g == "...")`); constraining its
    charset keeps every declared group name expressible as a plain CEL
    string literal with no escaping question.

    Args:
        value: The candidate group name.

    Raises:
        InterboltConfigError: If `value` contains a character outside
            `[A-Za-z0-9_.-]`, or is empty.
    """
    if not _GROUP_NAME_PATTERN.match(value):
        raise InterboltConfigError(
            f"group name {value!r} must match {_GROUP_NAME_PATTERN.pattern!r}"
        )


def validate_endorsement_kind(value: str) -> None:
    """Reject an endorsement kind with characters outside the safe identifier set.

    `kind` is interpolated into compiled CEL source (`SinkRule.require_endorsement`
    schema sugar), so an unconstrained character such as a quote could rewrite the
    compiled predicate's semantics.

    Args:
        value: The candidate endorsement kind.

    Raises:
        InterboltConfigError: If `value` contains a character outside
            `[A-Za-z0-9_.-]`, or is empty.
    """
    if not _ENDORSEMENT_KIND_PATTERN.match(value):
        raise InterboltConfigError(
            f"endorsement kind {value!r} must match "
            f"{_ENDORSEMENT_KIND_PATTERN.pattern!r}"
        )


def validate_qualified_name_part(value: str, *, part: str) -> None:
    """Reject a namespace or tool name that contains a dot.

    A dot in either half would make the dotted `namespace.tool` surface
    ambiguous to parse back apart.

    Args:
        value: The candidate namespace or tool name.
        part: Which part this is, for the error message ("namespace" or "tool").

    Raises:
        InterboltConfigError: If `value` contains a dot.
    """
    if "." in value:
        raise InterboltConfigError(f"{part} {value!r} may not contain a dot")


def split_qualified_name(value: str) -> tuple[str, str] | None:
    """Split a dotted `namespace.tool` name into its validated halves.

    Args:
        value: The candidate qualified name.

    Returns:
        The `(namespace, tool)` pair, or `None` if `value` has no dot.

    Raises:
        InterboltConfigError: If the namespace or tool half itself contains a dot.
    """
    namespace, separator, tool = value.rpartition(".")
    if not separator:
        return None
    validate_qualified_name_part(namespace, part="namespace")
    validate_qualified_name_part(tool, part="tool")
    return namespace, tool
