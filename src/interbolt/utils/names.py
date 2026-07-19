from __future__ import annotations

import re

from interbolt.errors import InterboltConfigError

_ENDORSEMENT_KIND_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")


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
