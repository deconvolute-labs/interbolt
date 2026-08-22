"""Policy name grounding: recovering a tool the other detectors could not find.

Every sink key a policy declares is a candidate tool name. A candidate not
already discoverable from source is resolved the same way a schema-literal
name is (`literal.index_module_functions`): by a unique module-level
function name match.

Not yet wired into `scan_repository()`. `--policy` and the CLI surface that
would call this land with coverage computation; this module exists so that
work has the grounding algorithm ready to call.
"""

from __future__ import annotations

import ast

from interbolt.policy import Policy
from interbolt.scan import security
from interbolt.scan.artifact import Discovery, ScanDefinition, ScanTool
from interbolt.scan.literal import index_module_functions
from interbolt.scan.signature import render_signature
from interbolt.utils.names import split_qualified_name


def ground_policy_names(
    trees: dict[str, ast.Module], policy: Policy
) -> tuple[list[ScanTool], list[str]]:
    """Resolve every policy sink key against the scanned source.

    Args:
        trees: Every scanned file's parsed module, keyed by its
            scan-root-relative POSIX path.
        policy: The policy whose declared sink keys become candidate tool
            names. Every key in `policy.document.sinks`, not just
            `policy.tool_capabilities`, is a candidate: a bare entry with
            neither `capabilities:` nor `rules:` is exactly what the
            recovery loop this function supports depends on.

    Returns:
        `(resolved_tools, unresolved_keys)`. A resolved key becomes a
        `ScanTool` with `discovery=Discovery.POLICY_NAME`. A key matching
        zero or more than one function collapses into the same
        "unresolved" outcome, since the caller reports it as an
        `unmatched_policy_sinks` entry, which has no field to distinguish
        the two failure modes the way `UndetectedKind` does.
    """
    functions_by_name = index_module_functions(trees)
    resolved: list[ScanTool] = []
    unresolved: list[str] = []

    for sink_key in policy.document.sinks:
        parsed = split_qualified_name(sink_key)
        if parsed is None:
            unresolved.append(sink_key)
            continue
        candidates = functions_by_name.get(parsed[1], [])
        if len(candidates) != 1 or security.is_forbidden_text(sink_key):
            unresolved.append(sink_key)
            continue
        path, node = candidates[0]
        resolved.append(
            ScanTool(
                qualified_name=sink_key,
                definition=ScanDefinition(
                    path=path, line=node.lineno, symbol=node.name
                ),
                signature=render_signature(node),
                discovery=Discovery.POLICY_NAME,
                detector_detail=f"policy sink key {sink_key!r}",
                declared=False,
                capabilities=(),
                guarded=False,
                policy_rules=(),
                evidence=(),
            )
        )

    resolved.sort(key=lambda t: t.qualified_name)
    unresolved.sort()
    return resolved, unresolved
