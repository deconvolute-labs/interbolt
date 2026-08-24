"""Policy name grounding: recovering a tool the other detectors could not find.

Every sink key a policy declares is a candidate tool name. A candidate not
already discovered from source is resolved the same way a schema-literal
name is (`literal.index_module_functions`): by a unique module-level
function name match.
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
    trees: dict[str, ast.Module], policy: Policy, *, discovered: set[str]
) -> list[ScanTool]:
    """Resolve policy sink keys not already discovered against the scanned source.

    Args:
        trees: Every scanned file's parsed module, keyed by its
            scan-root-relative POSIX path.
        policy: The policy whose declared sink keys become candidate tool
            names. Uses every key in `policy.document.sinks`, not just
            `policy.tool_capabilities`, which excludes sinks with no
            declared capabilities.
        discovered: Qualified names already found by another detector. A
            sink key already in this set is skipped, so a name that both a
            decorator and a policy sink key would resolve to is not entered
            twice under two different `discovery` values.

    Returns:
        A `ScanTool` per uniquely resolved key, with
        `discovery=Discovery.POLICY_NAME`. A key matching zero or more than
        one module-level function is left unresolved and produces no entry
        here; `coverage.build_unmatched_sinks` reports it from the sink-key
        side once the full tool list is known.
    """
    functions_by_name = index_module_functions(trees)
    resolved: list[ScanTool] = []

    for sink_key in policy.document.sinks:
        if sink_key in discovered:
            continue
        parsed = split_qualified_name(sink_key)
        if parsed is None:
            continue
        candidates = functions_by_name.get(parsed[1], [])
        if len(candidates) != 1 or security.is_forbidden_text(sink_key):
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
                binding_site=None,
                declared=False,
                capabilities=(),
                guarded=False,
                policy_rules=(),
                evidence=(),
                collision=False,
            )
        )

    resolved.sort(key=lambda t: t.qualified_name)
    return resolved
