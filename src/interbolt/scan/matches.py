"""The shared `Match` shape and collision resolution, used by every detector.

A tool's identity is its qualified name, never the detector that found it.
`resolve_matches` is the single place that turns a
name collected by more than one detector into either one `ScanTool` or a
`ScanCollision`, so a decorator match and a schema-literal match landing on
the same qualified name collide correctly regardless of which detector saw
them.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from interbolt.scan.artifact import (
    Discovery,
    ScanBindingSite,
    ScanCollision,
    ScanDefinition,
    ScanTool,
)


@dataclass(frozen=True)
class Match:
    """One tool name resolved by one detector, before collision resolution."""

    qualified_name: str
    definition: ScanDefinition
    signature: str | None
    discovery: Discovery
    detector_detail: str
    guarded: bool
    binding_site: ScanBindingSite | None = None


_DISCOVERY_STRENGTH = {
    Discovery.DECORATOR: 0,
    Discovery.TOOL_LIST_REFERENCE: 1,
    Discovery.TOOL_LIST_CONSTANT: 2,
    Discovery.SCHEMA_LITERAL: 3,
    Discovery.POLICY_NAME: 4,
}


def _dedupe_same_definition(matches: list[Match]) -> list[Match]:
    """Collapse matches that resolved to the same definition site into one.

    Two detectors finding the same function is not a collision, it is the
    same tool discovered twice: a decorator-discovered function whose name
    also appears in an unrelated `tools=` schema list resolves to one
    definition site either way. When that happens, keep the match from the
    strongest detector (`discovery`'s own ranking), since it carries the
    most accurate `guarded`/`detector_detail` — but still carry over a
    `binding_site` from another match in the group if the winner has none
    of its own, since the same tool is still bound by that list.
    """
    by_definition: dict[tuple[str, int, str], list[Match]] = {}
    for match in matches:
        key = (match.definition.path, match.definition.line, match.definition.symbol)
        by_definition.setdefault(key, []).append(match)
    deduped: list[Match] = []
    for group in by_definition.values():
        winner = min(group, key=lambda m: _DISCOVERY_STRENGTH[m.discovery])
        if winner.binding_site is None:
            borrowed = next(
                (m.binding_site for m in group if m.binding_site is not None), None
            )
            if borrowed is not None:
                winner = replace(winner, binding_site=borrowed)
        deduped.append(winner)
    return deduped


def resolve_matches(
    matches_by_name: dict[str, list[Match]],
) -> tuple[list[ScanTool], list[ScanCollision]]:
    """Split every collected match into tools and collisions.

    Args:
        matches_by_name: Every match found by every detector, keyed by
            qualified name.

    Returns:
        `(tools, collisions)`, both sorted by `qualified_name`. A name with
        more than one distinct definition site, whether found by one
        detector or several, is reported in `collisions` and still gets a
        `tools` entry, with `collision=True` and no resolved definition,
        since the name itself is real even though its implementation is
        ambiguous.
    """
    tools: list[ScanTool] = []
    collisions: list[ScanCollision] = []
    for qualified_name, raw_matches in matches_by_name.items():
        matches = _dedupe_same_definition(raw_matches)
        if len(matches) > 1:
            collisions.append(
                ScanCollision(
                    qualified_name=qualified_name,
                    definitions=tuple(
                        sorted(
                            (m.definition for m in matches),
                            key=lambda d: (d.path, d.line),
                        )
                    ),
                )
            )
            authoritative = min(matches, key=lambda m: _DISCOVERY_STRENGTH[m.discovery])
            tools.append(
                ScanTool(
                    qualified_name=qualified_name,
                    definition=None,
                    signature=None,
                    discovery=authoritative.discovery,
                    detector_detail=f"{len(matches)} definitions resolve to this name",
                    binding_site=None,
                    declared=False,
                    capabilities=(),
                    guarded=False,
                    policy_rules=(),
                    evidence=(),
                    collision=True,
                )
            )
            continue
        match = matches[0]
        tools.append(
            ScanTool(
                qualified_name=match.qualified_name,
                definition=match.definition,
                signature=match.signature,
                discovery=match.discovery,
                detector_detail=match.detector_detail,
                binding_site=match.binding_site,
                declared=False,
                capabilities=(),
                guarded=match.guarded,
                policy_rules=(),
                evidence=(),
                collision=False,
            )
        )
    tools.sort(key=lambda t: t.qualified_name)
    collisions.sort(key=lambda c: c.qualified_name)
    return tools, collisions
