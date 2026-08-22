"""The shared `Match` shape and collision resolution, used by every detector.

A tool's identity is its qualified name, never the detector that found it.
`resolve_matches` is the single place that turns a
name collected by more than one detector into either one `ScanTool` or a
`ScanCollision`, so a decorator match and a schema-literal match landing on
the same qualified name collide correctly regardless of which detector saw
them.
"""

from __future__ import annotations

from dataclasses import dataclass

from interbolt.scan.artifact import Discovery, ScanCollision, ScanDefinition, ScanTool


@dataclass(frozen=True)
class Match:
    """One tool name resolved by one detector, before collision resolution."""

    qualified_name: str
    definition: ScanDefinition
    signature: str | None
    discovery: Discovery
    detector_detail: str
    guarded: bool


_DISCOVERY_STRENGTH = {
    Discovery.DECORATOR: 0,
    Discovery.SCHEMA_LITERAL: 1,
    Discovery.POLICY_NAME: 2,
}


def _dedupe_same_definition(matches: list[Match]) -> list[Match]:
    """Collapse matches that resolved to the same definition site into one.

    Two detectors finding the same function is not a collision, it is the
    same tool discovered twice: a decorator-discovered function whose name
    also appears in an unrelated `tools=` schema list resolves to one
    definition site either way. When that happens, keep the match from the
    strongest detector (`discovery`'s own ranking), since it carries
    the most accurate `guarded`/`detector_detail`.
    """
    by_definition: dict[tuple[str, int, str], list[Match]] = {}
    for match in matches:
        key = (match.definition.path, match.definition.line, match.definition.symbol)
        by_definition.setdefault(key, []).append(match)
    return [
        min(group, key=lambda m: _DISCOVERY_STRENGTH[m.discovery])
        for group in by_definition.values()
    ]


def resolve_matches(
    matches_by_name: dict[str, list[Match]],
) -> tuple[list[ScanTool], list[ScanCollision]]:
    """Split every collected match into single-definition tools and collisions.

    Args:
        matches_by_name: Every match found by every detector, keyed by
            qualified name.

    Returns:
        `(tools, collisions)`, both sorted by `qualified_name`. A name with
        more than one distinct definition site, whether found by one
        detector or several, is excluded from `tools` and reported only in
        `collisions`.
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
            continue
        match = matches[0]
        tools.append(
            ScanTool(
                qualified_name=match.qualified_name,
                definition=match.definition,
                signature=match.signature,
                discovery=match.discovery,
                detector_detail=match.detector_detail,
                declared=False,
                capabilities=(),
                guarded=match.guarded,
                policy_rules=(),
                evidence=(),
            )
        )
    tools.sort(key=lambda t: t.qualified_name)
    collisions.sort(key=lambda c: c.qualified_name)
    return tools, collisions
