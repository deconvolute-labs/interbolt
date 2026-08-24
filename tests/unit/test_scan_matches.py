"""`scan/matches.py`: same-definition dedup and collision resolution."""

from __future__ import annotations

from interbolt.scan.artifact import Discovery, ScanBindingSite, ScanDefinition
from interbolt.scan.matches import Match, resolve_matches


def _definition(
    path: str = "a.py", line: int = 1, symbol: str = "send"
) -> ScanDefinition:
    return ScanDefinition(path=path, line=line, symbol=symbol)


class TestSameDefinitionDedup:
    def test_two_detectors_on_same_definition_keep_strongest_discovery(self) -> None:
        definition = _definition()
        matches_by_name = {
            "default.send": [
                Match(
                    qualified_name="default.send",
                    definition=definition,
                    signature="(x: str) -> None",
                    discovery=Discovery.SCHEMA_LITERAL,
                    detector_detail="schema literal",
                    guarded=False,
                ),
                Match(
                    qualified_name="default.send",
                    definition=definition,
                    signature="(x: str) -> None",
                    discovery=Discovery.DECORATOR,
                    detector_detail="decorator",
                    guarded=True,
                ),
            ]
        }
        tools, collisions = resolve_matches(matches_by_name)
        assert collisions == []
        assert len(tools) == 1
        assert tools[0].discovery is Discovery.DECORATOR
        assert tools[0].detector_detail == "decorator"
        assert tools[0].guarded is True

    def test_winner_borrows_binding_site_from_a_weaker_match(self) -> None:
        definition = _definition()
        binding_site = ScanBindingSite(path="agents/loader.py", line=10)
        matches_by_name = {
            "default.send": [
                Match(
                    qualified_name="default.send",
                    definition=definition,
                    signature=None,
                    discovery=Discovery.TOOL_LIST_REFERENCE,
                    detector_detail="tools= list reference",
                    guarded=False,
                    binding_site=binding_site,
                ),
                Match(
                    qualified_name="default.send",
                    definition=definition,
                    signature="(x: str) -> None",
                    discovery=Discovery.DECORATOR,
                    detector_detail="decorator",
                    guarded=True,
                ),
            ]
        }
        tools, _ = resolve_matches(matches_by_name)
        assert tools[0].discovery is Discovery.DECORATOR
        assert tools[0].binding_site == binding_site


class TestCollisions:
    def test_two_distinct_definitions_produce_a_collision_and_a_tool_entry(
        self,
    ) -> None:
        matches_by_name = {
            "default.send": [
                Match(
                    qualified_name="default.send",
                    definition=_definition(path="a.py"),
                    signature="(x: str) -> None",
                    discovery=Discovery.DECORATOR,
                    detector_detail="decorator",
                    guarded=False,
                ),
                Match(
                    qualified_name="default.send",
                    definition=_definition(path="b.py"),
                    signature="(x: str) -> None",
                    discovery=Discovery.DECORATOR,
                    detector_detail="decorator",
                    guarded=False,
                ),
            ]
        }
        tools, collisions = resolve_matches(matches_by_name)
        assert len(tools) == 1
        assert tools[0].qualified_name == "default.send"
        assert tools[0].collision is True
        assert tools[0].definition is None
        assert tools[0].signature is None
        assert tools[0].evidence == ()
        assert len(collisions) == 1
        assert collisions[0].qualified_name == "default.send"
        assert {d.path for d in collisions[0].definitions} == {"a.py", "b.py"}


class TestSortOrder:
    def test_tools_and_collisions_sorted_by_qualified_name(self) -> None:
        matches_by_name = {
            "zzz.last": [
                Match(
                    qualified_name="zzz.last",
                    definition=_definition(path="z.py", symbol="z"),
                    signature=None,
                    discovery=Discovery.DECORATOR,
                    detector_detail="decorator",
                    guarded=False,
                )
            ],
            "aaa.first": [
                Match(
                    qualified_name="aaa.first",
                    definition=_definition(path="a.py", symbol="a"),
                    signature=None,
                    discovery=Discovery.DECORATOR,
                    detector_detail="decorator",
                    guarded=False,
                )
            ],
        }
        tools, _ = resolve_matches(matches_by_name)
        assert [t.qualified_name for t in tools] == ["aaa.first", "zzz.last"]
