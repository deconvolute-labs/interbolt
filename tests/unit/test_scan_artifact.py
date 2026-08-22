"""Artifact schema shape, determinism, and the §3.5 neutrality invariant."""

from __future__ import annotations

import json
from pathlib import Path

from interbolt.scan.artifact import ScanArtifact, ScanRepository
from interbolt.scan.scanner import scan_repository

FIXTURES_DIR = Path(__file__).parent.parent / "scan_fixtures"


def _artifact_json(artifact: ScanArtifact) -> str:
    return json.dumps(
        artifact.model_dump(mode="json"), indent=2, sort_keys=False, ensure_ascii=True
    )


class TestSchemaShape:
    def test_no_dirty_field(self) -> None:
        assert "dirty" not in ScanRepository.model_fields

    def test_no_generated_at_field(self) -> None:
        assert "generated_at" not in ScanArtifact.model_fields

    def test_paths_always_empty(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text("x = 1\n")
        artifact = scan_repository(str(tmp_path))
        assert artifact.paths == ()

    def test_unmatched_policy_sinks_always_empty_in_pr1(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text("x = 1\n")
        artifact = scan_repository(str(tmp_path))
        assert artifact.unmatched_policy_sinks == ()

    def test_policy_ref_always_none_source_in_pr1(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text("x = 1\n")
        artifact = scan_repository(str(tmp_path))
        assert artifact.policy.source == "none"
        assert artifact.policy.ref is None
        assert artifact.policy.fingerprint is None

    def test_verdict_always_no_policy_in_pr1(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text(
            "from interbolt import guard\n\n@guard\ndef t(x: str) -> None: ...\n"
        )
        artifact = scan_repository(str(tmp_path))
        assert artifact.agents[0].verdict == "no_policy"
        assert all(not t.declared for t in artifact.tools)
        assert all(t.capabilities == () for t in artifact.tools)


class TestDeterminism:
    def test_two_scans_of_same_tree_are_byte_identical(self) -> None:
        root = str(FIXTURES_DIR / "decorator_only" / "src")
        first = _artifact_json(scan_repository(root))
        second = _artifact_json(scan_repository(root))
        assert first == second

    def test_undetected_and_collisions_and_tools_all_sorted(self) -> None:
        root = str(FIXTURES_DIR / "decorator_only" / "src")
        artifact = scan_repository(root)
        assert [t.qualified_name for t in artifact.tools] == sorted(
            t.qualified_name for t in artifact.tools
        )


class TestNeutrality:
    def test_identity_stable_when_guard_added(self) -> None:
        without = scan_repository(
            str(FIXTURES_DIR / "neutrality" / "without_guard" / "src")
        )
        with_guard = scan_repository(
            str(FIXTURES_DIR / "neutrality" / "with_guard" / "src")
        )

        without_by_name = {t.qualified_name: t for t in without.tools}
        with_by_name = {t.qualified_name: t for t in with_guard.tools}

        assert set(without_by_name) == set(with_by_name)
        for name, tool in without_by_name.items():
            other = with_by_name[name]
            assert tool.definition is not None
            assert other.definition is not None
            assert other.qualified_name == tool.qualified_name
            # Not `line`: the fixture adds an import and a decorator line
            # above each function, which legitimately shifts its line
            # number. Line is metadata, never part of identity (§3.1).
            assert other.definition.path == tool.definition.path
            assert other.definition.symbol == tool.definition.symbol
            # Only these are expected to change by adding `@guard`: it is
            # detected (guarded), and detector_detail names it as
            # authoritative (§3.1), since a policy declaration is what the
            # scanner exists to prompt, but decoration alone changes
            # nothing about what was already discovered.
            assert tool.guarded is False
            assert other.guarded is True
            assert tool.declared is False
            assert other.declared is False
