"""`interbolt scan`: CLI wiring, `--out`, `--format`, `--quiet`, exit codes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pytest_mock import MockerFixture

from interbolt.cli import main
from interbolt.cli.exit_codes import EXIT_OK, EXIT_USAGE
from interbolt.errors import InterboltConfigError
from interbolt.scan.artifact import (
    ScanAgent,
    ScanAgentIdentity,
    ScanArtifact,
    ScanPolicyRef,
    ScanRepository,
    ScanScannerInfo,
    Verdict,
)


def _empty_artifact() -> ScanArtifact:
    return ScanArtifact(
        schema_version=1,
        scanner=ScanScannerInfo(
            version="0.3.0", detectors=("decorator",), evidence_depth=1
        ),
        repository=ScanRepository(
            uri=None, revision=None, branch=None, root_name="myrepo"
        ),
        scan_root=".",
        policy=ScanPolicyRef(source="none", ref=None, fingerprint=None, scope=None),
        sources=(),
        agents=(
            ScanAgent(
                key="repo",
                scope="repo",
                identity=ScanAgentIdentity(
                    resolved=False, agent_id=None, binding_site=None
                ),
                tools=(),
                capabilities=(),
                verdict=Verdict.NO_POLICY,
                undeclared_tool_count=0,
            ),
        ),
        tools=(),
        undetected=(),
        collisions=(),
        unmatched_policy_sinks=(),
        paths=(),
    )


class TestOutFile:
    def test_writes_artifact_to_default_path(
        self, tmp_path: Path, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            "interbolt.cli.commands_scan.scan_repository",
            return_value=_empty_artifact(),
        )
        out = tmp_path / ".interbolt" / "scan.json"
        result = main(["scan", "--out", str(out), "--quiet"])
        assert result == EXIT_OK
        payload = json.loads(out.read_text())
        assert payload["schema_version"] == 1
        assert out.read_text().endswith("\n")

    def test_creates_parent_directories(
        self, tmp_path: Path, mocker: MockerFixture
    ) -> None:
        mocker.patch(
            "interbolt.cli.commands_scan.scan_repository",
            return_value=_empty_artifact(),
        )
        out = tmp_path / "nested" / "dir" / "scan.json"
        result = main(["scan", "--out", str(out), "--quiet"])
        assert result == EXIT_OK
        assert out.exists()


class TestOutStdout:
    def test_dash_writes_artifact_to_stdout_only(
        self, mocker: MockerFixture, capsys: pytest.CaptureFixture[str]
    ) -> None:
        mocker.patch(
            "interbolt.cli.commands_scan.scan_repository",
            return_value=_empty_artifact(),
        )
        result = main(["scan", "--out", "-"])
        assert result == EXIT_OK
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert payload["schema_version"] == 1
        assert "Scanned" in captured.err
        assert "wrote" not in captured.err


class TestFormatJson:
    def test_format_json_prints_full_artifact_to_stdout(
        self, tmp_path: Path, mocker: MockerFixture, capsys: pytest.CaptureFixture[str]
    ) -> None:
        mocker.patch(
            "interbolt.cli.commands_scan.scan_repository",
            return_value=_empty_artifact(),
        )
        out = tmp_path / "scan.json"
        result = main(["scan", "--out", str(out), "--format", "json"])
        assert result == EXIT_OK
        payload = json.loads(capsys.readouterr().out)
        assert payload["repository"]["root_name"] == "myrepo"


class TestQuiet:
    def test_quiet_suppresses_wrote_line_only(
        self, tmp_path: Path, mocker: MockerFixture, capsys: pytest.CaptureFixture[str]
    ) -> None:
        mocker.patch(
            "interbolt.cli.commands_scan.scan_repository",
            return_value=_empty_artifact(),
        )
        out = tmp_path / "scan.json"
        main(["scan", "--out", str(out), "--quiet"])
        captured = capsys.readouterr()
        assert "wrote" not in captured.out
        assert "Scanned" in captured.out

    def test_not_quiet_prints_wrote_line(
        self, tmp_path: Path, mocker: MockerFixture, capsys: pytest.CaptureFixture[str]
    ) -> None:
        mocker.patch(
            "interbolt.cli.commands_scan.scan_repository",
            return_value=_empty_artifact(),
        )
        out = tmp_path / "scan.json"
        main(["scan", "--out", str(out)])
        # rich soft-wraps long lines at its default console width outside a
        # real terminal, so a long tmp_path can split across lines here.
        printed = capsys.readouterr().out.replace("\n", "")
        assert f"wrote {out}" in printed


class TestUnreadableScanRoot:
    def test_config_error_exits_usage(
        self, mocker: MockerFixture, capsys: pytest.CaptureFixture[str]
    ) -> None:
        mocker.patch(
            "interbolt.cli.commands_scan.scan_repository",
            side_effect=InterboltConfigError("scan root /nope is not a directory"),
        )
        result = main(["scan", "does-not-exist"])
        assert result == EXIT_USAGE
        assert "not a directory" in capsys.readouterr().out

    def test_config_error_json_format(
        self, mocker: MockerFixture, capsys: pytest.CaptureFixture[str]
    ) -> None:
        mocker.patch(
            "interbolt.cli.commands_scan.scan_repository",
            side_effect=InterboltConfigError("scan root /nope is not a directory"),
        )
        result = main(["scan", "does-not-exist", "--format", "json"])
        assert result == EXIT_USAGE
        payload = json.loads(capsys.readouterr().out)
        assert payload["command"] == "scan"
        assert "not a directory" in payload["error"]


class TestEndToEnd:
    def test_real_fixture_tree_scanned_and_written(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        src = tmp_path / "src"
        src.mkdir()
        (src / "agent.py").write_text(
            "from interbolt import guard\n\n@guard\ndef send(x: str) -> None: ...\n"
        )
        out = tmp_path / "scan.json"
        result = main(["scan", str(src), "--out", str(out)])
        assert result == EXIT_OK
        payload = json.loads(out.read_text())
        assert payload["tools"][0]["qualified_name"] == "default.send"
        captured = capsys.readouterr()
        assert "1 tool found" in captured.out
        assert "default.send" in captured.out


class TestMarkupEscaping:
    def test_bracketed_decorator_argument_prints_literally_not_as_markup(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # A decorator's string argument is fully attacker-controlled and can
        # contain rich markup syntax. It must render as literal text in the
        # console summary, not be interpreted as a color/style directive.
        src = tmp_path / "src"
        src.mkdir()
        (src / "agent.py").write_text(
            "from langchain_core.tools import tool\n\n"
            '@tool("crm.query[red]customers")\n'
            "def query(x: str) -> None: ...\n"
        )
        out = tmp_path / "scan.json"
        result = main(["scan", str(src), "--out", str(out)])
        assert result == EXIT_OK
        assert "crm.query[red]customers" in capsys.readouterr().out
