"""`scan/mcp.py`: MCP server configuration detection, never enumerated."""

from __future__ import annotations

import json
from pathlib import Path

from interbolt.scan.artifact import UndetectedKind
from interbolt.scan.mcp import detect_mcp_servers


class TestMcpFilenames:
    def test_mcp_json_with_named_servers_produces_one_entry_per_server(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "mcp.json").write_text(
            json.dumps({"mcpServers": {"acme-tools": {}, "search": {}}})
        )
        undetected, truncated = detect_mcp_servers(tmp_path, ())
        assert truncated is False
        assert len(undetected) == 2
        assert all(u.kind == UndetectedKind.MCP_SERVER for u in undetected)
        assert {u.identifier for u in undetected} == {"acme-tools", "search"}

    def test_dot_mcp_json_also_recognized(self, tmp_path: Path) -> None:
        (tmp_path / ".mcp.json").write_text(
            json.dumps({"mcpServers": {"acme-tools": {}}})
        )
        undetected, _ = detect_mcp_servers(tmp_path, ())
        assert len(undetected) == 1

    def test_generic_json_file_with_mcp_servers_key_recognized(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "config.json").write_text(
            json.dumps({"mcpServers": {"acme-tools": {}}})
        )
        undetected, _ = detect_mcp_servers(tmp_path, ())
        assert len(undetected) == 1

    def test_json_file_without_mcp_servers_key_ignored(self, tmp_path: Path) -> None:
        (tmp_path / "config.json").write_text(json.dumps({"other": "value"}))
        undetected, _ = detect_mcp_servers(tmp_path, ())
        assert undetected == []


class TestMalformedOrEmptyMapping:
    def test_empty_servers_mapping_produces_one_generic_entry(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "mcp.json").write_text(json.dumps({"mcpServers": {}}))
        undetected, _ = detect_mcp_servers(tmp_path, ())
        assert len(undetected) == 1
        assert undetected[0].identifier is None

    def test_non_dict_servers_value_produces_one_generic_entry(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "mcp.json").write_text(json.dumps({"mcpServers": "not-a-dict"}))
        undetected, _ = detect_mcp_servers(tmp_path, ())
        assert len(undetected) == 1
        assert undetected[0].identifier is None

    def test_invalid_json_skipped_without_raising(self, tmp_path: Path) -> None:
        (tmp_path / "mcp.json").write_text("{not valid json")
        undetected, _ = detect_mcp_servers(tmp_path, ())
        assert undetected == []
