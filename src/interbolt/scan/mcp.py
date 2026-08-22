"""MCP server configuration: detected, never enumerated.

A file named `mcp.json` or `.mcp.json`, or any JSON file with a top-level
`mcpServers` key, configures a set of MCP servers. Connecting to one to
enumerate its tools is out of scope; each
configured server is instead reported as unreadable surface.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

from interbolt.constants import SCAN_MAX_FILE_BYTES
from interbolt.scan import security, walk
from interbolt.scan.artifact import ScanUndetected, UndetectedKind
from interbolt.utils import get_logger

_logger = get_logger("scan.mcp")
_MCP_FILENAMES = frozenset({"mcp.json", ".mcp.json"})


def detect_mcp_servers(
    scan_root: Path, exclude: Sequence[str]
) -> tuple[list[ScanUndetected], bool]:
    """Find every MCP server configured under `scan_root`.

    Args:
        scan_root: The resolved scan root.
        exclude: User-supplied `--exclude` globs, additive to the defaults.

    Returns:
        `(undetected, files_truncated)`: one `mcp_server` entry per
        configured server, and whether the JSON file-count bound stopped
        the walk before it finished.
    """
    files, files_truncated = walk.walk_json_files(scan_root, exclude)
    undetected: list[ScanUndetected] = []
    for file_path in files:
        relative = security.resolve_within_root(file_path, scan_root)
        if relative is None or security.is_forbidden_text(relative):
            continue
        read = _read_json_bounded(file_path)
        if read is None:
            continue
        source, document = read
        if not isinstance(document, dict):
            continue
        servers = document.get("mcpServers")
        if file_path.name not in _MCP_FILENAMES and not isinstance(servers, dict):
            continue
        undetected.extend(_server_entries(relative, source, servers))
    undetected.sort(key=lambda u: (u.path, u.line, u.identifier or ""))
    return undetected, files_truncated


def _server_entries(path: str, source: str, servers: object) -> list[ScanUndetected]:
    """One `mcp_server` entry per server name in a `mcpServers` mapping."""
    if not isinstance(servers, dict) or not servers:
        return [
            ScanUndetected(
                kind=UndetectedKind.MCP_SERVER,
                path=path,
                line=_locate_key(source, "mcpServers"),
                identifier=None,
                detail="MCP server configuration found; its tools are not enumerated",
            )
        ]
    entries: list[ScanUndetected] = []
    for name in servers:
        safe_name = (
            name
            if isinstance(name, str) and not security.is_forbidden_text(name)
            else None
        )
        entries.append(
            ScanUndetected(
                kind=UndetectedKind.MCP_SERVER,
                path=path,
                line=_locate_key(source, name) if isinstance(name, str) else 1,
                identifier=safe_name,
                detail=(
                    f"MCP server {safe_name!r} configured; its tools are not enumerated"
                    if safe_name is not None
                    else "MCP server configured; its tools are not enumerated"
                ),
            )
        )
    return entries


def _locate_key(source: str, key: str) -> int:
    """The 1-indexed line of `key`'s first appearance as a JSON object key.

    A best-effort text search for `"key":` rather than a real JSON parse
    with position tracking, since the standard library's parser discards
    positions. Falls back to line 1 if the key's quoted form does not
    appear verbatim, which can happen for a key containing a character
    `json.dumps` would escape.
    """
    needle = json.dumps(key)
    index = source.find(needle)
    if index == -1:
        return 1
    return source.count("\n", 0, index) + 1


def _read_json_bounded(path: Path) -> tuple[str, object] | None:
    """Read and parse one JSON file, bounded, never raising."""
    try:
        size = path.stat().st_size
        if size > SCAN_MAX_FILE_BYTES:
            _logger.warning(
                "skipping %s: %d bytes exceeds the %d-byte scan bound",
                path,
                size,
                SCAN_MAX_FILE_BYTES,
            )
            return None
        source = path.read_text(encoding="utf-8")
        return source, json.loads(source)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, OSError) as exc:
        _logger.warning("skipping %s: %s", path, type(exc).__name__)
        return None
