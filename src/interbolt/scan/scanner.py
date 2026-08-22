"""Orchestration: `scan_repository()`, the scanner's entry point."""

from __future__ import annotations

import ast
from collections.abc import Sequence

from interbolt import __version__
from interbolt.constants import SCAN_MAX_FILES, SCAN_SCHEMA_VERSION
from interbolt.errors import InterboltConfigError
from interbolt.scan import detect, evidence, repository, security, walk
from interbolt.scan.artifact import (
    ScanAgent,
    ScanAgentIdentity,
    ScanArtifact,
    ScanPolicyRef,
    ScanScannerInfo,
    ScanUndetected,
    UndetectedKind,
    Verdict,
)


def scan_repository(
    path: str | None = None, *, exclude: Sequence[str] = (), depth: int = 1
) -> ScanArtifact:
    """Scan a Python repository and return the artifact `interbolt scan` writes.

    Reads source with the `ast` module only: never imports the scanned
    code, never executes it, and makes no network call unless a remote
    policy is configured, which this release does not support. Tools are
    discovered by decorator only (§6.2 of `dev/features/scanner.md`); no
    policy is consulted, so every agent's `verdict` is `Verdict.NO_POLICY`.

    Args:
        path: The scan root, or `None` to resolve it per §6.1 (`src/` if it
            exists at the current directory, else the current directory).
        exclude: `--exclude` globs, additive to the default exclusions.
        depth: The maximum call-hop depth for evidence collection.

    Returns:
        The complete, deterministic `ScanArtifact`.

    Raises:
        InterboltConfigError: If the resolved scan root is not a readable
            directory.
    """
    scan_root = walk.resolve_scan_root(path)
    if not scan_root.is_dir():
        raise InterboltConfigError(f"scan root {scan_root} is not a directory")
    files, files_truncated = walk.walk_python_files(scan_root, exclude)

    trees: dict[str, ast.Module] = {}
    for file_path in files:
        relative = security.resolve_within_root(file_path, scan_root)
        if relative is None or security.is_forbidden_text(relative):
            continue
        module = walk.parse_python_file(file_path)
        if module is not None:
            trees[relative] = module

    undetected: list[ScanUndetected] = []
    if files_truncated:
        undetected.append(
            ScanUndetected(
                kind=UndetectedKind.FILES_TRUNCATED,
                path=".",
                line=0,
                identifier=None,
                detail=(
                    f"the scan stopped after {SCAN_MAX_FILES} files; "
                    "the inventory below is incomplete"
                ),
            )
        )

    tools, collisions, detect_undetected = detect.detect_decorated_tools(trees)
    undetected.extend(detect_undetected)
    tools, evidence_undetected = evidence.collect_all_evidence(tools, trees, depth)
    undetected.extend(evidence_undetected)
    undetected.sort(key=lambda u: (u.path, u.line, u.kind))

    located = repository.locate_repository(scan_root)
    repo = repository.resolve_repository_identity(scan_root, located)
    scan_root_relative = "."
    if located is not None:
        relative = security.resolve_within_root(scan_root, located[0])
        if relative:
            scan_root_relative = relative

    agent = ScanAgent(
        key="repo",
        scope="repo",
        identity=ScanAgentIdentity(resolved=False, agent_id=None, binding_site=None),
        tools=tuple(t.qualified_name for t in tools),
        capabilities=(),
        verdict=Verdict.NO_POLICY,
        undeclared_tool_count=len(tools),
    )

    return ScanArtifact(
        schema_version=SCAN_SCHEMA_VERSION,
        scanner=ScanScannerInfo(
            version=__version__, detectors=("decorator",), evidence_depth=depth
        ),
        repository=repo,
        scan_root=scan_root_relative,
        policy=ScanPolicyRef(source="none", ref=None, fingerprint=None, scope=None),
        agents=(agent,),
        tools=tuple(tools),
        undetected=tuple(undetected),
        collisions=tuple(collisions),
        unmatched_policy_sinks=(),
        paths=(),
    )
