"""Orchestration: `scan_repository()`, the scanner's entry point."""

from __future__ import annotations

import ast
from collections.abc import Sequence

from interbolt import __version__
from interbolt.constants import SCAN_MAX_FILES, SCAN_SCHEMA_VERSION
from interbolt.errors import InterboltConfigError
from interbolt.policy import Policy
from interbolt.scan import (
    coverage,
    detect,
    evidence,
    ground,
    mcp,
    repository,
    security,
    walk,
)
from interbolt.scan.artifact import (
    ScanAgent,
    ScanAgentIdentity,
    ScanArtifact,
    ScanPolicyRef,
    ScanScannerInfo,
    ScanUndetected,
    ScanUnmatchedSink,
    UndetectedKind,
)


def scan_repository(
    path: str | None = None,
    *,
    exclude: Sequence[str] = (),
    depth: int = 1,
    policy: Policy | None = None,
) -> ScanArtifact:
    """Scan a Python repository and return the artifact `interbolt scan` writes.

    Reads source with the `ast` module only: never imports the scanned
    code, never executes it, and makes no network call. Tools are
    discovered by decorator, literal schema, and, when `policy` is given,
    grounding against its declared sink names.

    Args:
        path: The scan root, or `None` to resolve it as `src/` if it exists
            at the current directory, else the current directory.
        exclude: `--exclude` globs, additive to the default exclusions.
        depth: The maximum call-hop depth for evidence collection.
        policy: When given, tools are joined against its declared
            capabilities and every agent's verdict is computed from that
            join. When `None`, every tool is undeclared and the verdict is
            `Verdict.NO_POLICY`.

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

    tools, collisions, detect_undetected = detect.detect_tools(trees)
    undetected.extend(detect_undetected)
    tools, evidence_undetected = evidence.collect_all_evidence(tools, trees, depth)
    undetected.extend(evidence_undetected)
    mcp_undetected, mcp_truncated = mcp.detect_mcp_servers(scan_root, exclude)
    undetected.extend(mcp_undetected)
    if mcp_truncated:
        undetected.append(
            ScanUndetected(
                kind=UndetectedKind.FILES_TRUNCATED,
                path=".",
                line=0,
                identifier=None,
                detail=(
                    f"the scan stopped after {SCAN_MAX_FILES} JSON files; "
                    "MCP configuration below may be incomplete"
                ),
            )
        )
    # `literal.py` and `registry.py` each run their own bounded AST walk
    # over the same trees `detect.py` walks, so the same truncated branch
    # can surface once per detector; the artifact reports it once.
    undetected = list(dict.fromkeys(undetected))
    undetected.sort(key=lambda u: (u.path, u.line, u.kind))

    located = repository.locate_repository(scan_root)
    repo = repository.resolve_repository_identity(scan_root, located)
    scan_root_relative = "."
    if located is not None:
        relative = security.resolve_within_root(scan_root, located[0])
        if relative:
            scan_root_relative = relative

    detectors = ["decorator", "schema_literal"]
    unmatched_policy_sinks: tuple[ScanUnmatchedSink, ...] = ()
    policy_ref = ScanPolicyRef(source="none", ref=None, fingerprint=None, scope=None)
    if policy is not None:
        detectors.append("policy_name")
        discovered = {t.qualified_name for t in tools}
        grounded = ground.ground_policy_names(trees, policy, discovered=discovered)
        tools = sorted([*tools, *grounded], key=lambda t: t.qualified_name)
        tools = list(coverage.join_declared_capabilities(tools, policy))
        unmatched_policy_sinks = coverage.build_unmatched_sinks(
            policy, [t.qualified_name for t in tools]
        )
        policy_ref = ScanPolicyRef(
            source="file",
            ref=policy.source,
            fingerprint=policy.fingerprint,
            scope=None,
        )

    verdict, capabilities, undeclared_count = coverage.compute_coverage(
        tools, policy_supplied=policy is not None
    )
    agent = ScanAgent(
        key="repo",
        scope="repo",
        identity=ScanAgentIdentity(resolved=False, agent_id=None, binding_site=None),
        tools=tuple(t.qualified_name for t in tools),
        capabilities=capabilities,
        verdict=verdict,
        undeclared_tool_count=undeclared_count,
    )

    return ScanArtifact(
        schema_version=SCAN_SCHEMA_VERSION,
        scanner=ScanScannerInfo(
            version=__version__,
            detectors=tuple(detectors),
            evidence_depth=depth,
        ),
        repository=repo,
        scan_root=scan_root_relative,
        policy=policy_ref,
        agents=(agent,),
        tools=tuple(tools),
        undetected=tuple(undetected),
        collisions=tuple(collisions),
        unmatched_policy_sinks=unmatched_policy_sinks,
        paths=(),
    )
