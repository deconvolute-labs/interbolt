"""Pydantic models for the scan artifact: `interbolt scan`'s versioned JSON output."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from interbolt.models.core import Capability


class Verdict(StrEnum):
    """An agent's coverage verdict, computed from its bound tools' declarations.

    `trifecta` cannot be reached in v1: `Capability` is a closed two-member
    set (`reads_private`, `reaches_external`), and the third lethal-trifecta
    leg, `from_untrusted`, is derived from taint at runtime and has no
    declarable, static form. A fully declared agent returns `clear`.
    """

    NO_POLICY = "no_policy"
    INCOMPLETE = "incomplete"
    CLEAR = "clear"
    TRIFECTA = "trifecta"


class Discovery(StrEnum):
    """How a tool entry was found. The three are not equally strong claims.

    A `decorator` match is evidence read directly from the code. A
    `policy_name` match is the user's assertion that a tool exists, plus a
    name lookup.
    """

    DECORATOR = "decorator"
    SCHEMA_LITERAL = "schema_literal"
    POLICY_NAME = "policy_name"


class UndetectedKind(StrEnum):
    """Why a piece of tool surface could not be resolved to a `ScanTool`.

    `rejected_name` covers a discovered name containing a control or
    Unicode-format character that could make a report display differently
    than the code parses (Trojan Source, CVE-2021-42574). `files_truncated`
    and `traversal_truncated` are not named in the design document's closed
    enum; they fill a gap between it and the resource-bound requirements
    that explicitly call for an `undetected` entry on truncation, using the
    same naming convention as the rest of the set.
    """

    MCP_SERVER = "mcp_server"
    DYNAMIC_REGISTRATION = "dynamic_registration"
    UNRESOLVED_TOOL_LIST = "unresolved_tool_list"
    UNRESOLVED_IMPLEMENTATION = "unresolved_implementation"
    AMBIGUOUS_IMPLEMENTATION = "ambiguous_implementation"
    REJECTED_NAME = "rejected_name"
    FILES_TRUNCATED = "files_truncated"
    TRAVERSAL_TRUNCATED = "traversal_truncated"


class ScanDefinition(BaseModel):
    """Where a tool's implementation was found.

    Attributes:
        path: POSIX-relative path from `scan_root`.
        line: 1-indexed line of the `def`/`async def`.
        symbol: The function's own name, ignoring any enclosing class.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str
    line: int
    symbol: str


class ScanEvidence(BaseModel):
    """One external symbol a tool body (or a function it calls) reaches.

    Attributes:
        symbol: The resolved `module.attr` form, from the file's import table.
        path: POSIX-relative path of the call site.
        line: 1-indexed line of the call site.
        depth: 0 for the tool body itself; each further hop into a
            same-tree function increments this by one.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    symbol: str
    path: str
    line: int
    depth: int


class ScanUndetected(BaseModel):
    """A piece of tool surface the scanner could not resolve.

    Attributes:
        kind: Why it could not be resolved. See `UndetectedKind`.
        path: POSIX-relative path from `scan_root`.
        line: 1-indexed line, or `0` when the entry has no single location
            (a whole-scan truncation).
        identifier: A server name, variable name, or similar, when one is
            readable. Never the rejected text itself for `rejected_name`.
        detail: One sentence naming what could not be read and why.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: UndetectedKind
    path: str
    line: int
    identifier: str | None
    detail: str


class ScanCollision(BaseModel):
    """Two or more definitions resolving to the same qualified name.

    A defect in the codebase's naming, not a security observation: one
    policy rule would govern two different tools. Neither definition is
    included in `ScanArtifact.tools`, since there is no principled way to
    pick a winner.

    Attributes:
        qualified_name: The colliding identity.
        definitions: Every definition site that produced it.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    qualified_name: str
    definitions: tuple[ScanDefinition, ...]


class ScanAgentIdentity(BaseModel):
    """An agent's binding-site identity. Always unresolved in v1.

    Attributes:
        resolved: Always `False` in v1; agent boundary detection is not
            implemented.
        agent_id: Always `None` in v1.
        binding_site: Always `None` in v1.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    resolved: bool
    agent_id: str | None
    binding_site: str | None


class ScanTool(BaseModel):
    """One discovered tool: its identity, provenance, coverage, and evidence.

    Attributes:
        qualified_name: The tool's identity, and the key a policy `sinks:`
            entry would use. File, line, and symbol are metadata, never part
            of identity.
        definition: Where the implementation was found, or `None` when the
            name is known but no implementation resolved.
        discovery: How this entry was found.
        detector_detail: Human-readable provenance, naming the decorator or
            binding site.
        declared: Whether the policy declares `capabilities:` for this tool.
            Always `False` in v1, since PR1 ships with no policy support.
        capabilities: The declared capabilities, sorted. Always empty in v1.
        guarded: Whether an Interbolt guard decorator (`@guard` or
            `@<handle>.guard`) was found on the definition.
        policy_rules: Names of the rules in this tool's sink entry, in
            policy order. Always empty in v1.
        evidence: External symbols this tool's body (or a function it calls)
            reaches, sorted by `(depth, path, line, symbol)`.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    qualified_name: str
    definition: ScanDefinition | None
    signature: str | None  # "(to: str, body: str) -> None"
    discovery: Discovery
    detector_detail: str
    declared: bool
    capabilities: tuple[Capability, ...]
    guarded: bool
    policy_rules: tuple[str, ...]
    evidence: tuple[ScanEvidence, ...]


class ScanAgent(BaseModel):
    """The rolled-up view of one agent's bound tools.

    v1 emits exactly one agent, `key="repo"`, `scope="repo"`, holding every
    tool found: agent boundary detection is not implemented, so the verdict
    describes the whole repository rather than one agent loop, and
    over-reports for a repository holding more than one agent.

    Attributes:
        key: Scan-local identifier. Always `"repo"` in v1.
        scope: Always `"repo"` in v1. Reserved for `"loop"` once agent
            detection lands.
        identity: The agent's binding-site identity. Always unresolved.
        tools: Qualified names of every bound tool, sorted.
        capabilities: Rolled up from the bound tools' declared capabilities,
            sorted and de-duplicated. Always empty in v1.
        verdict: The coverage verdict. Always `Verdict.NO_POLICY` in v1.
        undeclared_tool_count: The undeclared worklist size.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    key: str
    scope: str
    identity: ScanAgentIdentity
    tools: tuple[str, ...]
    capabilities: tuple[Capability, ...]
    verdict: Verdict
    undeclared_tool_count: int


class ScanScannerInfo(BaseModel):
    """Which scanner version and detectors produced this artifact.

    Attributes:
        version: `interbolt.__version__` at scan time.
        detectors: Which detectors ran, sorted. Present so a coverage change
            between releases is distinguishable from a code change.
        evidence_depth: The `--depth` value in force.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: str
    detectors: tuple[str, ...]
    evidence_depth: int


class ScanRepository(BaseModel):
    """Repository identity, read directly from `.git`. No field ever raises.

    Attributes:
        uri: From `.git/config`'s `[remote "origin"]` `url`, normalized to
            drop credentials and a trailing `.git`. `None` outside a git
            repository or with no origin remote.
        revision: The full 40-character commit SHA `HEAD` resolves to.
            `None` outside a git repository.
        branch: The branch `HEAD` points at. `None` on a detached `HEAD` or
            outside a git repository.
        root_name: The repository root directory's name. Always present, so
            identity exists even outside git.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    uri: str | None
    revision: str | None
    branch: str | None
    root_name: str


class ScanPolicyRef(BaseModel):
    """Which policy, if any, coverage was computed against.

    Attributes:
        source: `"file"`, `"remote"`, or `"none"`. Only `"none"` occurs in
            v1, since PR1 ships with no `--policy` support.
        ref: The path, for `"file"`. `None` for `"none"`.
        fingerprint: `Policy.fingerprint`, for `"file"`. `None` for `"none"`.
        scope: Reserved for the platform's scoped projection. Always `None`
            in v1.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    source: Literal["file", "remote", "none"]
    ref: str | None
    fingerprint: str | None
    scope: str | None


class ScanUnmatchedSink(BaseModel):
    """A policy sink key the scan did not find a matching tool for.

    Attributes:
        sink_key: The declared key.
        detail: Why it is reported this way rather than as a defect.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    sink_key: str
    detail: str


class ScanArtifact(BaseModel):
    """The complete, versioned JSON artifact `interbolt scan` writes.

    Deterministic: two scans of the same commit, with the same flags and
    the same policy, produce byte-identical output. Every list here is
    sorted by the key named on its own model; nested lists are sorted too.

    Attributes:
        schema_version: `constants.SCAN_SCHEMA_VERSION`. Bumped on any
            breaking shape change, the same discipline as
            `EVENT_SCHEMA_VERSION`.
        scanner: Which scanner version and detectors produced this artifact.
        repository: Repository identity, read from `.git` directly.
        scan_root: POSIX-relative path from the repository root.
        policy: Which policy, if any, coverage was computed against. Always
            `source="none"` in v1.
        agents: Sorted by `key`. Exactly one entry in v1.
        tools: Sorted by `qualified_name`.
        undetected: Sorted by `(path, line, kind)`.
        collisions: Sorted by `qualified_name`.
        unmatched_policy_sinks: Sorted by `sink_key`. Always empty in v1.
        paths: Reserved, always empty in v1; the shape is undefined until
            agent-boundary detection lands.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int
    scanner: ScanScannerInfo
    repository: ScanRepository
    scan_root: str
    policy: ScanPolicyRef
    agents: tuple[ScanAgent, ...]
    tools: tuple[ScanTool, ...]
    undetected: tuple[ScanUndetected, ...]
    collisions: tuple[ScanCollision, ...]
    unmatched_policy_sinks: tuple[ScanUnmatchedSink, ...]
    paths: tuple[Any, ...] = ()  # shape reserved, undefined until §13.2 lands
