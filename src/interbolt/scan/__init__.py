"""Static analysis of a Python repository's tool surface. See `scan_repository`."""

from __future__ import annotations

from interbolt.scan.artifact import (
    Discovery,
    ScanAgent,
    ScanAgentIdentity,
    ScanArtifact,
    ScanBindingSite,
    ScanCollision,
    ScanDefinition,
    ScanEvidence,
    ScanPolicyRef,
    ScanRepository,
    ScanScannerInfo,
    ScanSource,
    ScanSourceSite,
    ScanTool,
    ScanUndetected,
    ScanUnmatchedSink,
    UndetectedKind,
    Verdict,
)
from interbolt.scan.scanner import scan_repository

__all__ = [
    "scan_repository",
    "ScanArtifact",
    "ScanAgent",
    "ScanAgentIdentity",
    "ScanTool",
    "ScanEvidence",
    "ScanUndetected",
    "ScanRepository",
    "ScanPolicyRef",
    "ScanSource",
    "ScanSourceSite",
    "ScanCollision",
    "ScanDefinition",
    "ScanBindingSite",
    "ScanScannerInfo",
    "ScanUnmatchedSink",
    "Verdict",
    "Discovery",
    "UndetectedKind",
]
