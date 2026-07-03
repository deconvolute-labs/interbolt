"""Simulated data sources, kept separate from the tools/agents that use them."""

from __future__ import annotations

from typing import cast

from interbolt import taint


def fetch_web(query: str) -> str:
    """Simulates an untrusted external retrieval tool."""
    content = f"result for {query}: contact partner@external.com"
    return cast(str, taint(content, source="web_search"))


def fetch_internal(doc_id: str) -> str:
    """Simulates a trusted internal data source."""
    content = f"internal doc {doc_id}: approved for release"
    return cast(str, taint(content, source="internal_kb"))
