"""The laundering audit: `AuditRegistry` and its string-scan helper."""

from __future__ import annotations

import threading
from collections import OrderedDict, deque
from collections.abc import Generator, Mapping
from datetime import UTC, datetime
from typing import Any

from interbolt.constants import (
    AUDIT_FINDINGS_MAX,
    AUDIT_MAX_TRACKED_RUNS,
    AUDIT_MIN_MATCH_LENGTH,
    EVENT_SCHEMA_VERSION,
)
from interbolt.models.core import Finding, Label, TrustLevel
from interbolt.policy.evaluate import resolve_label_trust
from interbolt.taint import Tainted, TaintedBytes
from interbolt.taint.walk import leaf_text, walk_leaves
from interbolt.utils import current_trace_context


def _walk_strings(
    value: Any,  # noqa: ANN401
    *,
    depth: int,
) -> Generator[tuple[str, Label | None], None, None]:
    """Yield every string leaf in `value`: `(content, label)`.

    `label` is `None` for a plain `str`/`bytes` leaf (a potential laundering
    point) and set for an already-labeled `Tainted`/`TaintedBytes` leaf.
    Recurses into builtin containers to `depth`.
    """
    for leaf in walk_leaves(value, depth=depth):
        text = leaf_text(leaf)
        if text is None:
            continue
        label = leaf.label if isinstance(leaf, (Tainted, TaintedBytes)) else None
        yield text, label


class AuditRegistry:
    """The laundering audit's per-run registry of untrusted-resolving content.

    Advisory only: catches mechanical laundering, not model paraphrase. See
    https://docs.deconvoluteai.com/docs/concepts/taint-propagation.
    """

    def __init__(
        self,
        *,
        min_match_length: int = AUDIT_MIN_MATCH_LENGTH,
        max_findings: int = AUDIT_FINDINGS_MAX,
        max_tracked_runs: int = AUDIT_MAX_TRACKED_RUNS,
    ) -> None:
        """Initialize the registry with its bounding thresholds."""
        self._min_match_length = min_match_length
        self._max_tracked_runs = max_tracked_runs
        self._by_run: OrderedDict[str, list[tuple[str, str]]] = OrderedDict()
        self._emitted: OrderedDict[str, set[tuple[str, str, str]]] = OrderedDict()
        self._findings: deque[Finding] = deque(maxlen=max_findings)
        self._lock = threading.Lock()

    def register_from_args(
        self,
        args: Mapping[str, Any],
        *,
        sources_table: Mapping[str, TrustLevel],
        run_id: str,
        depth: int,
    ) -> None:
        """Register every untrusted-resolving string found in `args` for this run."""
        to_register: list[tuple[str, str]] = []
        for value in args.values():
            for content, label in _walk_strings(value, depth=depth):
                if label is None or len(content) < self._min_match_length:
                    continue
                if resolve_label_trust(label, sources_table) is TrustLevel.UNTRUSTED:
                    to_register.append((content, label.source))
        if not to_register:
            return
        with self._lock:
            self._by_run.setdefault(run_id, []).extend(to_register)
            self._by_run.move_to_end(run_id)
            while len(self._by_run) > self._max_tracked_runs:
                evicted_run_id, _ = self._by_run.popitem(last=False)
                self._emitted.pop(evicted_run_id, None)

    def register_content(self, content: str, source: str, run_id: str) -> None:
        """Register one taint()-time content string for the ambient run.

        Called from the observer `configure(audit=True)` installs on
        `taint/`. Equivalent to one `register_from_args` entry, applying the
        same minimum-length threshold, but for content observed at ingress
        rather than collected from a labeled sink argument. Complementary
        with `register_from_args`: both write into the same per-run bucket.
        """
        if len(content) < self._min_match_length:
            return
        with self._lock:
            self._by_run.setdefault(run_id, []).append((content, source))
            self._by_run.move_to_end(run_id)
            while len(self._by_run) > self._max_tracked_runs:
                evicted_run_id, _ = self._by_run.popitem(last=False)
                self._emitted.pop(evicted_run_id, None)

    def scan(
        self,
        args: Mapping[str, Any],
        *,
        tool: str,
        run_id: str,
        agent_id: str,
        session_id: str | None,
        depth: int,
        policy_fingerprint: str,
    ) -> list[Finding]:
        """Scan `args` for previously-registered untrusted content with no label.

        Deduplicates: emits at most one Finding per (source, tool, argument)
        per run, not per occurrence.
        """
        trace_id, span_id = current_trace_context() or (None, None)
        # Held for the whole scan, not a snapshot-then-relock: the dedup
        # check-and-set must be atomic against a concurrent scan() call for
        # the same run, or both could see "not yet emitted" and both emit.
        with self._lock:
            registered = list(self._by_run.get(run_id, ()))
            if not registered:
                return []
            emitted = self._emitted.setdefault(run_id, set())
            findings: list[Finding] = []
            for argument, value in args.items():
                for content, label in _walk_strings(value, depth=depth):
                    if label is not None:
                        continue
                    for registered_content, source in registered:
                        if registered_content in content:
                            key = (source, tool, argument)
                            if key in emitted:
                                continue
                            emitted.add(key)
                            findings.append(
                                Finding(
                                    schema_version=EVENT_SCHEMA_VERSION,
                                    source=source,
                                    tool=tool,
                                    argument=argument,
                                    agent_id=agent_id,
                                    run_id=run_id,
                                    session_id=session_id,
                                    trace_id=trace_id,
                                    span_id=span_id,
                                    policy_fingerprint=policy_fingerprint,
                                    timestamp=datetime.now(UTC),
                                )
                            )
            self._findings.extend(findings)
        return findings

    def clear_run(self, run_id: str) -> None:
        """Drop the registered content and emitted-finding keys for a finished run."""
        with self._lock:
            self._by_run.pop(run_id, None)
            self._emitted.pop(run_id, None)

    @property
    def findings(self) -> list[Finding]:
        """Every finding recorded so far; oldest evicted first past `max_findings`."""
        with self._lock:
            return list(self._findings)
