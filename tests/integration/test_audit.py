from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

from interbolt import InMemoryReporter, Policy, configure, taint
from interbolt.runtime.guard import current_run_id

if TYPE_CHECKING:
    from interbolt import Runtime

POLICY_PATH = Path(__file__).parent.parent / "policies" / "agent_loop.yaml"


def _installed_taint_observer() -> object:
    """The current `taint/`-level observer, or `None` if uninstalled.

    Looked up via `sys.modules` rather than `import interbolt.taint as X`:
    `interbolt/__init__.py` does `from interbolt.taint import taint`, which
    overwrites the `taint` attribute on the `interbolt` package with the
    function; `import a.b as x` resolves through that attribute chain, so it
    would silently bind to the function instead of the submodule.
    """
    return getattr(sys.modules["interbolt.taint"], "_taint_observer")  # noqa: B009


def _configure(*, audit: bool) -> Runtime:
    return configure(
        policy=Policy.from_file(str(POLICY_PATH)),
        reporter=InMemoryReporter(),
        approval_resolver=lambda decision: True,
        mode="enforce",
        audit=audit,
    )


class TestLaunderingAuditCanonicalCase:
    """Fix 7: the audit must catch content laundered before any labeled sink."""

    async def test_fstring_laundered_payload_caught_via_guard(self) -> None:
        rt = _configure(audit=True)
        agent = rt.agent("research-agent")

        @agent.guard(tool="send_email")
        def send_email(to: str, body: str) -> None:
            pass

        async with rt.agent_context("research-agent"):
            web = taint("ATTACKER-PAYLOAD-INJECTED-CONTENT", source="web_search")
            body = f"Summary: {web} done"
            send_email(to="partner@external.com", body=body)

        findings = rt.audit_findings()
        assert len(findings) == 1
        assert findings[0].source == "web_search"
        assert findings[0].argument == "body"

    async def test_fstring_laundered_payload_caught_via_bare_check_with_explicit_run_id(
        self,
    ) -> None:
        # Bare check() never reads the agent_context contextvar automatically,
        # unlike @guard; run_id must be passed explicitly to correlate with
        # the run taint() attributed content to.
        rt = _configure(audit=True)
        async with rt.agent_context("a"):
            web = taint("ATTACKER-PAYLOAD-INJECTED-CONTENT", source="web_search")
            body = f"Summary: {web} done"
            rt.check(
                tool="default.send_email",
                args={"to": "partner@external.com", "body": body},
                agent_id="a",
                run_id=current_run_id.get(),
            )
        findings = rt.audit_findings()
        assert len(findings) == 1

    async def test_audit_disabled_yields_no_findings_and_installs_no_observer(
        self,
    ) -> None:
        rt = _configure(audit=False)
        assert _installed_taint_observer() is None
        async with rt.agent_context("a"):
            web = taint("ATTACKER-PAYLOAD-INJECTED-CONTENT", source="web_search")
            body = f"Summary: {web} done"
            rt.check(
                tool="default.send_email",
                args={"to": "partner@external.com", "body": body},
                agent_id="a",
                run_id=current_run_id.get(),
            )
        assert rt.audit_findings() == []

    async def test_short_content_not_registered(self) -> None:
        rt = _configure(audit=True)
        async with rt.agent_context("a"):
            web = taint("short", source="web_search")
            body = f"Summary: {web} done"
            rt.check(
                tool="default.send_email",
                args={"to": "partner@external.com", "body": body},
                agent_id="a",
                run_id=current_run_id.get(),
            )
        assert rt.audit_findings() == []

    async def test_trusted_source_content_not_registered(self) -> None:
        rt = _configure(audit=True)
        async with rt.agent_context("a"):
            kb = taint("INTERNAL-APPROVED-CONTENT-STRING", source="internal_kb")
            body = f"Summary: {kb} done"
            rt.check(
                tool="default.send_email",
                args={"to": "partner@external.com", "body": body},
                agent_id="a",
                run_id=current_run_id.get(),
            )
        assert rt.audit_findings() == []

    def test_taint_outside_agent_context_registers_nothing_and_does_not_raise(
        self,
    ) -> None:
        _configure(audit=True)
        # No active agent_context: current_run_id.get() is None, so the
        # observer branch is skipped entirely. Just confirm no exception.
        taint("ATTACKER-PAYLOAD-INJECTED-CONTENT", source="web_search")

    async def test_reconfigure_audit_false_stops_registration(self) -> None:
        rt = _configure(audit=True)
        async with rt.agent_context("a"):
            web = taint("ATTACKER-PAYLOAD-INJECTED-CONTENT", source="web_search")
            rt.check(
                tool="default.send_email",
                args={
                    "to": "partner@external.com",
                    "body": f"Summary: {web} done",
                },
                agent_id="a",
                run_id=current_run_id.get(),
            )
        assert len(rt.audit_findings()) == 1

        rt2 = _configure(audit=False)
        async with rt2.agent_context("a"):
            web2 = taint("ANOTHER-ATTACKER-PAYLOAD-CONTENT", source="web_search")
            rt2.check(
                tool="default.send_email",
                args={
                    "to": "partner@external.com",
                    "body": f"Summary: {web2} done",
                },
                agent_id="a",
                run_id=current_run_id.get(),
            )
        assert rt2.audit_findings() == []
