from __future__ import annotations

from collections.abc import Callable

from interbolt import InMemoryReporter, Policy, configure, endorse, taint
from interbolt.models.core import Action
from interbolt.policy.schema import SinkRule
from interbolt.utils import current_run_id


def _endorsement_policy(make_policy: Callable[..., Policy]) -> Policy:
    return make_policy(
        sink_action=Action.ALLOW,
        sinks={
            "default.send_email": (
                SinkRule(
                    name="require_allowlist",
                    require_endorsement="recipient_allowlisted",
                    action=Action.BLOCK,
                ),
                SinkRule(name="default", action=Action.ALLOW),
            )
        },
    )


class TestEndorseSanitizerMismatchEndToEnd:
    """The kind-matching idiom must gate on the specific endorsement kind a
    sink names, not merely on "was this endorsed at all"."""

    async def test_endorsed_with_required_kind_is_allowed(
        self, make_policy: Callable[..., Policy]
    ) -> None:
        policy = _endorsement_policy(make_policy)
        rt = configure(policy=policy, reporter=InMemoryReporter(), mode="enforce")
        async with rt.agent_context("agent"):
            recipient = taint("attacker@external.com", source="web_search")
            endorsed = endorse(recipient, kind="recipient_allowlisted")
            decision = rt.check(
                tool="default.send_email", args={"to": endorsed}, agent_id="agent"
            )
        assert decision.action is Action.ALLOW

    async def test_endorsed_with_wrong_kind_is_still_blocked(
        self, make_policy: Callable[..., Policy]
    ) -> None:
        # Same untrusted source, endorsed for a DIFFERENT kind than the sink
        # requires (a URL sanitizer, not a recipient allowlist): must still
        # block. This is the sanitizer-mismatch case named kinds exist for.
        policy = _endorsement_policy(make_policy)
        rt = configure(policy=policy, reporter=InMemoryReporter(), mode="enforce")
        async with rt.agent_context("agent"):
            recipient = taint("attacker@external.com", source="web_search")
            endorsed = endorse(recipient, kind="url_sanitized")
            decision = rt.check(
                tool="default.send_email", args={"to": endorsed}, agent_id="agent"
            )
        assert decision.action is Action.BLOCK

    async def test_unendorsed_value_is_blocked(
        self, make_policy: Callable[..., Policy]
    ) -> None:
        policy = _endorsement_policy(make_policy)
        rt = configure(policy=policy, reporter=InMemoryReporter(), mode="enforce")
        async with rt.agent_context("agent"):
            recipient = taint("attacker@external.com", source="web_search")
            decision = rt.check(
                tool="default.send_email", args={"to": recipient}, agent_id="agent"
            )
        assert decision.action is Action.BLOCK


class TestEndorseRunTaintedUnaffected:
    async def test_run_tainted_remains_true_after_endorsing_the_only_tainted_value(
        self, make_policy: Callable[..., Policy]
    ) -> None:
        policy = make_policy(sink_action=Action.ALLOW)
        rt = configure(policy=policy, reporter=InMemoryReporter(), mode="enforce")
        async with rt.agent_context("agent"):
            web = taint("payload", source="web_search")
            endorse(web, kind="reviewed")
            decision = rt.check(
                tool="default.unrelated_tool",
                args={},
                agent_id="agent",
                run_id=current_run_id.get(),
            )
        assert decision.run_tainted is True


class TestEndorsementReachesReporter:
    async def test_endorsement_record_emitted_with_kind_and_note(
        self, make_policy: Callable[..., Policy]
    ) -> None:
        policy = make_policy(sink_action=Action.ALLOW)
        reporter = InMemoryReporter()
        rt = configure(policy=policy, reporter=reporter, mode="enforce")
        async with rt.agent_context("agent"):
            web = taint("attacker@external.com", source="web_search")
            endorse(web, kind="recipient_allowlisted", note="checked against CRM")

        assert len(reporter.endorsements) == 1
        assert reporter.endorsements[0].kind == "recipient_allowlisted"
        assert reporter.endorsements[0].note == "checked against CRM"
        assert reporter.endorsements[0].policy_fingerprint == rt.policy.fingerprint
