"""`scan/coverage.py`: joining discovered tools and sources against a policy."""

from __future__ import annotations

from interbolt.models.core import Action, Capability, TrustLevel
from interbolt.policy import Policy, compile_policy
from interbolt.policy.schema import (
    Defaults,
    PolicyDocument,
    SinkDeclaration,
    SinkRule,
    SourceDeclaration,
)
from interbolt.scan.artifact import (
    Discovery,
    ScanDefinition,
    ScanSource,
    ScanTool,
    Verdict,
)
from interbolt.scan.coverage import (
    build_unmatched_sinks,
    compute_coverage,
    join_declared_capabilities,
    join_declared_sources,
)


def _policy(
    sinks: dict[str, SinkDeclaration] | None = None,
    sources: tuple[SourceDeclaration, ...] = (),
) -> Policy:
    document = PolicyDocument(
        version="2.0", defaults=Defaults(), sources=sources, sinks=sinks or {}
    )
    return Policy(document=document, compiled_sinks=compile_policy(document))


def _tool(name: str, *, declared: bool = False) -> ScanTool:
    return ScanTool(
        qualified_name=name,
        definition=ScanDefinition(path="a.py", line=1, symbol=name.rpartition(".")[2]),
        signature=None,
        discovery=Discovery.DECORATOR,
        detector_detail="interbolt @guard",
        binding_site=None,
        declared=declared,
        capabilities=(),
        guarded=True,
        policy_rules=(),
        evidence=(),
        collision=False,
    )


class TestJoinDeclaredCapabilities:
    def test_undeclared_tool_stays_undeclared(self) -> None:
        policy = _policy()
        joined = join_declared_capabilities([_tool("email.send_email")], policy)
        assert joined[0].declared is False
        assert joined[0].capabilities == ()
        assert joined[0].policy_rules == ()

    def test_declared_tool_with_capabilities_populated(self) -> None:
        policy = _policy(
            {
                "email.send_email": SinkDeclaration(
                    capabilities=(Capability.REACHES_EXTERNAL,),
                    rules=(SinkRule(name="block", action=Action.BLOCK),),
                )
            }
        )
        joined = join_declared_capabilities([_tool("email.send_email")], policy)
        assert joined[0].declared is True
        assert joined[0].capabilities == (Capability.REACHES_EXTERNAL,)
        assert joined[0].policy_rules == ("block",)

    def test_empty_capabilities_list_still_counts_as_declared(self) -> None:
        policy = _policy({"util.format_report": SinkDeclaration(capabilities=())})
        joined = join_declared_capabilities([_tool("util.format_report")], policy)
        assert joined[0].declared is True
        assert joined[0].capabilities == ()

    def test_sink_with_rules_but_no_capabilities_stays_undeclared_but_carries_rules(
        self,
    ) -> None:
        policy = _policy(
            {
                "email.send_email": SinkDeclaration(
                    rules=(SinkRule(name="block", action=Action.BLOCK),)
                )
            }
        )
        joined = join_declared_capabilities([_tool("email.send_email")], policy)
        assert joined[0].declared is False
        assert joined[0].policy_rules == ("block",)


class TestJoinDeclaredSources:
    def test_declared_source_marked_true(self) -> None:
        policy = _policy(
            sources=(SourceDeclaration(name="web_search", trust=TrustLevel.UNTRUSTED),)
        )
        source = ScanSource(name="web_search", sites=(), declared=False)
        joined = join_declared_sources([source], policy)
        assert joined[0].declared is True

    def test_undeclared_source_stays_false(self) -> None:
        policy = _policy()
        source = ScanSource(name="web_search", sites=(), declared=False)
        joined = join_declared_sources([source], policy)
        assert joined[0].declared is False


class TestBuildUnmatchedSinks:
    def test_sink_with_no_matching_tool_reported(self) -> None:
        policy = _policy({"crm.query_customers": SinkDeclaration()})
        unmatched = build_unmatched_sinks(policy, matched_names=set())
        assert [u.sink_key for u in unmatched] == ["crm.query_customers"]

    def test_matched_sink_not_reported(self) -> None:
        policy = _policy({"crm.query_customers": SinkDeclaration()})
        unmatched = build_unmatched_sinks(policy, matched_names={"crm.query_customers"})
        assert unmatched == ()

    def test_sorted_by_sink_key(self) -> None:
        policy = _policy(
            {"zzz.last": SinkDeclaration(), "aaa.first": SinkDeclaration()}
        )
        unmatched = build_unmatched_sinks(policy, matched_names=set())
        assert [u.sink_key for u in unmatched] == ["aaa.first", "zzz.last"]


class TestComputeCoverage:
    def test_no_policy_supplied_is_always_no_policy(self) -> None:
        verdict, capabilities, undeclared = compute_coverage(
            [_tool("a.b")], policy_supplied=False
        )
        assert verdict is Verdict.NO_POLICY
        assert capabilities == ()
        assert undeclared == 1

    def test_undeclared_bound_tool_is_incomplete(self) -> None:
        tools = [_tool("a.b", declared=False)]
        verdict, _, undeclared = compute_coverage(tools, policy_supplied=True)
        assert verdict is Verdict.INCOMPLETE
        assert undeclared == 1

    def test_fully_declared_with_no_capabilities_is_clear(self) -> None:
        tools = [_tool("a.b", declared=True)]
        verdict, capabilities, undeclared = compute_coverage(
            tools, policy_supplied=True
        )
        assert verdict is Verdict.CLEAR
        assert capabilities == ()
        assert undeclared == 0

    def test_fully_declared_with_both_capability_legs_is_still_clear_not_trifecta(
        self,
    ) -> None:
        # v1's declarable capability set (`reads_private`, `reaches_external`)
        # is two of the three trifecta legs; the third, `from_untrusted`, has
        # no static form, so this can never reach `trifecta`.
        tools = [
            _tool("a.reads", declared=True).model_copy(
                update={"capabilities": (Capability.READS_PRIVATE,)}
            ),
            _tool("b.sends", declared=True).model_copy(
                update={"capabilities": (Capability.REACHES_EXTERNAL,)}
            ),
        ]
        verdict, capabilities, undeclared = compute_coverage(
            tools, policy_supplied=True
        )
        assert verdict is Verdict.CLEAR
        assert set(capabilities) == {
            Capability.READS_PRIVATE,
            Capability.REACHES_EXTERNAL,
        }
        assert undeclared == 0

    def test_empty_tool_list_with_policy_is_clear(self) -> None:
        verdict, capabilities, undeclared = compute_coverage([], policy_supplied=True)
        assert verdict is Verdict.CLEAR
        assert capabilities == ()
        assert undeclared == 0
