# Deferred features

What this version deliberately does not do, with the seam already in place
for each so adding it later is additive rather than a rewrite. Full design
rationale for each item lives in `dev/spec.md` §15; this page is the
user-facing summary.

## Async approval semantics

No timeout, no decision caching, no async resolver on a sync call site, no
sync-to-async bridge. This version ships the split sync/async resolver pair
(see [Reporters](../reference/reporters.md) and
[the `ApprovalResolver` reference](../reference/api.md#reporter-approvalresolver))
without a bridge between the two: a sync call site cannot use a resolver
that returns an awaitable, by design, since bridging sync-over-async inside
an already-running event loop is a known footgun (`asyncio.run` raises if a
loop is already running, which it usually is inside an agent).

## Trifecta capabilities declaration

This version computes exactly one of the three lethal-trifecta legs,
`from_untrusted`; `reaches_external` and `reads_private` are not computed
(see [the v1 trifecta limit](../concepts/policies.md#the-v1-trifecta-limit-read-this)).
A future capabilities declaration in the policy file, letting the
integrator annotate which tools read private data and which reach external
destinations, would make all three legs computable.

## Cross-boundary provenance

A label does not survive a storage round-trip or a process boundary; data
that re-enters the process is treated as fresh untrusted ingress and must
be re-`taint`ed (see
[Taint propagation: boundaries](../concepts/taint-propagation.md#boundaries-that-always-reset-to-untrusted-ingress)).
Persisting a label alongside data so it survives such a round-trip is
deferred.

## Argument value classifiers

`args` is exposed raw inside a `when` expression; there are no built-in
URL/email/path/host classifiers (`args.to.is_external` and similar). Write
the predicate by hand, as in every example in
[Policies](../concepts/policies.md).

## Additional reporters

An OpenTelemetry reporter and a hosted buffering reporter (a crash-durable
local buffer drained by a non-blocking background worker, for self-hosted
persistence and platform sync) are deferred. The shipped reporters are
`NullReporter`, `InMemoryReporter`, and `LoggingReporter`; see
[Reporters](../reference/reporters.md). Any of these would arrive as a
drop-in implementation of the existing `Reporter` protocol, with no change
to `taint`, `policy`, `enforcement`, or `runtime`.

## Additional framework integrations

MCP is the integration this version specifies (see [MCP](../guides/mcp.md)
for its current implementation status). LangChain, Pydantic AI, CrewAI, and
LlamaIndex adapters are deferred, each meant to ship behind its own optional
extra.

## Capability-variable model

A future execution model where the library owns the tool-calling loop and
every value is a capability with attached metadata, rather than a
string-subclass carrier. This is the only path that would close the
propagation gap (see [Taint propagation](../concepts/taint-propagation.md))
at the source rather than detecting it after the fact via the
[audit](../guides/auditing.md). Documented as a direction, not planned for a
specific version.

## Run-level capability gating

Value-level taint is precise but launderable by a model paraphrasing
untrusted text before it reaches a sink (see
[Taint propagation](../concepts/taint-propagation.md#does-not-propagate-laundering-points-re-taint-required)
and [Auditing](../guides/auditing.md#what-it-does-not-catch)). A
complementary, coarser instrument would gate on run-scoped capability facts
instead of a specific value's bytes: "has this run ingested data from an
untrusted source, and is it now calling a sink that reaches an external
destination." Because the decision is over run-scoped facts rather than the
bytes of an argument, paraphrase and summarization would not evade it. This
depends on the trifecta capabilities declaration above and is deferred.

## Remote policy source

A policy-source abstraction `configure()` would resolve: a local file
today, a remote control plane when an API key is present, with the remote
policy authoritative over local sources whenever it is in play. Not
implemented in this version; `Policy.from_file(path)` is the only supported
policy source, and the library makes no network calls under any default
configuration.

## Agent-boundary provenance

Automatic re-taint at an agent's output boundary (rather than the manual
`taint(agent_a_output, source="agent_a")` pattern documented in
[Identity](../concepts/identity.md#multi-agent-and-handoffs)), an
agent-level provenance graph showing which agents touched data and in what
order, and run-level gating as the enforcement consumer of both. None of
the three pieces ship automatically in this version; manual re-taint at the
handoff is the only piece available today.
