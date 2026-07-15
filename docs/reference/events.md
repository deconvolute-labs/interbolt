# Events: the stable record schema

`Event`, `Finding`, and `Endorsement` are Interbolt's own versioned records —
the source of truth for what a guarded call decided, what the laundering
audit found, and what was explicitly endorsed. Any reporter, native or
OpenTelemetry, is a projection of these records; they are not projections of
anything else. This page is the integration contract for anything that
consumes them, including a future Deconvolute platform.

## Versioning policy

`schema_version` (backed by `constants.EVENT_SCHEMA_VERSION`) is bumped on
any field addition or semantic change. As a commitment:

- Additions are backward-compatible: a new field always defaults to `None`
  (or an equivalent empty value), so a consumer reading an older record
  never sees a missing key crash a parser, and `interbolt inspect` parses
  every schema version it has ever emitted, side by side, in one run.
- Removals or renames do not happen within a major version. A field that
  becomes irrelevant is left in place, not deleted.

## `Event` (as `JsonlReporter` serializes it)

```json
{
  "record_type": "event",
  "schema_version": 6,
  "decision": {
    "action": "block",
    "matched_rule": "block_untrusted_exfil",
    "matched_condition": "taint.any(t, t.trust == \"untrusted\") && args.to.endsWith(\"@external.com\")",
    "tool": "default.send_email",
    "contributing_labels": [
      {
        "source": "web_search",
        "value_id": "b2c1...",
        "lineage": ["web_search"],
        "endorsements": []
      }
    ],
    "trifecta": ["from_untrusted"],
    "untrusted_sources": ["web_search"],
    "run_tainted": false,
    "mode": "enforce",
    "decision_id": "b7e0...",
    "agent_id": "support-agent",
    "run_id": "8f3a...",
    "session_id": null
  },
  "agent_id": "support-agent",
  "run_id": "8f3a...",
  "session_id": null,
  "sources": ["web_search"],
  "lineage": ["web_search"],
  "matched_rule": "block_untrusted_exfil",
  "trifecta": ["from_untrusted"],
  "untrusted_sources": ["web_search"],
  "run_tainted": false,
  "mode": "enforce",
  "outcome": "block",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "span_id": "00f067aa0ba902b7",
  "timestamp": "2026-01-01T12:00:00+00:00"
}
```

`record_type` is not a model field; `JsonlReporter` injects it alongside
`event.model_dump(mode="json")` so a reader can recover the concrete type
(`"event"`, `"finding"`, or `"endorsement"`) without guessing from shape.
`decision` is the full, nested `Decision` (see
[the API reference](api.md#decision)); the top-level fields duplicate the
subset a consumer commonly filters or aggregates on
(`sources`/`lineage`/`matched_rule`/`trifecta`/`untrusted_sources`/
`run_tainted`/`mode`) so those don't require a hop into `decision` first.
`outcome` is the real, pre-`dry_run`-downgrade action; `decision.action` is
what was actually enforced. `trace_id`/`span_id` are `null` unless
OpenTelemetry was installed and a span was active when the record was
constructed (schema version 6 and later; see below).

## `Finding`

```json
{
  "record_type": "finding",
  "schema_version": 6,
  "source": "web_search",
  "tool": "default.send_email",
  "argument": "body",
  "agent_id": "support-agent",
  "run_id": "8f3a...",
  "session_id": null,
  "trace_id": null,
  "span_id": null,
  "timestamp": "2026-01-01T12:00:00+00:00"
}
```

A laundering-audit hit: `source` leaked into `argument` at `tool` with no
label. See [Auditing](../guides/auditing.md).

## `Endorsement`

```json
{
  "record_type": "endorsement",
  "schema_version": 6,
  "kind": "recipient_allowlisted",
  "note": "checked against the outbound allowlist",
  "lineage": ["web_search"],
  "value_id": "b2c1...",
  "agent_id": "support-agent",
  "run_id": "8f3a...",
  "session_id": null,
  "trace_id": null,
  "span_id": null,
  "timestamp": "2026-01-01T12:00:00+00:00"
}
```

Emitted on every `endorse()` call. See
[Auditing: endorsement](../guides/auditing.md#endorsement).

## OpenTelemetry attribute mapping

[`OTelReporter`](reporters.md#otelreporter) maps these records onto span
events (or a fallback span; see [the OTel guide](../guides/otel.md)) as a
mapping at the edge, never the native format. Attributes are flattened,
`None`-valued fields are omitted, and two fields are deliberately never
serialized:

| Interbolt field | Never mapped because |
| --- | --- |
| `Decision.contributing_labels` | Unbounded: a merge or a large split can carry many labels; the full record is what the native reporters are for. |
| `Decision.matched_condition` | The matched rule's CEL `when:` text may embed a literal (a domain, a path) the policy author did not intend to ship into a third-party trace backend. |

| Interbolt field | OTel attribute | On |
| --- | --- | --- |
| `schema_version` | `interbolt.schema_version` | all |
| `decision.tool` / `tool` | `gen_ai.tool.name` | event, finding |
| `outcome` | `interbolt.outcome` | event |
| `decision.action` | `interbolt.decision.action` | event |
| `decision.decision_id` | `interbolt.decision.id` | event |
| `matched_rule` (if not `None`) | `interbolt.matched_rule` | event |
| `mode` | `interbolt.mode` | event |
| `agent_id` | `interbolt.agent_id` | all |
| `run_id` | `interbolt.run_id` | all |
| `session_id` (if not `None`) | `interbolt.session_id` | all |
| `run_tainted` | `interbolt.run_tainted` | event |
| `sources` | `interbolt.sources` (string sequence) | event |
| `untrusted_sources` | `interbolt.untrusted_sources` (string sequence) | event |
| `trifecta` | `interbolt.trifecta` (string sequence) | event |
| `source` | `interbolt.finding.source` | finding |
| `argument` | `interbolt.finding.argument` | finding |
| `kind` | `interbolt.endorsement.kind` | endorsement |
| `note` (if not `None`) | `interbolt.endorsement.note` | endorsement |

`gen_ai.tool.name` is the one attribute mapped outside the `interbolt.`
namespace: it is the OpenTelemetry GenAI semantic convention's registered
attribute for "name of the tool utilized," an exact semantic fit for the
qualified tool name. No other Interbolt field has an exact GenAI semconv
counterpart, so the rest stay under `interbolt.*`.

## `EVENT_SCHEMA_VERSION` history

| Version | Added |
| --- | --- |
| 1 | Initial `Event`/`Finding` schema. |
| 2 | `run_tainted` on `Decision` and `Event` (run-level gating signal). |
| 3 | `untrusted_sources` on `Decision` and `Event`. |
| 4 | `matched_condition` on `Decision`. |
| 5 | `Label.endorsements`; the new `Endorsement` record type. |
| 6 | `trace_id`/`span_id` on `Event`, `Finding`, and `Endorsement`. |
