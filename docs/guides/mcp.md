# MCP

## Status

An MCP client-session integration (`interbolt[mcp]`, providing
`wrap_session`) is specified for this version (see `dev/spec.md` §12.2) but
is **not yet implemented** in this release: there is no `interbolt.mcp`
module and no `[mcp]` extra published yet. This page documents the intended
design and the working pattern to use until the wrapper ships.

## Intended design

Wrapping an MCP client session is meant to:

- Set the [namespace](../concepts/namespacing.md) to the MCP server's name
  (aliased when the server name itself contains a dot, since a namespace
  may not contain one: `wrap_session(session, namespace="acme")`).
- Taint every tool output as untrusted by default, recursing into container
  returns the same way `taint()` does for any other ingress.
- Route each tool call through `check()`, so MCP tool calls are gated by
  the same policy as any other guarded call.

This reuses the existing namespacing and taint primitives and is meant to
add no core dependency; the MCP client library itself sits behind the
optional extra.

## Until the wrapper ships: call `check()` directly

An MCP router or client loop can already be gated today, without the
wrapper, by tainting tool results as they come back and calling `check()`
(or `runtime.check()`) before dispatching each tool call:

```python
from interbolt import check, taint

async def call_mcp_tool(session, server_name: str, tool_name: str, args: dict):
    qualified = f"{server_name}.{tool_name}"  # mind the dot constraint;
                                                # see Namespacing
    decision = check(
        tool=qualified,
        args=args,
        agent_id="my-agent",
    )
    # decision.action handling: raise/approve/proceed, same as @guard does

    result = await session.call_tool(tool_name, args)
    return taint(result, source=server_name)
```

See [the `check()` reference](../reference/api.md#check) and
[Namespacing](../concepts/namespacing.md) for the qualified-name rules this
pattern must respect (neither the server name nor the tool name may itself
contain a dot once qualified; alias a dotted server name to something
dot-free).
