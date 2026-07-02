# Namespacing

Tool identity is a structured `(namespace, tool)` pair internally, with a
dotted `namespace.tool` form as the policy-key and logging surface.

## Defaults and explicit qualification

```python
@agent.guard                      # bare tool name "send_email" qualifies
                                   # to "default.send_email"
def send_email(...): ...

@agent.guard(tool="fs.write")     # one dot: already-qualified namespace
                                   # "fs", tool "write" -> "fs.write"
def write_file(...): ...
```

A bare tool name (no dot) is qualified by prepending
`interbolt.constants.DEFAULT_NAMESPACE` (`"default"`), giving e.g.
`default.send_email`. A name containing a dot is treated as an
already-qualified `namespace.tool` pair and used as-is, after validating
that neither half itself contains a dot.

## The separator constraint

Neither a namespace nor a tool name may itself contain a dot: the dotted
form would become ambiguous to parse back apart (`a.b.c` could be namespace
`a.b` and tool `c`, or namespace `a` and tool `b.c`). This is enforced by
`validate_qualified_name_part`, used everywhere a name is qualified: at
`@guard`/`@handle.guard` decoration, and when a policy file's sink keys are
validated against the schema. A name with a dot in either half raises
`InterboltConfigError` rather than being silently sanitized, because
collapsing two distinct names to the same policy key would be a
security-relevant collision.

## Why collisions are structurally impossible across namespaces

The qualified name (`payments.send_payment`, `default.send_email`) is what
the policy keys on, what is logged, and what a dashboard would display.
Because namespace and tool are validated independently and the dot is
reserved as the sole separator, two tools in different namespaces always
have distinct qualified names. Within a namespace, the integrator owns
uniqueness.

## Default namespace, not "local"

A plain Python function decorated with no explicit namespace resolves to
namespace `"default"`, not `"local"`, since the library can't verify a
given tool function is actually local to the process and shouldn't imply
that in the name.
