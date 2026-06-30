# CI

## `interbolt validate`

```bash
interbolt validate policy.yaml
```

Static policy analysis only: loads the file, checks it against the policy
schema, compiles every CEL expression (rejecting invalid CEL syntax), flags
dead rules (more than one unconditional catch-all in a sink, or any rule
placed after one), and rejects `when` expressions referencing a
[lethal-trifecta leg](../concepts/policies.md#the-v1-trifecta-limit-read-this)
outside the v1-computable set. It **never executes an agent and never
observes live taint**, and imports no consumer code, which is what lets it
run anywhere a file can be read: CI, pre-commit, a developer's shell. It
runs in milliseconds and exits `0` on success, `1` if any problem is found,
printing each one to the console.

It does not verify that every source name a `when` expression compares
`t.source` against is actually declared in `sources`. An undeclared source
is still handled safely at runtime regardless, since it resolves untrusted
by default-deny; this is a missing lint, not a missing safety property.

The Python-level equivalent, for a custom CI script or a test:

```python
from interbolt import Policy

problems = Policy.validate("policy.yaml")
if problems:
    raise SystemExit("\n".join(problems))
```

## Pre-commit

```yaml
# .pre-commit-config.yaml
- repo: local
  hooks:
    - id: interbolt-validate
      name: interbolt validate
      entry: interbolt validate policy.yaml
      language: system
      pass_filenames: false
```

## The `INTERBOLT_MODE` escape hatch

`interbolt validate` is the static check; it never executes your agent. The
dynamic counterpart is running your actual test suite with the policy
enforced. If a known-noisy or in-progress policy is blocking an
unrelated CI job, the `INTERBOLT_MODE` environment variable overrides
`configure(mode=...)` and the policy file's `defaults.fail_mode`:

```bash
INTERBOLT_MODE=monitor pytest
```

This downgrades evaluation errors to log-and-proceed without disabling
real `block` decisions. Because the override is loud (it logs a warning
whenever it changes the effective mode), it is meant as a deliberate,
visible operator action, not something to set as a default in CI
configuration.

See [Testing](testing.md) for asserting on policy decisions directly in
your test suite, and [Auditing](auditing.md) for running the laundering
audit against a recorded workload in a staging job.
