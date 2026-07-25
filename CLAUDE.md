# Working in this repository

## Read first

[ARCHITECTURE.md](ARCHITECTURE.md) governs. Read in full before writing code. Carry the layering rules, the invariants, the propagation contract, the testing conventions, and
the style rules, and they are the authority wherever anything below overlaps.

If `dev/spec.md` exists in the working tree, read it too and treat it as
governing wherever it overlaps. If it does not exist, do not ask for it,
reference it, or block on it.

## Before any change is done

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy .
uv run pytest
```

All four pass, or the change is not finished.

## Rules specific to working here with an agent

- **Do not implement tests unless explicitly instructed.** When you do, follow
  the conventions in CONTRIBUTING.md rather than building a harness.
- **A wall-clock stress test that fails under coverage but passes in isolation
  is a timing flake.** Do not "fix" it by changing library code.
- **Never weaken the propagation contract or the default-deny posture as a side
  effect of another change.** If a change alters what propagates, what a
  missing rule falls through to, or what an undeclared source resolves to, stop
  and say so explicitly rather than absorbing it into a larger diff.
- **A docstring that describes behavior the code does not have is a defect of
  the same kind as a wrong branch.** In a library whose value is that its
  guarantees are precise, do not write an aspirational docstring.
- **Docstrings and comments never justify themselves.** No references to an
  internal design document, a ticket or PR number, or a line-count threshold.
  Do not explain why something is not done, why an alternative was rejected, or
  otherwise narrate a design discussion. State what the code does and, where it
  genuinely helps a reader, why it does it that way, in a way that stands on
  its own.
- **Record shapes are versioned.** Changing `Event`, `Finding`, `Endorsement`,
  or `Label` means bumping `constants.EVENT_SCHEMA_VERSION`. Changing the
  `pack`/`unpack` envelope means bumping `constants.WIRE_SCHEMA_VERSION`.
- **Do not add a mutable module-level global.** The two modules permitted to
  hold process-global state are named in ARCHITECTURE.md.
- **Do not add a third container walk.** The two permitted traversals are named
  in ARCHITECTURE.md.

## Style

American English. No em dash, no double dash. No `print()`: CLI output goes
through `rich.console.Console`, log output through the library logger.
