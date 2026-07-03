"""Guarded tools, imported from a module separate from the agents that own them.

Mixes both binding patterns in one file: tools bound to a specific,
durable agent identity via the handles in `agents.py`, and a bare `@guard`
tool that picks up whichever agent identity is ambient at call time.
"""

from __future__ import annotations

from fixtures.agents import research_agent, writer_agent
from interbolt.runtime import guard


@research_agent.guard(tool="send_email")
def send_email(to: str, body: str) -> None:
    pass


@writer_agent.guard(tool="fs_write")
def write_file(path: str, content: str) -> None:
    pass


@guard(tool="run_shell")  # type: ignore[untyped-decorator]
def run_shell(command: str) -> None:
    pass
