"""Agent identity handles, defined at import time.

Both handles are created here, at module import, with no `configure()` call
having run anywhere in the process yet. This is exactly what a real
application's top-level agent registry looks like: `tools.py` imports these
handles to decorate its functions, and neither module needs to know or care
when (or whether) `configure()` has been called yet.
"""

from __future__ import annotations

from interbolt import agent

research_agent = agent("research-agent")
writer_agent = agent("writer-agent")
