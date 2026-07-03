"""A minimal multi-file simulated agent app, used by test_multi_module_agent.py.

Deliberately spread across separate modules (sources, model, agents, tools)
to exercise the "agents and tools defined in different modules" story:
`agents.py` defines its handles at import time, before any `configure()`
call anywhere in the test session, the same way a real application's
top-level agent registry would.
"""

from __future__ import annotations
