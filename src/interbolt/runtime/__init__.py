"""The composition root: configure() and the process-current runtime."""

from __future__ import annotations

from interbolt.runtime.config import auto_deny as auto_deny
from interbolt.runtime.config import configure as configure
from interbolt.runtime.current import _current as _current
from interbolt.runtime.current import get_runtime as get_runtime
from interbolt.runtime.guard import agent as agent
from interbolt.runtime.guard import check as check
from interbolt.runtime.guard import guard as guard
from interbolt.runtime.runtime import Runtime as Runtime
