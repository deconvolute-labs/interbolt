"""A tool named `send`, colliding with `tools/a.py`'s `send`."""

from interbolt import guard


@guard
def send(message: str) -> None: ...
