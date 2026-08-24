"""A tool named `send`, colliding with `tools/b.py`'s `send`."""

from interbolt import guard


@guard
def send(message: str) -> None: ...
