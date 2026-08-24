"""An interbolt-guarded tool, cross-file evidence via `_deliver.py`."""

from interbolt import guard

from tools._deliver import send_via_smtp


@guard(tool="email.send_email")
def send_email(to: str) -> None:
    send_via_smtp(to)
