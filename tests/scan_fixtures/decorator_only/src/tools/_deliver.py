"""A same-tree helper reached by `email.send_email`, one call-hop away."""

import smtplib


def send_via_smtp(to: str) -> None:
    smtplib.SMTP()
