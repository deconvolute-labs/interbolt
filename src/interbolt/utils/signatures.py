"""Call-argument binding shared by the guard decorator and `track_model_call`."""

from __future__ import annotations

import inspect
from typing import Any


def bind_arguments(
    sig: inspect.Signature, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> dict[str, Any]:
    """Bind a call's positional/keyword arguments to `sig`, defaults applied.

    A leaf-level primitive shared by `runtime/guard.py` (the `guard`
    decorator's argument collection) and `taint/` (`track_model_call`'s
    argument collection), without either importing the other.
    """
    bound = sig.bind(*args, **kwargs)
    bound.apply_defaults()
    return dict(bound.arguments)
