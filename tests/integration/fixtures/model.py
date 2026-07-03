"""A simulated LLM call, tracked as a new source derived from its inputs."""

from __future__ import annotations

from interbolt import track_model_call


@track_model_call(source="model")  # type: ignore[untyped-decorator]
def summarize(web_result: str, internal_result: str) -> str:
    """Simulates an LLM combining two pieces of context into one summary."""
    return f"summary combining: {web_result[:20]} | {internal_result[:20]}"
