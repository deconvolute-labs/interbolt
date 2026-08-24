"""OpenAI- and Anthropic-shaped dict-literal tool schemas, no decorators."""

from openai import OpenAI

client = OpenAI()

TOOLS = [
    {"type": "function", "function": {"name": "query_customers"}},
    {"name": "send_alert"},
]


def run(prompt: str) -> None:
    client.chat.completions.create(model="gpt-4", messages=[], tools=TOOLS)
