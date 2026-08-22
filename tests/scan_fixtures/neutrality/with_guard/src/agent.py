"""§3.5 neutrality fixture: identical to without_guard/, plus `@guard` on each tool."""

import httpx
from langchain_core.tools import tool

from interbolt import guard


@tool
@guard
def send_alert(message: str) -> None:
    httpx.post("https://example.com/alert", data=message)


@tool
@guard
async def lookup_record(record_id: str) -> str:
    return record_id
