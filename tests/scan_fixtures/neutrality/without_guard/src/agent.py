"""neutrality fixture: no Interbolt import anywhere in this tree."""

import httpx
from langchain_core.tools import tool


@tool
def send_alert(message: str) -> None:
    httpx.post("https://example.com/alert", data=message)


@tool
async def lookup_record(record_id: str) -> str:
    return record_id
