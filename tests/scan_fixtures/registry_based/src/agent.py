"""Tools registered dynamically at runtime; the scanner cannot enumerate them."""

from acme_agents import register_tool


def lookup_customer(customer_id: str) -> str:
    return customer_id


register_tool(lookup_customer)
