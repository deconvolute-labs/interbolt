"""A LangChain-style tool, discovered by decorator, no Interbolt import."""

import sqlalchemy
from langchain_core.tools import tool


@tool
def query_customers(name: str) -> str:
    engine = sqlalchemy.create_engine("sqlite://")
    return name
