import json
from pathlib import Path

from ..mcp import mcp_ollama_tools


def get_tool_definitions() -> list[dict]:
    schema_path = Path(__file__).parent.parent / "data" / "tools.json"
    with open(schema_path, "r") as f:
        tools = json.load(f)

    tools.extend(mcp_ollama_tools(max_servers=10))
    return tools
