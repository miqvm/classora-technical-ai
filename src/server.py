import os
import uuid
import json
from datetime import datetime
from dotenv import load_dotenv
from fastmcp import FastMCP

from adapters.virustotal_service import VirusTotalIOCAnalyserService

# Load variables safely from environment/.env
load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ioc_analyser_service = VirusTotalIOCAnalyserService(api_key=VT_API_KEY)

mcp = FastMCP("Production_IOC_Analysis_Server")

# In-memory storage for state preservation across multi-step LLM operations
db_ioc_context = {}
session_logs = []


def log_action(action: str, details: dict):
    session_logs.append(
        {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "details": details,
        }
    )


@mcp.tool()
async def analyze_ioc(ioc_value: str, ioc_type: str) -> str:
    """
    Analyzes a compromise indicator (IP, domain or hash) against real-world threat intel.

    Args:
        ioc_value: The indicator value (e.g., '8.8.8.8', 'google.com')
        ioc_type: The type of indicator ("ip" | "domain" | "hash")
    """
    valid_types = ["ip", "domain", "hash"]
    if ioc_type.lower() not in valid_types:
        error_msg = (
            f"Error: Invalid ioc_type '{ioc_type}'. Must be one of {valid_types}."
        )
        return error_msg

    try:
        # Call out to the architectural service port
        analysed_data = await ioc_analyser_service.get_context(ioc_value, ioc_type)

        ioc_id = str(uuid.uuid4())
        db_ioc_context[ioc_id] = analysed_data

        log_action(
            "analyze_ioc",
            {"ioc_id": ioc_id, "ioc_value": ioc_value, "ioc_type": ioc_type},
        )
        return f"Analysis complete. IOC ID: {ioc_id}"

    except Exception as e:
        error_msg = f"Analysis failed: {str(e)}"
        return error_msg


@mcp.tool()
async def get_threat_context(ioc_id: str) -> str:
    """
    Returns live threat context data for an already analyzed IOC ID.

    Args:
        ioc_id: The unique identifier for the analyzed IOC (returned from analyze_ioc)
    """
    if ioc_id not in db_ioc_context:
        return f"Error: No context found for IOC ID '{ioc_id}'."

    log_action("get_threat_context", {"ioc_id": ioc_id})
    return json.dumps(db_ioc_context[ioc_id], indent=2)


@mcp.resource("log://analyzed_iocs")
def get_analyzed_iocs_log() -> str:
    """Returns a log of all actions during this session."""
    return json.dumps(session_logs, indent=2)


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
