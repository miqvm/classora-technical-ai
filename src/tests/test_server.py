import pytest
import json
from unittest.mock import AsyncMock, patch

import server


@pytest.fixture(autouse=True)
def reset_server_state():
    """
    Fixture to clear the server's in-memory state before every test.
    This guarantees isolated and deterministic test runs.
    """
    server.db_ioc_context.clear()
    server.session_logs.clear()


@pytest.mark.asyncio
async def test_analyze_ioc_success():
    """Test that a valid IOC is processed and stored correctly."""

    # Define the mocked response from our VirusTotal adapter
    mock_vt_response = {
        "ioc_value": "8.8.8.8",
        "ioc_type": "ip",
        "reputation_score": 50,
        "categories": ["suspicious"],
        "last_seen": "2023-10-12T12:00:00Z",
        "country": "US",
    }

    # Patch the get_context method of the globally instantiated service in server.py
    with patch.object(
        server.ioc_analyser_service, "get_context", new_callable=AsyncMock
    ) as mock_get_context:
        mock_get_context.return_value = mock_vt_response

        # Call the server tool directly
        result = await server.analyze_ioc("8.8.8.8", "ip")

        # Verify the response format
        assert "Analysis complete. IOC ID:" in result

        # Extract the generated UUID
        ioc_id = result.split("IOC ID: ")[1].strip()

        # Verify it was saved in the in-memory database
        assert ioc_id in server.db_ioc_context
        assert server.db_ioc_context[ioc_id] == mock_vt_response

        # Verify the action was logged
        assert len(server.session_logs) == 1
        assert server.session_logs[0]["action"] == "analyze_ioc"


@pytest.mark.asyncio
async def test_analyze_ioc_invalid_type():
    """Test that an invalid IOC type is rejected properly."""
    result = await server.analyze_ioc("12345", "unsupported_type")

    assert "Error: Invalid ioc_type" in result
    # It shouldn't log an action or save to DB if it fails early
    assert len(server.db_ioc_context) == 0


@pytest.mark.asyncio
async def test_get_threat_context_success():
    """Test fetching context for an already analyzed IOC."""
    # Pre-populate the database
    fake_id = "test-uuid-1234"
    fake_data = {"ioc_value": "google.com", "reputation_score": 0}
    server.db_ioc_context[fake_id] = fake_data

    # Call the tool
    result = await server.get_threat_context(fake_id)

    # Verify the JSON output matches what we injected
    parsed_result = json.loads(result)
    assert parsed_result == fake_data

    # Verify logging
    assert len(server.session_logs) == 1
    assert server.session_logs[0]["action"] == "get_threat_context"


@pytest.mark.asyncio
async def test_get_threat_context_not_found():
    """Test handling of an unknown IOC ID."""
    result = await server.get_threat_context("non-existent-id")
    assert "Error: No context found for IOC ID" in result


def test_get_analyzed_iocs_log():
    """Test the Senior requirement: Resource endpoint for session logs."""
    # Inject fake logs
    server.log_action("test_action", {"detail": "info"})

    # Call the resource function
    result = server.get_analyzed_iocs_log()
    parsed_logs = json.loads(result)

    assert len(parsed_logs) == 1
    assert parsed_logs[0]["action"] == "test_action"
    assert parsed_logs[0]["details"] == {"detail": "info"}
    assert "timestamp" in parsed_logs[0]
