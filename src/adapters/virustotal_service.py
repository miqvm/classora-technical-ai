import httpx
from datetime import datetime, timezone
from typing import Dict, Any

from interfaces.ioc_analyser_interface import IOCAnalyserInterface


class VirusTotalIOCAnalyserService(IOCAnalyserInterface):
    def __init__(
        self,
        api_key: str,
        base_url: str = "https://www.virustotal.com/api/v3",
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self._api_key = api_key
        self._base_url = base_url
        self._timeout = httpx.Timeout(5.0)
        self._transport = transport

    def _get_endpoint(self, ioc_value: str, ioc_type: str) -> str:
        t = ioc_type.lower()
        # Build the correct endpoint depending on the IOC type
        if t == "ip":
            return f"{self._base_url}/ip_addresses/{ioc_value}"
        elif t == "domain":
            return f"{self._base_url}/domains/{ioc_value}"
        elif t == "hash":
            return f"{self._base_url}/monitor_partner/hashes/{ioc_value}"
        else:
            raise ValueError(f"Unsupported IOC type: {ioc_type}")

    async def get_context(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        try:
            url = self._get_endpoint(ioc_value, ioc_type)
        except ValueError as e:
            raise Exception(str(e))

        # Prepare request headers and retry policy
        headers = {"x-apikey": self._api_key, "accept": "application/json"}
        max_attempts = 3

        async with httpx.AsyncClient(
            timeout=self._timeout, transport=self._transport
        ) as client:
            for attempt in range(1, max_attempts + 1):
                try:
                    response = await client.get(url, headers=headers)
                    response.raise_for_status()

                    # Parse the JSON response and extract the attributes block
                    attributes = response.json().get("data", {}).get("attributes", {})

                    # Calculate a simple reputation score based on malicious votes
                    stats = attributes.get("last_analysis_stats", {})
                    malicious_votes = stats.get("malicious", 0)
                    reputation_score = min(malicious_votes * 10, 100)

                    # Prefer last_analysis_date, fallback to last_modification_date
                    date_unix = attributes.get("last_analysis_date") or attributes.get(
                        "last_modification_date"
                    )
                    last_seen = (
                        datetime.fromtimestamp(date_unix, tz=timezone.utc).isoformat()
                        if date_unix
                        else "Unknown"
                    )

                    # Return a plain dictionary instead of a strict model
                    return {
                        "ioc_value": ioc_value,
                        "ioc_type": ioc_type,
                        "reputation_score": reputation_score,
                        "categories": attributes.get("tags", []),
                        "last_seen": last_seen,
                        "country": attributes.get("country", "Unknown"),
                    }

                except httpx.HTTPStatusError as e:
                    # Retry on server errors (5xx)
                    if e.response.status_code >= 500 and attempt < max_attempts:
                        continue
                    # If the IOC is not found, return a neutral result
                    if e.response.status_code == 404:
                        return {
                            "ioc_value": ioc_value,
                            "ioc_type": ioc_type,
                            "reputation_score": 0,
                            "categories": [],
                            "last_seen": "Never",
                            "country": "Unknown",
                        }
                    # Surface other HTTP errors
                    raise Exception(
                        f"VirusTotal failed with HTTP {e.response.status_code}"
                    ) from e
                except httpx.RequestError as e:
                    # Network/transport level error
                    raise Exception(f"VirusTotal request failed: {str(e)}") from e
