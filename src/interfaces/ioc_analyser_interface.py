from abc import ABC, abstractmethod


class IOCAnalyserInterface(ABC):
    @abstractmethod
    async def get_context(self, ioc_value: str, ioc_type: str) -> dict:
        """Fetch threat enrichment details for an IP, domain, or file hash."""
        pass
