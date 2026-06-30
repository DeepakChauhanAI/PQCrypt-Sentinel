from abc import ABC, abstractmethod
from typing import Dict, Any


class BaseConnector(ABC):
    """
    Abstract base class for all CMDB and discovery integration connectors.
    """

    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    async def sync(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Execute the synchronization/import process.
        Returns a dictionary summarizing the results (e.g., assets_imported, errors).
        """
        pass
