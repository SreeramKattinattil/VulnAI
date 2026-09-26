from abc import ABC, abstractmethod
from typing import Any, Dict, List

from vulnai.scanners.result import Finding


class BaseScanner(ABC):
    """
    Base class for all VulnAI vulnerability scanners.
    """

    name = "base"
    description = "Base vulnerability scanner"

    def __init__(self, client):
        self.client = client

    @abstractmethod
    def scan(
        self,
        endpoint: Dict[str, Any],
    ) -> List[Finding]:
        """
        Scan a single endpoint.

        Every scanner must implement this method.
        """

        raise NotImplementedError

    def supports(
        self,
        endpoint: Dict[str, Any],
    ) -> bool:
        """
        Determine whether this scanner should
        analyze the supplied endpoint.

        Scanners can override this method when
        they need specific endpoint types.
        """

        return True