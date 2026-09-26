from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Finding:
    """
    Represents a vulnerability discovered by a scanner.
    """

    vulnerability: str
    severity: str
    confidence: str

    url: str
    method: str = "GET"

    parameter: Optional[str] = None
    payload: Optional[str] = None

    evidence: List[str] = field(
        default_factory=list
    )

    description: str = ""

    scanner: str = ""

    def to_dict(self) -> dict:
        """
        Convert the finding into a dictionary.
        """

        return {
            "vulnerability": self.vulnerability,
            "severity": self.severity,
            "confidence": self.confidence,
            "url": self.url,
            "method": self.method,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence,
            "description": self.description,
            "scanner": self.scanner,
        }