from typing import Any, Dict, List

from vulnai.scanners.base import BaseScanner
from vulnai.scanners.result import Finding


class ScannerEngine:
    """
    Coordinates vulnerability scanners.
    """

    def __init__(
        self,
        client,
        scanners: List[BaseScanner] | None = None,
    ):
        self.client = client
        self.scanners = scanners or []

    def register(
        self,
        scanner: BaseScanner,
    ) -> None:
        """
        Register a vulnerability scanner.
        """

        self.scanners.append(scanner)

    def scan_endpoint(
        self,
        endpoint: Dict[str, Any],
    ) -> List[Finding]:
        """
        Run applicable scanners against
        a single endpoint.
        """

        findings: List[Finding] = []

        for scanner in self.scanners:

            try:

                if not scanner.supports(endpoint):
                    continue

                results = scanner.scan(endpoint)

                if results:
                    findings.extend(results)

            except Exception as error:

                print(
                    f"[Scanner Error] "
                    f"{scanner.name}: {error}"
                )

        return findings

    def scan(
        self,
        endpoints: List[Dict[str, Any]],
    ) -> List[Finding]:
        """
        Run all registered scanners against
        all supplied endpoints.
        """

        findings: List[Finding] = []

        for endpoint in endpoints:

            endpoint_findings = self.scan_endpoint(
                endpoint
            )

            findings.extend(
                endpoint_findings
            )

        return self._deduplicate(
            findings
        )

    def _deduplicate(
        self,
        findings: List[Finding],
    ) -> List[Finding]:
        """
        Remove duplicate findings.
        """

        unique_findings = []
        seen = set()

        for finding in findings:

            key = (
                finding.vulnerability,
                finding.method,
                finding.url,
                finding.parameter,
                finding.payload,
            )

            if key in seen:
                continue

            seen.add(key)

            unique_findings.append(
                finding
            )

        return unique_findings

    def scanner_count(self) -> int:
        """
        Return the number of registered scanners.
        """

        return len(self.scanners)

    def scanner_names(self) -> List[str]:
        """
        Return the names of registered scanners.
        """

        return [
            scanner.name
            for scanner in self.scanners
        ]