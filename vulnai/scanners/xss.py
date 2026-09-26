import re

from typing import Any, Dict, List, Optional
from urllib.parse import (
    parse_qsl,
    urlencode,
    urlsplit,
    urlunsplit,
)

from vulnai.scanners.base import BaseScanner
from vulnai.scanners.result import Finding


class ReflectedXSSScanner(BaseScanner):
    """
    Detect potential reflected XSS by injecting a unique
    marker into URL query parameters and analyzing the
    reflection context in the HTTP response.

    This scanner does not automatically treat reflection
    as confirmed XSS.
    """

    name = "reflected-xss"

    description = (
        "Detects potentially dangerous reflected input "
        "and identifies its response context."
    )

    TEST_MARKER = "VULNAI_XSS_TEST_9F3A"

    def supports(
        self,
        endpoint: Dict[str, Any],
    ) -> bool:
        """
        Only test endpoints that expose parameters.
        """

        parameters = endpoint.get(
            "parameters",
            [],
        )

        method = endpoint.get(
            "method",
            "GET",
        ).upper()

        return (
            method == "GET"
            and bool(parameters)
        )

    def scan(
        self,
        endpoint: Dict[str, Any],
    ) -> List[Finding]:
        """
        Test each discovered query parameter.
        """

        findings: List[Finding] = []

        url = endpoint.get("url")

        if not url:
            return findings

        parameters = endpoint.get(
            "parameters",
            [],
        )

        for parameter in parameters:

            finding = self._test_parameter(
                url=url,
                parameter=parameter,
                method=endpoint.get(
                    "method",
                    "GET",
                ),
            )

            if finding:
                findings.append(
                    finding
                )

        return findings

    def _test_parameter(
        self,
        url: str,
        parameter: str,
        method: str,
    ) -> Optional[Finding]:
        """
        Inject a unique marker into one query parameter
        and analyze how it is reflected.
        """

        parsed = urlsplit(url)

        query_parameters = parse_qsl(
            parsed.query,
            keep_blank_values=True,
        )

        if not query_parameters:
            return None

        modified_parameters = []

        parameter_found = False

        for name, value in query_parameters:

            if name == parameter:

                modified_parameters.append(
                    (
                        name,
                        self.TEST_MARKER,
                    )
                )

                parameter_found = True

            else:

                modified_parameters.append(
                    (
                        name,
                        value,
                    )
                )

        if not parameter_found:
            return None

        modified_query = urlencode(
            modified_parameters,
            doseq=True,
        )

        test_url = urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                modified_query,
                parsed.fragment,
            )
        )

        try:

            response = self.client.get(
                test_url
            )

        except Exception:

            return None

        response_text = response.text

        if self.TEST_MARKER not in response_text:
            return None

        context = self._detect_context(
            response_text
        )

        if context is None:

            context = "UNKNOWN"

        severity = self._determine_severity(
            context
        )

        confidence = self._determine_confidence(
            context
        )

        evidence = [
            (
                f"Marker '{self.TEST_MARKER}' "
                f"was reflected in the HTTP response."
            ),
            (
                f"Parameter: {parameter}"
            ),
            (
                f"Reflection context: {context}"
            ),
            (
                f"Test URL: {test_url}"
            ),
        ]

        return Finding(
            vulnerability=(
                "Potential Reflected XSS"
            ),
            severity=severity,
            confidence=confidence,
            url=test_url,
            method=method,
            parameter=parameter,
            payload=self.TEST_MARKER,
            evidence=evidence,
            description=(
                "User-controlled input was reflected "
                "in the HTTP response. The scanner "
                "identified the reflection context, "
                "but reflection alone does not prove "
                "that JavaScript execution is possible."
            ),
            scanner=self.name,
            reflection_context=context,
            verified=False,
        )

    def _detect_context(
        self,
        response_text: str,
    ) -> Optional[str]:
        """
        Determine the approximate context in which
        the marker appears.
        """

        marker = re.escape(
            self.TEST_MARKER
        )

        script_pattern = re.compile(
            rf"<script\b[^>]*>.*?{marker}.*?</script>",
            re.IGNORECASE | re.DOTALL,
        )

        if script_pattern.search(
            response_text
        ):
            return "SCRIPT"

        event_handler_pattern = re.compile(
            rf"\bon[a-z]+\s*=\s*['\"][^'\"]*"
            rf"{marker}",
            re.IGNORECASE,
        )

        if event_handler_pattern.search(
            response_text
        ):
            return "EVENT_HANDLER"

        attribute_pattern = re.compile(
            rf"<[^>]+\b[a-zA-Z_:][-a-zA-Z0-9_:.]*"
            rf"\s*=\s*['\"][^'\"]*{marker}",
            re.IGNORECASE,
        )

        if attribute_pattern.search(
            response_text
        ):
            return "HTML_ATTRIBUTE"

        tag_pattern = re.compile(
            rf"<[^>]*{marker}[^>]*>",
            re.IGNORECASE,
        )

        if tag_pattern.search(
            response_text
        ):
            return "HTML_TAG"

        json_string_pattern = re.compile(
            rf'["\'][^"\']*{marker}[^"\']*["\']'
        )

        if json_string_pattern.search(
            response_text
        ):
            return "JSON_OR_STRING"

        return "HTML_TEXT"

    def _determine_severity(
        self,
        context: str,
    ) -> str:
        """
        Assign a preliminary severity based on
        reflection context.

        This is not a final vulnerability severity.
        """

        if context in {
            "SCRIPT",
            "EVENT_HANDLER",
        }:
            return "High"

        if context in {
            "HTML_ATTRIBUTE",
            "HTML_TAG",
        }:
            return "Medium"

        return "Low"

    def _determine_confidence(
        self,
        context: str,
    ) -> str:
        """
        Assign confidence based on the detected
        reflection context.
        """

        if context in {
            "SCRIPT",
            "EVENT_HANDLER",
        }:
            return "Medium"

        if context in {
            "HTML_ATTRIBUTE",
            "HTML_TAG",
        }:
            return "Low"

        return "Low"