from collections import deque
from urllib.parse import urljoin, urlparse, parse_qs

import httpx
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright


class Crawler:
    def __init__(self, start_url: str, max_depth: int = 2):
        self.start_url = start_url.rstrip("/")
        self.max_depth = max_depth

        parsed = urlparse(self.start_url)
        self.base_hostname = parsed.hostname

        self.visited = set()
        self.urls = set()
        self.forms = []
        self.parameters = set()
        self.api_requests = set()

    # ---------------------------------------------------------
    # URL HELPERS
    # ---------------------------------------------------------

    def is_same_domain(self, url: str) -> bool:
        """Check whether a URL belongs to the target hostname."""

        try:
            parsed = urlparse(url)

            return (
                parsed.hostname == self.base_hostname
            )

        except Exception:
            return False

    def normalize_url(self, url: str) -> str:
        """Normalize URLs by removing fragments."""

        try:
            parsed = urlparse(url)

            normalized = parsed._replace(
                fragment=""
            ).geturl()

            if (
                normalized.endswith("/")
                and parsed.path != "/"
            ):
                normalized = normalized.rstrip("/")

            return normalized

        except Exception:
            return url

    def extract_parameters(self, url: str):
        """Extract query-string parameters from a URL."""

        try:
            parsed = urlparse(url)

            query_parameters = parse_qs(
                parsed.query
            )

            for parameter in query_parameters:
                self.parameters.add(parameter)

        except Exception:
            pass

    def add_url(self, url: str):
        """Add a discovered URL if it belongs to the target."""

        try:
            normalized = self.normalize_url(url)

            if not self.is_same_domain(normalized):
                return

            self.urls.add(normalized)

            self.extract_parameters(
                normalized
            )

        except Exception:
            pass

    def add_api_request(self, url: str):
        """Add a discovered API/network request."""

        try:
            normalized = self.normalize_url(url)

            if not self.is_same_domain(normalized):
                return

            self.api_requests.add(normalized)

            self.extract_parameters(
                normalized
            )

        except Exception:
            pass

    # ---------------------------------------------------------
    # HTML ANALYSIS
    # ---------------------------------------------------------

    def extract_page_data(
        self,
        page_url: str,
        html: str
    ):
        """
        Extract links, forms and parameters
        from HTML.
        """

        soup = BeautifulSoup(
            html,
            "lxml"
        )

        # -----------------------------
        # LINKS
        # -----------------------------

        for link in soup.find_all(
            "a",
            href=True
        ):

            href = link.get("href")

            if not href:
                continue

            absolute_url = urljoin(
                page_url,
                href
            )

            self.add_url(
                absolute_url
            )

        # -----------------------------
        # FORMS
        # -----------------------------

        for form in soup.find_all("form"):

            action = form.get(
                "action",
                ""
            )

            method = form.get(
                "method",
                "GET"
            ).upper()

            form_url = urljoin(
                page_url,
                action
            )

            inputs = []

            for element in form.find_all(
                [
                    "input",
                    "textarea",
                    "select"
                ]
            ):

                name = element.get("name")

                if not name:
                    continue

                input_type = element.get(
                    "type",
                    "text"
                )

                inputs.append(
                    {
                        "name": name,
                        "type": input_type
                    }
                )

                self.parameters.add(
                    name
                )

            self.forms.append(
                {
                    "page": page_url,
                    "action": form_url,
                    "method": method,
                    "inputs": inputs,
                }
            )

    # ---------------------------------------------------------
    # HTTP CRAWLER
    # ---------------------------------------------------------

    def crawl_http(self):
        """Crawl normal HTML applications using HTTP."""

        queue = deque()

        queue.append(
            (
                self.start_url,
                0
            )
        )

        visited_http = set()

        headers = {
            "User-Agent": "VulnAI/0.1"
        }

        with httpx.Client(
            follow_redirects=True,
            timeout=10.0,
            headers=headers,
        ) as client:

            while queue:

                current_url, depth = (
                    queue.popleft()
                )

                current_url = (
                    self.normalize_url(
                        current_url
                    )
                )

                if current_url in visited_http:
                    continue

                if depth > self.max_depth:
                    continue

                if not self.is_same_domain(
                    current_url
                ):
                    continue

                visited_http.add(
                    current_url
                )

                print(
                    f"[HTTP] {current_url}"
                )

                try:

                    response = client.get(
                        current_url
                    )

                except httpx.RequestError as error:

                    print(
                        f"[-] HTTP request failed: "
                        f"{error}"
                    )

                    continue

                final_url = self.normalize_url(
                    str(response.url)
                )

                self.add_url(
                    final_url
                )

                content_type = (
                    response.headers.get(
                        "content-type",
                        ""
                    )
                )

                if (
                    "text/html"
                    not in content_type.lower()
                ):
                    continue

                before_urls = set(
                    self.urls
                )

                self.extract_page_data(
                    final_url,
                    response.text
                )

                new_urls = (
                    self.urls - before_urls
                )

                for discovered_url in new_urls:

                    if (
                        discovered_url
                        not in visited_http
                        and depth < self.max_depth
                    ):

                        queue.append(
                            (
                                discovered_url,
                                depth + 1
                            )
                        )

    # ---------------------------------------------------------
    # BROWSER CRAWLER
    # ---------------------------------------------------------

    def crawl_browser(self):
        """
        Crawl JavaScript applications using
        installed Google Chrome.
        """

        queue = deque()

        queue.append(
            (
                self.start_url,
                0
            )
        )

        visited_browser = set()

        chrome_path = (
            r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        )

        with sync_playwright() as playwright:

            browser = playwright.chromium.launch(
                headless=True,
                executable_path=chrome_path
            )

            context = browser.new_context(
                user_agent="VulnAI/0.1"
            )

            page = context.new_page()

            # -------------------------------------------------
            # NETWORK REQUEST CAPTURE
            # -------------------------------------------------

            def handle_request(request):
                """
                Capture browser network requests.
                """

                try:

                    request_url = request.url

                    if not self.is_same_domain(
                        request_url
                    ):
                        return

                    resource_type = (
                        request.resource_type
                    )

                    if resource_type in {
                        "xhr",
                        "fetch"
                    }:

                        self.add_api_request(
                            request_url
                        )

                except Exception:
                    pass

            page.on(
                "request",
                handle_request
            )

            # -------------------------------------------------
            # RESPONSE CAPTURE
            # -------------------------------------------------

            def handle_response(response):
                """
                Capture responses from XHR/fetch.
                """

                try:

                    request = response.request

                    request_url = request.url

                    if not self.is_same_domain(
                        request_url
                    ):
                        return

                    resource_type = (
                        request.resource_type
                    )

                    if resource_type in {
                        "xhr",
                        "fetch"
                    }:

                        self.add_api_request(
                            request_url
                        )

                except Exception:
                    pass

            page.on(
                "response",
                handle_response
            )

            # -------------------------------------------------
            # BROWSER CRAWLING
            # -------------------------------------------------

            while queue:

                current_url, depth = (
                    queue.popleft()
                )

                current_url = (
                    self.normalize_url(
                        current_url
                    )
                )

                if current_url in visited_browser:
                    continue

                if depth > self.max_depth:
                    continue

                if not self.is_same_domain(
                    current_url
                ):
                    continue

                visited_browser.add(
                    current_url
                )

                print(
                    f"[Browser] {current_url}"
                )

                try:

                    page.goto(
                        current_url,
                        wait_until="domcontentloaded",
                        timeout=30000
                    )

                except Exception as error:

                    print(
                        f"[-] Browser navigation error: "
                        f"{error}"
                    )

                    continue

                # -------------------------------------------------
                # Give JavaScript time to execute.
                # -------------------------------------------------

                try:

                    page.wait_for_timeout(
                        5000
                    )

                except Exception:
                    pass

                # -------------------------------------------------
                # Capture current URL.
                # -------------------------------------------------

                current_page_url = (
                    self.normalize_url(
                        page.url
                    )
                )

                self.add_url(
                    current_page_url
                )

                # -------------------------------------------------
                # Capture browser performance entries.
                #
                # This is especially useful for SPAs such as
                # Juice Shop.
                # -------------------------------------------------

                try:

                    performance_urls = (
                        page.evaluate(
                            """
                            () => performance
                                .getEntriesByType('resource')
                                .map(entry => entry.name)
                        """
                        )
                    )

                    for resource_url in (
                        performance_urls or []
                    ):

                        if not isinstance(
                            resource_url,
                            str
                        ):
                            continue

                        if not self.is_same_domain(
                            resource_url
                        ):
                            continue

                        # API-like browser resources.
                        if (
                            resource_url
                            not in self.urls
                        ):

                            self.add_api_request(
                                resource_url
                            )

                except Exception:
                    pass

                # -------------------------------------------------
                # Extract rendered HTML.
                # -------------------------------------------------

                try:

                    html = page.content()

                    self.extract_page_data(
                        current_page_url,
                        html
                    )

                except Exception:
                    pass

                # -------------------------------------------------
                # Discover rendered links.
                # -------------------------------------------------

                try:

                    links = page.locator(
                        "a"
                    ).all()

                    for link in links:

                        try:

                            href = (
                                link.get_attribute(
                                    "href"
                                )
                            )

                        except Exception:
                            continue

                        if not href:
                            continue

                        if href.startswith(
                            (
                                "javascript:",
                                "mailto:",
                                "tel:"
                            )
                        ):
                            continue

                        absolute_url = urljoin(
                            current_page_url,
                            href
                        )

                        absolute_url = (
                            self.normalize_url(
                                absolute_url
                            )
                        )

                        if not self.is_same_domain(
                            absolute_url
                        ):
                            continue

                        self.add_url(
                            absolute_url
                        )

                        if (
                            depth < self.max_depth
                            and absolute_url
                            not in visited_browser
                        ):

                            queue.append(
                                (
                                    absolute_url,
                                    depth + 1
                                )
                            )

                except Exception:
                    pass

                # -------------------------------------------------
                # Discover forms from rendered DOM.
                # -------------------------------------------------

                try:

                    forms = page.locator(
                        "form"
                    ).all()

                    for form in forms:

                        try:

                            action = (
                                form.get_attribute(
                                    "action"
                                )
                                or ""
                            )

                            method = (
                                form.get_attribute(
                                    "method"
                                )
                                or "GET"
                            ).upper()

                            form_url = urljoin(
                                current_page_url,
                                action
                            )

                            inputs = []

                            elements = form.locator(
                                "input, textarea, select"
                            ).all()

                            for element in elements:

                                name = (
                                    element.get_attribute(
                                        "name"
                                    )
                                )

                                input_type = (
                                    element.get_attribute(
                                        "type"
                                    )
                                    or "text"
                                )

                                if name:

                                    inputs.append(
                                        {
                                            "name": name,
                                            "type": input_type
                                        }
                                    )

                                    self.parameters.add(
                                        name
                                    )

                            self.forms.append(
                                {
                                    "page": current_page_url,
                                    "action": form_url,
                                    "method": method,
                                    "inputs": inputs,
                                }
                            )

                        except Exception:
                            continue

                except Exception:
                    pass

            browser.close()

    # ---------------------------------------------------------
    # MAIN CRAWLER
    # ---------------------------------------------------------

    def crawl(self):
        """Run the complete hybrid crawler."""

        print(
            "\n[+] Starting HTTP crawler..."
        )

        self.crawl_http()

        print(
            "\n[+] Starting browser crawler..."
        )

        self.crawl_browser()

        return {
            "urls": self.urls,
            "forms": self.forms,
            "parameters": self.parameters,
            "api_requests": self.api_requests,
        }