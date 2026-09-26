from collections import deque
from urllib.parse import (
    urljoin,
    urlparse,
    parse_qs,
    urlunparse,
)

import httpx
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright


class Crawler:

    def __init__(
        self,
        start_url: str,
        max_depth: int = 2,
    ):
        self.start_url = start_url.rstrip("/")
        self.max_depth = max_depth

        parsed_start = urlparse(self.start_url)

        self.base_hostname = parsed_start.hostname

        # ======================================================
        # GENERAL CRAWLER STATE
        # ======================================================

        self.visited = set()
        self.urls = set()

        # ======================================================
        # DISCOVERED FORMS
        # ======================================================

        self.forms = []

        # ======================================================
        # PARAMETERS
        # ======================================================

        self.parameters = set()

        # ======================================================
        # RAW API / NETWORK REQUESTS
        # ======================================================

        self.api_requests = set()

        # ======================================================
        # STRUCTURED ENDPOINT INVENTORY
        #
        # Key:
        #
        #     METHOD + PATH
        #
        # Example:
        #
        #     GET /rest/products/search
        #
        # Query values are intentionally ignored when
        # generating the endpoint key.
        # ======================================================

        self.endpoint_inventory = {}

    # ==========================================================
    # URL HELPERS
    # ==========================================================

    def is_same_domain(
        self,
        url: str,
    ) -> bool:
        """
        Check whether a URL belongs to the target hostname.
        """

        try:

            parsed = urlparse(url)

            return (
                parsed.hostname
                == self.base_hostname
            )

        except Exception:

            return False

    def normalize_url(
        self,
        url: str,
    ) -> str:
        """
        Normalize a URL so duplicate URLs are reduced.
        """

        try:

            parsed = urlparse(url)

            scheme = parsed.scheme.lower()

            hostname = (
                parsed.hostname.lower()
                if parsed.hostname
                else ""
            )

            port = parsed.port

            if port:

                if (
                    (
                        scheme == "http"
                        and port == 80
                    )
                    or
                    (
                        scheme == "https"
                        and port == 443
                    )
                ):

                    netloc = hostname

                else:

                    netloc = (
                        f"{hostname}:{port}"
                    )

            else:

                netloc = hostname

            path = parsed.path or "/"

            # Normalize duplicate slashes.
            while "//" in path:

                path = path.replace(
                    "//",
                    "/",
                )

            query = parsed.query

            return urlunparse(
                (
                    scheme,
                    netloc,
                    path,
                    "",
                    query,
                    "",
                )
            )

        except Exception:

            return url

    def extract_parameters(
        self,
        url: str,
    ):
        """
        Extract query parameter names from a URL.
        """

        try:

            parsed = urlparse(url)

            parameters = parse_qs(
                parsed.query,
                keep_blank_values=True,
            )

            for parameter in parameters.keys():

                self.parameters.add(
                    parameter
                )

        except Exception:

            pass

    # ==========================================================
    # ENDPOINT CLASSIFICATION
    # ==========================================================

    def classify_url(
        self,
        url: str,
        resource_type: str | None = None,
        method: str = "GET",
    ) -> str:
        """
        Classify a discovered URL.

        Possible types:

            API
            WEB
            STATIC
            SOCKET
            OTHER
        """

        try:

            parsed = urlparse(url)

            path = parsed.path.lower()

            normalized_method = (
                method.upper()
                if method
                else "GET"
            )

            resource = (
                resource_type.lower()
                if resource_type
                else ""
            )

            # ==================================================
            # SOCKET
            # ==================================================

            if (
                resource == "websocket"
                or "/socket.io" in path
                or path.startswith("/socket")
            ):

                return "SOCKET"

            # ==================================================
            # STATIC RESOURCES
            #
            # Check these BEFORE generic XHR/fetch detection.
            #
            # This is important because files such as:
            #
            #     /assets/i18n/en.json
            #
            # can be loaded through XHR/fetch while still
            # being static application resources.
            # ==================================================

            static_extensions = (
                ".js",
                ".mjs",
                ".css",
                ".png",
                ".jpg",
                ".jpeg",
                ".gif",
                ".svg",
                ".ico",
                ".webp",
                ".avif",
                ".bmp",
                ".tif",
                ".tiff",
                ".woff",
                ".woff2",
                ".ttf",
                ".otf",
                ".eot",
                ".map",
                ".mp3",
                ".mp4",
                ".wav",
                ".webm",
                ".pdf",
                ".zip",
                ".gz",
                ".tar",
            )

            if path.endswith(
                static_extensions
            ):

                return "STATIC"

            # --------------------------------------------------
            # JSON APPLICATION ASSETS
            # --------------------------------------------------

            if (
                path.endswith(".json")
                and (
                    path.startswith(
                        "/assets/"
                    )
                    or path.startswith(
                        "/static/"
                    )
                    or "/assets/" in path
                )
            ):

                return "STATIC"

            # ==================================================
            # API
            # ==================================================

            api_prefixes = (
                "/api/",
                "/api",
                "/rest/",
                "/rest",
                "/graphql",
                "/graphql/",
                "/v1/",
                "/v2/",
                "/v3/",
                "/oauth/",
                "/oauth",
                "/auth/",
                "/auth",
            )

            if path.startswith(
                api_prefixes
            ):

                return "API"

            # --------------------------------------------------
            # XHR / FETCH
            #
            # If the URL is not a known static resource and
            # was loaded using XHR/fetch, treat it as an API.
            # --------------------------------------------------

            if resource in (
                "xhr",
                "fetch",
            ):

                return "API"

            # ==================================================
            # WEB
            # ==================================================

            if resource in (
                "document",
                "form",
                "navigation",
            ):

                return "WEB"

            # Navigation methods are also considered WEB
            # when no more specific classification exists.
            if normalized_method in (
                "GET",
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
                "OPTIONS",
                "HEAD",
            ):

                return "WEB"

            return "OTHER"

        except Exception:

            return "OTHER"

    # ==========================================================
    # ENDPOINT INVENTORY
    # ==========================================================

    def add_endpoint(
        self,
        url: str,
        method: str = "GET",
        source: str = "unknown",
        resource_type: str | None = None,
    ):
        """
        Add or update an endpoint in the structured inventory.
        """

        if not url:

            return

        try:

            normalized_url = (
                self.normalize_url(url)
            )

            if not self.is_same_domain(
                normalized_url
            ):

                return

            parsed = urlparse(
                normalized_url
            )

            method = (
                method.upper()
                if method
                else "GET"
            )

            path = (
                parsed.path
                or "/"
            )

            endpoint_type = (
                self.classify_url(
                    normalized_url,
                    resource_type=resource_type,
                    method=method,
                )
            )

            query_parameters = list(
                parse_qs(
                    parsed.query,
                    keep_blank_values=True,
                ).keys()
            )

            # Add discovered parameter names
            # to the global parameter set.
            for parameter in (
                query_parameters
            ):

                self.parameters.add(
                    parameter
                )

            # ==================================================
            # ENDPOINT IDENTITY
            #
            # Query values are ignored.
            #
            # Example:
            #
            # /rest/products/search?q=apple
            # /rest/products/search?q=phone
            #
            # become:
            #
            # GET /rest/products/search
            # ==================================================

            endpoint_key = (
                f"{method} {path}"
            )

            if (
                endpoint_key
                not in self.endpoint_inventory
            ):

                self.endpoint_inventory[
                    endpoint_key
                ] = {
                    "method": method,
                    "url": normalized_url,
                    "path": path,
                    "parameters": set(),
                    "type": endpoint_type,
                    "sources": set(),
                    "resource_types": set(),
                    "observed_urls": set(),
                }

            endpoint = (
                self.endpoint_inventory[
                    endpoint_key
                ]
            )

            endpoint[
                "parameters"
            ].update(
                query_parameters
            )

            endpoint[
                "sources"
            ].add(
                source
            )

            if resource_type:

                endpoint[
                    "resource_types"
                ].add(
                    resource_type
                )

            endpoint[
                "observed_urls"
            ].add(
                normalized_url
            )

            # --------------------------------------------------
            # Classification upgrade
            #
            # API should take precedence over WEB/OTHER if
            # the same endpoint is later discovered through
            # an API-specific source.
            # --------------------------------------------------

            if endpoint_type == "API":

                endpoint[
                    "type"
                ] = "API"

            elif (
                endpoint["type"]
                == "OTHER"
                and endpoint_type
                != "OTHER"
            ):

                endpoint[
                    "type"
                ] = endpoint_type

        except Exception:

            pass

    # ==========================================================
    # URL REGISTRATION
    # ==========================================================

    def add_url(
        self,
        url: str,
        source: str = "unknown",
    ):
        """
        Add a discovered page URL.
        """

        if not url:

            return

        try:

            normalized_url = (
                self.normalize_url(url)
            )

            if not self.is_same_domain(
                normalized_url
            ):

                return

            self.extract_parameters(
                normalized_url
            )

            self.urls.add(
                normalized_url
            )

            self.add_endpoint(
                normalized_url,
                method="GET",
                source=source,
                resource_type="document",
            )

        except Exception:

            pass

    # ==========================================================
    # API / NETWORK REGISTRATION
    # ==========================================================

    def add_api_request(
        self,
        url: str,
        method: str = "GET",
        source: str = "network",
        resource_type: str = "xhr",
    ):
        """
        Register an API/network request.

        Static resources are still checked by classify_url()
        so that an asset such as /assets/i18n/en.json is not
        incorrectly classified as an API.
        """

        if not url:

            return

        try:

            normalized_url = (
                self.normalize_url(url)
            )

            if not self.is_same_domain(
                normalized_url
            ):

                return

            self.extract_parameters(
                normalized_url
            )

            # Keep the raw network request.
            self.api_requests.add(
                normalized_url
            )

            self.add_endpoint(
                normalized_url,
                method=method,
                source=source,
                resource_type=resource_type,
            )

        except Exception:

            pass

    # ==========================================================
    # HTML EXTRACTION
    # ==========================================================

    def extract_page_data(
        self,
        html: str,
        current_url: str,
        source: str = "html",
    ):
        """
        Extract:

        - links
        - forms
        - form inputs
        """

        try:

            soup = BeautifulSoup(
                html,
                "lxml",
            )

        except Exception:

            soup = BeautifulSoup(
                html,
                "html.parser",
            )

        # ======================================================
        # LINKS
        # ======================================================

        for link in soup.find_all("a"):

            href = link.get(
                "href"
            )

            if not href:

                continue

            href = href.strip()

            if href.startswith(
                (
                    "#",
                    "javascript:",
                    "mailto:",
                    "tel:",
                )
            ):

                continue

            absolute_url = urljoin(
                current_url,
                href,
            )

            if self.is_same_domain(
                absolute_url
            ):

                self.add_url(
                    absolute_url,
                    source=source,
                )

        # ======================================================
        # FORMS
        # ======================================================

        for form in soup.find_all(
            "form"
        ):

            action = form.get(
                "action"
            )

            if action:

                action = urljoin(
                    current_url,
                    action,
                )

            else:

                action = current_url

            if not self.is_same_domain(
                action
            ):

                continue

            method = (
                form.get(
                    "method",
                    "GET",
                )
                .upper()
            )

            inputs = []

            for input_field in (
                form.find_all(
                    [
                        "input",
                        "textarea",
                        "select",
                        "button",
                    ]
                )
            ):

                name = input_field.get(
                    "name"
                )

                input_type = (
                    input_field.get(
                        "type",
                        input_field.name,
                    )
                    or input_field.name
                )

                if name:

                    self.parameters.add(
                        name
                    )

                inputs.append(
                    {
                        "name": (
                            name
                            or ""
                        ),
                        "type": input_type,
                    }
                )

            form_data = {
                "page": current_url,
                "action": action,
                "method": method,
                "inputs": inputs,
            }

            self.forms.append(
                form_data
            )

            self.add_endpoint(
                action,
                method=method,
                source="form",
                resource_type="form",
            )

    # ==========================================================
    # HTTP CRAWLER
    # ==========================================================

    def crawl_http(self):
        """
        Crawl pages using normal HTTP requests.
        """

        print(
            "\n[+] Starting HTTP crawler..."
        )

        queue = deque()

        queue.append(
            (
                self.start_url,
                0,
            )
        )

        client = httpx.Client(
            timeout=10.0,
            follow_redirects=True,
        )

        while queue:

            current_url, depth = (
                queue.popleft()
            )

            normalized_url = (
                self.normalize_url(
                    current_url
                )
            )

            if normalized_url in (
                self.visited
            ):

                continue

            if depth > self.max_depth:

                continue

            if not self.is_same_domain(
                normalized_url
            ):

                continue

            self.visited.add(
                normalized_url
            )

            print(
                f"[HTTP] {normalized_url}"
            )

            try:

                response = client.get(
                    normalized_url
                )

                final_url = (
                    self.normalize_url(
                        str(response.url)
                    )
                )

                if not self.is_same_domain(
                    final_url
                ):

                    continue

                self.add_url(
                    final_url,
                    source="http",
                )

                content_type = (
                    response.headers.get(
                        "content-type",
                        "",
                    )
                    .lower()
                )

                # Only parse HTML pages.
                if "text/html" not in (
                    content_type
                ):

                    continue

                self.extract_page_data(
                    response.text,
                    final_url,
                    source="html",
                )

                # Add discovered URLs to queue.
                for discovered_url in list(
                    self.urls
                ):

                    if discovered_url in (
                        self.visited
                    ):

                        continue

                    if not self.is_same_domain(
                        discovered_url
                    ):

                        continue

                    queue.append(
                        (
                            discovered_url,
                            depth + 1,
                        )
                    )

            except Exception as error:

                print(
                    f"[HTTP ERROR] "
                    f"{normalized_url}: "
                    f"{error}"
                )

        client.close()

    # ==========================================================
    # BROWSER NETWORK HANDLERS
    # ==========================================================

    def handle_browser_request(
        self,
        request,
    ):
        """
        Capture browser network requests.

        XHR/fetch requests are recorded as network/API
        candidates, but classification is ultimately handled
        by classify_url().
        """

        try:

            url = request.url

            if not self.is_same_domain(
                url
            ):

                return

            method = (
                request.method
                or "GET"
            ).upper()

            resource_type = (
                request.resource_type
                or ""
            ).lower()

            if resource_type in (
                "xhr",
                "fetch",
            ):

                self.add_api_request(
                    url,
                    method=method,
                    source="browser-network",
                    resource_type=resource_type,
                )

            else:

                self.add_endpoint(
                    url,
                    method=method,
                    source="browser-network",
                    resource_type=resource_type,
                )

        except Exception:

            pass

    def handle_browser_response(
        self,
        response,
    ):
        """
        Capture browser responses.

        Useful for applications that expose API endpoints
        only after JavaScript execution.
        """

        try:

            request = response.request

            url = response.url

            if not self.is_same_domain(
                url
            ):

                return

            method = (
                request.method
                or "GET"
            ).upper()

            resource_type = (
                request.resource_type
                or ""
            ).lower()

            if resource_type in (
                "xhr",
                "fetch",
            ):

                self.add_api_request(
                    url,
                    method=method,
                    source="browser-response",
                    resource_type=resource_type,
                )

        except Exception:

            pass

    # ==========================================================
    # PERFORMANCE RESOURCE CAPTURE
    # ==========================================================

    def capture_performance_entries(
        self,
        page,
    ):
        """
        Capture resources discovered by the browser.

        Static resources such as JavaScript, CSS, images,
        fonts, and asset JSON files are stored as STATIC.

        XHR/fetch requests are stored as API candidates.
        """

        try:

            entries = page.evaluate(
                """
                () => performance
                    .getEntriesByType('resource')
                    .map(entry => ({
                        name: entry.name,
                        initiatorType: entry.initiatorType
                    }))
                """
            )

            for entry in entries:

                resource_url = entry.get(
                    "name"
                )

                initiator_type = (
                    entry.get(
                        "initiatorType"
                    )
                    or ""
                ).lower()

                if not resource_url:

                    continue

                if not self.is_same_domain(
                    resource_url
                ):

                    continue

                if initiator_type in (
                    "xmlhttprequest",
                    "fetch",
                ):

                    self.add_api_request(
                        resource_url,
                        method="GET",
                        source="performance",
                        resource_type=(
                            "xhr"
                            if initiator_type
                            == "xmlhttprequest"
                            else "fetch"
                        ),
                    )

                else:

                    self.add_endpoint(
                        resource_url,
                        method="GET",
                        source="performance",
                        resource_type=initiator_type,
                    )

        except Exception:

            pass

    # ==========================================================
    # BROWSER CRAWLER
    # ==========================================================

    def crawl_browser(self):
        """
        Crawl the application using Playwright
        with the locally installed Google Chrome.
        """

        print(
            "\n[+] Starting browser crawler..."
        )

        chrome_path = (
            r"C:\Program Files\Google\Chrome"
            r"\Application\chrome.exe"
        )

        try:

            with sync_playwright() as playwright:

                browser = (
                    playwright.chromium.launch(
                        headless=True,
                        executable_path=chrome_path,
                    )
                )

                context = (
                    browser.new_context(
                        ignore_https_errors=True,
                    )
                )

                page = context.new_page()

                # ==================================================
                # NETWORK EVENTS
                # ==================================================

                page.on(
                    "request",
                    self.handle_browser_request,
                )

                page.on(
                    "response",
                    self.handle_browser_response,
                )

                # ==================================================
                # NAVIGATION EVENTS
                # ==================================================

                def handle_navigation(
                    frame,
                ):

                    try:

                        url = frame.url

                        if (
                            url
                            and self.is_same_domain(
                                url
                            )
                        ):

                            self.add_url(
                                url,
                                source="browser",
                            )

                            print(
                                f"[Browser] {url}"
                            )

                    except Exception:

                        pass

                page.on(
                    "framenavigated",
                    handle_navigation,
                )

                # ==================================================
                # INITIAL PAGE
                # ==================================================

                print(
                    f"[Browser] "
                    f"{self.start_url}"
                )

                try:

                    page.goto(
                        self.start_url,
                        wait_until=(
                            "domcontentloaded"
                        ),
                        timeout=30000,
                    )

                except Exception as error:

                    print(
                        "[Browser navigation error] "
                        f"{error}"
                    )

                # ==================================================
                # WAIT FOR JAVASCRIPT
                # ==================================================

                try:

                    page.wait_for_timeout(
                        5000
                    )

                except Exception:

                    pass

                # ==================================================
                # PERFORMANCE RESOURCES
                # ==================================================

                self.capture_performance_entries(
                    page
                )

                # ==================================================
                # CURRENT PAGE HTML
                # ==================================================

                try:

                    current_url = (
                        self.normalize_url(
                            page.url
                        )
                    )

                    if self.is_same_domain(
                        current_url
                    ):

                        html = page.content()

                        self.extract_page_data(
                            html,
                            current_url,
                            source="browser-html",
                        )

                except Exception:

                    pass

                # ==================================================
                # RENDERED LINKS
                # ==================================================

                try:

                    links = (
                        page.locator(
                            "a"
                        ).all()
                    )

                    for link in links:

                        try:

                            href = (
                                link.get_attribute(
                                    "href"
                                )
                            )

                            if not href:

                                continue

                            absolute_url = (
                                urljoin(
                                    page.url,
                                    href,
                                )
                            )

                            if self.is_same_domain(
                                absolute_url
                            ):

                                self.add_url(
                                    absolute_url,
                                    source=(
                                        "browser-link"
                                    ),
                                )

                        except Exception:

                            continue

                except Exception:

                    pass

                # ==================================================
                # RENDERED FORMS
                # ==================================================

                try:

                    forms = (
                        page.locator(
                            "form"
                        ).all()
                    )

                    for form in forms:

                        try:

                            action = (
                                form.get_attribute(
                                    "action"
                                )
                            )

                            if action:

                                action = (
                                    urljoin(
                                        page.url,
                                        action,
                                    )
                                )

                            else:

                                action = page.url

                            if not self.is_same_domain(
                                action
                            ):

                                continue

                            method = (
                                form.get_attribute(
                                    "method"
                                )
                                or "GET"
                            ).upper()

                            inputs = []

                            fields = (
                                form.locator(
                                    "input, textarea, "
                                    "select, button"
                                ).all()
                            )

                            for field in fields:

                                try:

                                    name = (
                                        field.get_attribute(
                                            "name"
                                        )
                                        or ""
                                    )

                                    input_type = (
                                        field.get_attribute(
                                            "type"
                                        )
                                        or field.evaluate(
                                            """
                                            (el) =>
                                                el.tagName
                                                .toLowerCase()
                                            """
                                        )
                                    )

                                    if name:

                                        self.parameters.add(
                                            name
                                        )

                                    inputs.append(
                                        {
                                            "name": name,
                                            "type": input_type,
                                        }
                                    )

                                except Exception:

                                    continue

                            self.forms.append(
                                {
                                    "page": page.url,
                                    "action": action,
                                    "method": method,
                                    "inputs": inputs,
                                }
                            )

                            self.add_endpoint(
                                action,
                                method=method,
                                source="browser-form",
                                resource_type="form",
                            )

                        except Exception:

                            continue

                except Exception:

                    pass

                # ==================================================
                # FINAL PERFORMANCE CAPTURE
                # ==================================================

                self.capture_performance_entries(
                    page
                )

                # ==================================================
                # CLOSE BROWSER
                # ==================================================

                context.close()

                browser.close()

        except Exception as error:

            print(
                f"[Browser ERROR] {error}"
            )

    # ==========================================================
    # MAIN CRAWL
    # ==========================================================

    def crawl(self):
        """
        Run both HTTP and browser crawling.

        Returns:

            urls
            forms
            parameters
            api_requests
            endpoint_inventory
        """

        # ======================================================
        # HTTP CRAWLER
        # ======================================================

        self.crawl_http()

        # ======================================================
        # BROWSER CRAWLER
        # ======================================================

        self.crawl_browser()

        # ======================================================
        # SERIALIZE ENDPOINT INVENTORY
        # ======================================================

        endpoint_inventory = {}

        for (
            key,
            endpoint,
        ) in self.endpoint_inventory.items():

            endpoint_inventory[key] = {
                "method": endpoint[
                    "method"
                ],
                "url": endpoint[
                    "url"
                ],
                "path": endpoint[
                    "path"
                ],
                "parameters": sorted(
                    endpoint[
                        "parameters"
                    ]
                ),
                "type": endpoint[
                    "type"
                ],
                "sources": sorted(
                    endpoint[
                        "sources"
                    ]
                ),
                "resource_types": sorted(
                    endpoint[
                        "resource_types"
                    ]
                ),
                "observed_urls": sorted(
                    endpoint[
                        "observed_urls"
                    ]
                ),
            }

        # ======================================================
        # FINAL RESULT
        # ======================================================

        return {
            "urls": sorted(
                self.urls
            ),

            "forms": self.forms,

            "parameters": sorted(
                self.parameters
            ),

            "api_requests": sorted(
                self.api_requests
            ),

            "endpoint_inventory": (
                endpoint_inventory
            ),
        }