import httpx


class HTTPClient:
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    def get(self, url: str) -> httpx.Response:
        response = httpx.get(
            url,
            timeout=self.timeout,
            follow_redirects=True,
        )

        return response