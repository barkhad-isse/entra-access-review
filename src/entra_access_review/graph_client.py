"""Minimal read-only Microsoft Graph client.

Authenticates with the OAuth 2.0 client credentials flow (app registration
with a client secret) and handles paging and throttling (HTTP 429).
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from typing import Any

import msal
import requests

GRAPH = "https://graph.microsoft.com/v1.0"
SCOPE = ["https://graph.microsoft.com/.default"]


class GraphError(RuntimeError):
    pass


class GraphClient:
    def __init__(self, tenant_id: str, client_id: str, client_secret: str, timeout: int = 30):
        self._app = msal.ConfidentialClientApplication(
            client_id,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
            client_credential=client_secret,
        )
        self._session = requests.Session()
        self._timeout = timeout

    def _token(self) -> str:
        result = self._app.acquire_token_for_client(scopes=SCOPE)
        if "access_token" not in result:
            raise GraphError(f"Authentication failed: {result.get('error_description', result)}")
        return result["access_token"]

    def _get(self, url: str, params: dict[str, str] | None = None, retries: int = 5) -> dict[str, Any]:
        for attempt in range(retries):
            resp = self._session.get(
                url,
                params=params,
                headers={"Authorization": f"Bearer {self._token()}", "ConsistencyLevel": "eventual"},
                timeout=self._timeout,
            )
            if resp.status_code == 429 or resp.status_code >= 500:
                wait = int(resp.headers.get("Retry-After", 2 ** attempt))
                time.sleep(wait)
                continue
            if resp.status_code == 403:
                raise GraphError(
                    f"403 Forbidden for {url}. Check that the app has the required "
                    "application permissions and that admin consent is granted."
                )
            if not resp.ok:
                raise GraphError(f"{resp.status_code} for {url}: {resp.text[:300]}")
            return resp.json()
        raise GraphError(f"Gave up after {retries} retries: {url}")

    def get_all(self, path: str, params: dict[str, str] | None = None) -> Iterator[dict[str, Any]]:
        """Yield every item from a collection, following @odata.nextLink."""
        url: str | None = f"{GRAPH}{path}"
        while url:
            page = self._get(url, params)
            yield from page.get("value", [])
            url = page.get("@odata.nextLink")
            params = None  # nextLink already contains the query
