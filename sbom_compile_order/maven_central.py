"""
Maven Central API client for fetching package metadata.

Provides functionality to query Maven Central Search API for package information
including homepage URLs and license information.
"""

import json
import time
from typing import Dict, Optional, Tuple
from urllib.parse import quote
from urllib.request import Request, urlopen

from sbom_compile_order.parser import Component


class MavenCentralClient:
    """
    Client for interacting with Maven Central Search API.

    Provides methods to fetch package metadata including homepage URLs and licenses.
    """

    BASE_URL = "https://search.maven.org/solrsearch/select"
    RATE_LIMIT_DELAY = 0.1  # Delay between requests in seconds

    def __init__(self, verbose: bool = False) -> None:
        """
        Initialize the Maven Central client.

        Args:
            verbose: Whether to print verbose output
        """
        self.verbose = verbose
        self._last_request_time = 0.0
        self._cache: Dict[str, Dict] = {}

    def _rate_limit(self) -> None:
        """
        Enforce rate limiting between requests.
        """
        current_time = time.time()
        time_since_last = current_time - self._last_request_time
        if time_since_last < self.RATE_LIMIT_DELAY:
            time.sleep(self.RATE_LIMIT_DELAY - time_since_last)
        self._last_request_time = time.time()

    def _make_request(self, query: str) -> Optional[Dict]:
        """
        Make a request to Maven Central Search API.

        Args:
            query: Search query string

        Returns:
            JSON response as dictionary, or None if request fails
        """
        if query in self._cache:
            return self._cache[query]

        self._rate_limit()

        try:
            url = f"{self.BASE_URL}?q={quote(query)}&rows=1&wt=json"
            request = Request(url)
            request.add_header("User-Agent", "sbom-compile-order/1.1.1")

            with urlopen(request, timeout=10) as response:
                data = json.loads(response.read().decode("utf-8"))
                self._cache[query] = data
                return data
        except Exception as exc:  # pylint: disable=broad-exception-caught
            if self.verbose:
                print(f"Warning: Failed to query Maven Central for {query}: {exc}", file=__import__("sys").stderr)
            return None

    def get_package_info(
        self, component: Component
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Get homepage URL and license information for a Maven package.

        Args:
            component: Component object with group, name, and version

        Returns:
            Tuple of (homepage_url, license_type), both may be None
        """
        if not component.group or not component.name:
            return None, None

        # Build search query: g:groupId AND a:artifactId AND v:version
        query = f"g:{component.group} AND a:{component.name}"
        if component.version:
            query += f" AND v:{component.version}"

        response = self._make_request(query)
        if not response:
            return None, None

        try:
            docs = response.get("response", {}).get("docs", [])
            if not docs:
                return None, None

            doc = docs[0]

            # Extract homepage URL
            homepage_url = None
            if "ec" in doc:  # ec = "ecosystem" or external links
                # Try to find homepage in various fields
                homepage_url = doc.get("ec", "")
            if not homepage_url and "id" in doc:
                # Construct Maven Central artifact page URL
                artifact_id = doc.get("id", "")
                if artifact_id:
                    parts = artifact_id.split(":")
                    if len(parts) >= 2:
                        group_id = parts[0].replace(".", "/")
                        artifact_id_part = parts[1]
                        homepage_url = (
                            f"https://mvnrepository.com/artifact/"
                            f"{parts[0]}/{artifact_id_part}"
                        )
                        if len(parts) >= 3:
                            homepage_url += f"/{parts[2]}"

            # Extract license information
            license_type = None
            # Maven Central doesn't always provide license in search API
            # We'll need to fetch from mvnrepository.com or POM file
            # For now, return None and let dependency resolver handle it

            return homepage_url, license_type
        except Exception as exc:  # pylint: disable=broad-exception-caught
            if self.verbose:
                print(
                    f"Warning: Failed to parse Maven Central response: {exc}",
                    file=__import__("sys").stderr,
                )
            return None, None
