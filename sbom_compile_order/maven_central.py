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

    def _make_request(self, query: str, use_gav_core: bool = False) -> Optional[Dict]:
        """
        Make a request to Maven Central Search API.

        Uses the official REST API as documented at:
        https://central.sonatype.org/search/rest-api-guide/

        Args:
            query: Search query string (e.g., "g:groupId AND a:artifactId AND v:version")
            use_gav_core: If True, use core=gav parameter for version-specific searches

        Returns:
            JSON response as dictionary, or None if request fails
        """
        cache_key = f"{query}:{use_gav_core}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        self._rate_limit()

        try:
            # Build URL according to official API documentation
            # https://central.sonatype.org/search/rest-api-guide/
            url = f"{self.BASE_URL}?q={quote(query)}&rows=1&wt=json"
            if use_gav_core:
                url += "&core=gav"  # Use GAV core for version-specific searches
            request = Request(url)
            request.add_header("User-Agent", "sbom-compile-order/1.3.0")

            if self.verbose:
                print(
                    f"[DEBUG] Querying Maven Central API: {query}",
                    file=__import__("sys").stderr,
                )

            with urlopen(request, timeout=10) as response:
                data = json.loads(response.read().decode("utf-8"))
                self._cache[cache_key] = data
                return data
        except Exception as exc:  # pylint: disable=broad-exception-caught
            if self.verbose:
                print(
                    f"Warning: Failed to query Maven Central for {query}: {exc}",
                    file=__import__("sys").stderr,
                )
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

        # Build search query according to official API documentation:
        # https://central.sonatype.org/search/rest-api-guide/
        # Format: g:groupId AND a:artifactId AND v:version
        query = f"g:{component.group} AND a:{component.name}"
        use_gav_core = False
        if component.version:
            query += f" AND v:{component.version}"
            use_gav_core = True  # Use GAV core for version-specific searches

        response = self._make_request(query, use_gav_core=use_gav_core)
        if not response:
            return None, None

        try:
            docs = response.get("response", {}).get("docs", [])
            if not docs:
                return None, None

            doc = docs[0]

            # Extract homepage URL from response
            # According to API documentation, response may contain various fields
            homepage_url = None
            
            # Try to extract from available fields in the response
            # Common fields: id, g (groupId), a (artifactId), v (version), latestVersion, etc.
            if "id" in doc:
                # Construct Maven Central artifact page URL
                # Format: groupId:artifactId:version
                artifact_id = doc.get("id", "")
                if artifact_id:
                    parts = artifact_id.split(":")
                    if len(parts) >= 2:
                        # Construct mvnrepository.com URL as fallback homepage
                        homepage_url = (
                            f"https://mvnrepository.com/artifact/"
                            f"{parts[0]}/{parts[1]}"
                        )
                        if len(parts) >= 3:
                            homepage_url += f"/{parts[2]}"
            
            # Check for other URL fields that might contain homepage
            # The API response may include various metadata fields
            for field in ["ec", "url", "repository_url"]:
                if field in doc and doc[field]:
                    potential_url = doc[field]
                    if isinstance(potential_url, str) and potential_url.startswith("http"):
                        homepage_url = potential_url
                        break

            # Extract license information
            license_type = None
            # Note: Maven Central Search API typically doesn't include license info
            # License information is usually in the POM file, which requires
            # downloading from: https://search.maven.org/remotecontent?filepath=...
            # For now, return None and let dependency resolver (mvnrepository.com) handle it
            # as it provides better license extraction from HTML pages

            if self.verbose and (homepage_url or license_type):
                print(
                    f"[DEBUG] Maven Central API returned metadata for "
                    f"{component.group}:{component.name}:{component.version}",
                    file=__import__("sys").stderr,
                )

            return homepage_url, license_type
        except Exception as exc:  # pylint: disable=broad-exception-caught
            if self.verbose:
                print(
                    f"Warning: Failed to parse Maven Central response: {exc}",
                    file=__import__("sys").stderr,
                )
            return None, None
