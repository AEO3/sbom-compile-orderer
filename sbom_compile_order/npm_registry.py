"""
Simple npm registry client for fetching package metadata.

Used to provide homepage and license information for npm packages.
"""

import json
import time
from typing import Dict, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from sbom_compile_order.parser import Component


class NpmRegistryClient:
    """Client for retrieving npm package metadata from the public registry."""

    BASE_URL = "https://registry.npmjs.org"
    RATE_LIMIT_DELAY = 0.1  # seconds between requests

    def __init__(self, verbose: bool = False) -> None:
        """
        Args:
            verbose: If True, prints request activity to stderr.
        """
        self.verbose = verbose
        self._last_request_time = 0.0
        self._cache: Dict[str, Dict] = {}

    def _rate_limit(self) -> None:
        """Sleep briefly to respect rate limits."""
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < self.RATE_LIMIT_DELAY:
            time.sleep(self.RATE_LIMIT_DELAY - elapsed)
        self._last_request_time = time.time()

    def _log(self, message: str) -> None:
        if self.verbose:
            print(message, file=__import__("sys").stderr)

    def _build_url(self, package_name: str) -> str:
        encoded = quote(package_name, safe="")
        return f"{self.BASE_URL}/{encoded}"

    def _fetch_package_data(self, package_name: str) -> Optional[Dict]:
        if package_name in self._cache:
            return self._cache[package_name]

        self._rate_limit()
        url = self._build_url(package_name)
        request = Request(url)
        request.add_header("User-Agent", "sbom-compile-order/1.8.9")

        try:
            with urlopen(request, timeout=15) as response:
                payload = json.loads(response.read().decode("utf-8"))
                self._cache[package_name] = payload
                return payload
        except (HTTPError, URLError, json.JSONDecodeError) as exc:
            self._log(f"[npm] Failed to fetch metadata for {package_name}: {exc}")
            return None

    def _extract_version_data(self, metadata: Dict, version: Optional[str]) -> Optional[Dict]:
        if version and version in metadata.get("versions", {}):
            return metadata["versions"][version]

        dist_tags = metadata.get("dist-tags", {})
        latest_version = dist_tags.get("latest")
        if latest_version and latest_version in metadata.get("versions", {}):
            return metadata["versions"][latest_version]

        return None

    def _normalize_repo_url(self, url: str) -> str:
        if not url:
            return ""
        url = url.strip()
        if url.startswith("git+"):
            url = url[4:]
        if url.endswith(".git"):
            url = url[: -4]
        return url

    def _extract_license(self, license_value: Optional[object]) -> Optional[str]:
        if isinstance(license_value, str):
            return license_value.strip()
        if isinstance(license_value, dict):
            return (
                license_value.get("type")
                or license_value.get("name")
                or license_value.get("license")
            )
        return None

    def get_package_info(self, component: Component) -> Tuple[Optional[str], Optional[str]]:
        """
        Returns homepage and license information for an npm package if available.

        Args:
            component: Component with `name` and `version` fields.

        Returns:
            Tuple of (homepage_url, license_type).
        """
        package_name = component.name or ""
        if not package_name:
            return None, None

        metadata = self._fetch_package_data(package_name)
        if not metadata:
            return None, None

        version_data = self._extract_version_data(metadata, component.version)
        if not version_data:
            return None, None

        homepage = version_data.get("homepage") or metadata.get("homepage")
        if not homepage:
            repo_info = version_data.get("repository") or metadata.get("repository")
            if isinstance(repo_info, dict):
                homepage = repo_info.get("url")
            elif isinstance(repo_info, str):
                homepage = repo_info

        homepage = self._normalize_repo_url(homepage or "")
        license_type = self._extract_license(version_data.get("license"))
        return (homepage or None, license_type)
"""
Simple npm registry client for fetching package metadata.

Used to provide homepage and license information for npm packages.
"""

import json
import time
from typing import Dict, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from sbom_compile_order.parser import Component


class NpmRegistryClient:
    """Client for retrieving npm package metadata from the public registry."""

    BASE_URL = "https://registry.npmjs.org"
    RATE_LIMIT_DELAY = 0.1  # seconds between requests

    def __init__(self, verbose: bool = False) -> None:
        """
        Args:
            verbose: If True, prints request activity to stderr.
        """
        self.verbose = verbose
        self._last_request_time = 0.0
        self._cache: Dict[str, Dict] = {}

    def _rate_limit(self) -> None:
        """Sleep briefly to respect rate limits."""
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < self.RATE_LIMIT_DELAY:
            time.sleep(self.RATE_LIMIT_DELAY - elapsed)
        self._last_request_time = time.time()

    def _log(self, message: str) -> None:
        if self.verbose:
            print(message, file=__import__("sys").stderr)

    def _build_url(self, package_name: str) -> str:
        encoded = quote(package_name, safe="")
        return f"{self.BASE_URL}/{encoded}"

    def _fetch_package_data(self, package_name: str) -> Optional[Dict]:
        if package_name in self._cache:
            return self._cache[package_name]

        self._rate_limit()
        url = self._build_url(package_name)
        request = Request(url)
        request.add_header("User-Agent", "sbom-compile-order/1.8.9")

        try:
            with urlopen(request, timeout=15) as response:
                payload = json.loads(response.read().decode("utf-8"))
                self._cache[package_name] = payload
                return payload
        except (HTTPError, URLError, json.JSONDecodeError) as exc:
            self._log(f"[npm] Failed to fetch metadata for {package_name}: {exc}")
            return None

    def _extract_version_data(self, metadata: Dict, version: Optional[str]) -> Optional[Dict]:
        if version and version in metadata.get("versions", {}):
            return metadata["versions"][version]

        dist_tags = metadata.get("dist-tags", {})
        latest_version = dist_tags.get("latest")
        if latest_version and latest_version in metadata.get("versions", {}):
            return metadata["versions"][latest_version]

        return None

    def _normalize_repo_url(self, url: str) -> str:
        if not url:
            return ""
        url = url.strip()
        if url.startswith("git+"):
            url = url[4:]
        if url.endswith(".git"):
            url = url[: -4]
        return url

    def _extract_license(self, license_value: Optional[object]) -> Optional[str]:
        if isinstance(license_value, str):
            return license_value.strip()
        if isinstance(license_value, dict):
            return (
                license_value.get("type")
                or license_value.get("name")
                or license_value.get("license")
            )
        return None

    def get_package_info(self, component: Component) -> Tuple[Optional[str], Optional[str]]:
        """
        Returns homepage and license information for an npm package if available.

        Args:
            component: Component with `name` and `version` fields.

        Returns:
            Tuple of (homepage_url, license_type).
        """
        package_name = component.name or ""
        if not package_name:
            return None, None

        metadata = self._fetch_package_data(package_name)
        if not metadata:
            return None, None

        version_data = self._extract_version_data(metadata, component.version)
        if not version_data:
            return None, None

        homepage = version_data.get("homepage") or metadata.get("homepage")
        if not homepage:
            repo_info = version_data.get("repository") or metadata.get("repository")
            if isinstance(repo_info, dict):
                homepage = repo_info.get("url")
            elif isinstance(repo_info, str):
                homepage = repo_info

        homepage = self._normalize_repo_url(homepage or "")
        license_type = self._extract_license(version_data.get("license"))
        return (homepage or None, license_type)
