"""
npm registry client for fetching comprehensive package metadata.

Used to provide homepage, license, dependencies, and other metadata for npm packages.
"""

import json
import time
from typing import Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from sbom_compile_order import __version__
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
        """Log a message if verbose mode is enabled."""
        if self.verbose:
            print(message, file=__import__("sys").stderr)

    def _build_url(self, package_name: str) -> str:
        """Build the npm registry URL for a package."""
        encoded = quote(package_name, safe="")
        return f"{self.BASE_URL}/{encoded}"

    def _fetch_package_data(self, package_name: str) -> Optional[Dict]:
        """
        Fetch full package metadata from npm registry.

        Args:
            package_name: Name of the npm package

        Returns:
            Full package metadata dictionary, or None if fetch fails
        """
        if package_name in self._cache:
            return self._cache[package_name]

        self._rate_limit()
        url = self._build_url(package_name)
        request = Request(url)
        request.add_header("User-Agent", f"sbom-compile-order/{__version__}")

        try:
            with urlopen(request, timeout=15) as response:
                payload = json.loads(response.read().decode("utf-8"))
                self._cache[package_name] = payload
                return payload
        except (HTTPError, URLError, json.JSONDecodeError) as exc:
            self._log(f"[npm] Failed to fetch metadata for {package_name}: {exc}")
            return None

    def _extract_version_data(self, metadata: Dict, version: Optional[str]) -> Optional[Dict]:
        """
        Extract version-specific data from package metadata.

        Args:
            metadata: Full package metadata
            version: Specific version to extract, or None for latest

        Returns:
            Version-specific data dictionary, or None if not found
        """
        if version and version in metadata.get("versions", {}):
            return metadata["versions"][version]

        dist_tags = metadata.get("dist-tags", {})
        latest_version = dist_tags.get("latest")
        if latest_version and latest_version in metadata.get("versions", {}):
            return metadata["versions"][latest_version]

        return None

    def _normalize_repo_url(self, url: str) -> str:
        """Normalize repository URL by removing git+ prefix and .git suffix."""
        if not url:
            return ""
        url = url.strip()
        if url.startswith("git+"):
            url = url[4:]
        if url.endswith(".git"):
            url = url[: -4]
        return url

    def _extract_license(self, license_value: Optional[object]) -> Optional[str]:
        """Extract license string from various license formats."""
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

    def get_comprehensive_package_data(self, component: Component) -> Optional[Dict]:
        """
        Get comprehensive package data from npm registry including dependencies, author, etc.

        This method extracts all available metadata from the npm registry API,
        similar to what would be in a package.json file.

        Args:
            component: Component with `name` and `version` fields.

        Returns:
            Dictionary containing comprehensive package data, or None if not available.
            Keys include:
            - homepage: Homepage URL
            - license: License information
            - repository: Repository URL
            - author: Author information
            - description: Package description
            - dependencies: Runtime dependencies (dict of name -> version)
            - devDependencies: Development dependencies (dict of name -> version)
            - peerDependencies: Peer dependencies (dict of name -> version)
            - optionalDependencies: Optional dependencies (dict of name -> version)
            - keywords: Package keywords
            - bugs: Bug tracker URL
            - dist: Distribution information (tarball URL, shasum, etc.)
        """
        package_name = component.name or ""
        if not package_name:
            return None

        metadata = self._fetch_package_data(package_name)
        if not metadata:
            return None

        version_data = self._extract_version_data(metadata, component.version)
        if not version_data:
            return None

        # Extract comprehensive data
        result: Dict[str, any] = {}

        # Homepage
        homepage = version_data.get("homepage") or metadata.get("homepage")
        if not homepage:
            repo_info = version_data.get("repository") or metadata.get("repository")
            if isinstance(repo_info, dict):
                homepage = repo_info.get("url")
            elif isinstance(repo_info, str):
                homepage = repo_info
        result["homepage"] = self._normalize_repo_url(homepage or "") if homepage else None

        # License
        result["license"] = self._extract_license(version_data.get("license"))

        # Repository
        repo_info = version_data.get("repository") or metadata.get("repository")
        if isinstance(repo_info, dict):
            result["repository"] = repo_info.get("url")
        elif isinstance(repo_info, str):
            result["repository"] = repo_info
        else:
            result["repository"] = None

        # Author
        author = version_data.get("author") or metadata.get("author")
        if isinstance(author, dict):
            result["author"] = author.get("name", "")
            if author.get("email"):
                result["author_email"] = author.get("email")
            if author.get("url"):
                result["author_url"] = author.get("url")
        elif isinstance(author, str):
            result["author"] = author
        else:
            result["author"] = None

        # Description
        result["description"] = version_data.get("description") or metadata.get("description")

        # Dependencies
        result["dependencies"] = version_data.get("dependencies") or {}
        result["devDependencies"] = version_data.get("devDependencies") or {}
        result["peerDependencies"] = version_data.get("peerDependencies") or {}
        result["optionalDependencies"] = version_data.get("optionalDependencies") or {}

        # Keywords
        result["keywords"] = version_data.get("keywords") or metadata.get("keywords") or []

        # Bugs
        bugs = version_data.get("bugs") or metadata.get("bugs")
        if isinstance(bugs, dict):
            result["bugs"] = bugs.get("url")
        elif isinstance(bugs, str):
            result["bugs"] = bugs
        else:
            result["bugs"] = None

        # Distribution information
        dist = version_data.get("dist")
        if isinstance(dist, dict):
            result["dist"] = {
                "tarball": dist.get("tarball"),
                "shasum": dist.get("shasum"),
                "integrity": dist.get("integrity"),
            }
        else:
            result["dist"] = None

        # Version and name
        result["version"] = version_data.get("version")
        result["name"] = version_data.get("name") or package_name

        return result

    def get_dependencies(self, component: Component) -> List[Tuple[str, str]]:
        """
        Get all dependencies for an npm package.

        Args:
            component: Component with `name` and `version` fields.

        Returns:
            List of tuples (package_name, version_spec) for all dependencies.
            Includes runtime, peer, and optional dependencies (but not devDependencies).
        """
        package_data = self.get_comprehensive_package_data(component)
        if not package_data:
            return []

        dependencies: List[Tuple[str, str]] = []

        # Add runtime dependencies
        deps = package_data.get("dependencies", {})
        for dep_name, dep_version in deps.items():
            dependencies.append((dep_name, dep_version))

        # Add peer dependencies
        peer_deps = package_data.get("peerDependencies", {})
        for dep_name, dep_version in peer_deps.items():
            dependencies.append((dep_name, dep_version))

        # Add optional dependencies
        optional_deps = package_data.get("optionalDependencies", {})
        for dep_name, dep_version in optional_deps.items():
            dependencies.append((dep_name, dep_version))

        return dependencies
