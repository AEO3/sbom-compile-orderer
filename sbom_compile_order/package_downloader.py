"""
Package (JAR) file downloader with caching support.

Downloads JAR files from Maven Central and caches them locally.
"""

import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from sbom_compile_order.parser import Component, build_maven_central_url_from_purl


class PackageDownloader:
    """Downloads and caches JAR files from Maven Central."""

    def __init__(self, cache_dir: Path, verbose: bool = False) -> None:
        """
        Initialize the package downloader.

        Args:
            cache_dir: Directory to cache downloaded JAR files
            verbose: Enable verbose output
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.verbose = verbose
        self.jar_cache_dir = self.cache_dir / "jars"
        self.jar_cache_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.cache_dir / "sbom-compile-order.log"

    def _log(self, message: str) -> None:
        """
        Log a message to both stderr (if verbose) and log file.

        Args:
            message: Message to log
        """
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        log_entry = f"{timestamp} {message}"
        if self.verbose:
            print(log_entry, file=sys.stderr)
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(f"{log_entry}\n")

    def _get_maven_central_jar_url(self, component: Component) -> str:
        """
        Construct the Maven Central direct JAR download URL from component PURL.

        Args:
            component: Component object with PURL or coordinates

        Returns:
            URL string for downloading the JAR from Maven Central
        """
        if component.purl:
            return build_maven_central_url_from_purl(component.purl, file_type="jar")
        elif component.group and component.name and component.version:
            # Fallback: build URL from coordinates if PURL not available
            from sbom_compile_order.parser import build_maven_central_url
            return build_maven_central_url(component.group, component.name, component.version, "jar")
        return ""

    def download_package(self, component: Component) -> Tuple[Optional[str], bool]:
        """
        Download JAR file for a component from Maven Central.

        Args:
            component: Component to download JAR for

        Returns:
            Tuple of (filename of cached JAR file or None if not found, auth_required bool)
        """
        if not component.group or not component.name or not component.version:
            return None, False

        # Create a cache key based on component identifier
        # Clean up the identifier by removing query parameters and URL fragments
        identifier = component.get_identifier()
        # Remove query parameters (everything after ?)
        if "?" in identifier:
            identifier = identifier.split("?")[0]
        # Remove URL fragments (everything after #)
        if "#" in identifier:
            identifier = identifier.split("#")[0]
        # Replace problematic characters for filename
        cache_key = identifier.replace("/", "_").replace(":", "_").replace("@", "_")
        cached_jar = self.jar_cache_dir / f"{cache_key}.jar"

        # Check if already cached
        if cached_jar.exists():
            self._log(f"Using cached JAR for {component.name}")
            return cached_jar.name, False

        # Download from Maven Central
        jar_url = self._get_maven_central_jar_url(component)
        if not jar_url:
            self._log(f"Failed to build JAR URL for {component.name}")
            return None, False
        self._log(f"[URL USING TO DOWNLOAD] {jar_url}")
        self._log(f"Downloading JAR from Maven Central: {jar_url}")

        try:
            req = Request(jar_url)
            req.add_header("User-Agent", "sbom-compile-order/1.4.1")
            with urlopen(req, timeout=30) as response:
                if response.status == 200:
                    jar_content = response.read()
                    # Verify it's a valid JAR (starts with ZIP magic bytes)
                    if len(jar_content) > 4 and jar_content[:4] == b"PK\x03\x04":
                        with open(cached_jar, "wb") as f:
                            f.write(jar_content)
                        self._log(f"Cached JAR from Maven Central: {cached_jar.name}")
                        return cached_jar.name, False
                    else:
                        self._log(
                            f"Downloaded file is not a valid JAR for "
                            f"{component.group}:{component.name}:{component.version}"
                        )
        except HTTPError as exc:
            if exc.code in [401, 403]:
                return None, True  # Auth required
            if exc.code == 404:
                # Try fallback URL: https://mvnrepository.com/repos/central
                self._log(
                    f"Maven Central JAR not found (HTTP 404), trying fallback repository: "
                    f"{component.group}:{component.name}:{component.version}"
                )
                fallback_jar_url = self._get_fallback_jar_url(component)
                if fallback_jar_url:
                    self._log(f"[URL USING TO DOWNLOAD] {fallback_jar_url}")
                    try:
                        fallback_req = Request(fallback_jar_url)
                        fallback_req.add_header("User-Agent", "sbom-compile-order/1.4.1")
                        with urlopen(fallback_req, timeout=30) as fallback_response:
                            if fallback_response.status == 200:
                                jar_content = fallback_response.read()
                                if len(jar_content) > 4 and jar_content[:4] == b"PK\x03\x04":
                                    with open(cached_jar, "wb") as f:
                                        f.write(jar_content)
                                    self._log(
                                        f"Cached JAR from fallback repository (mvnrepository.com/repos/central): "
                                        f"{cached_jar.name}"
                                    )
                                    return cached_jar.name, False
                    except HTTPError as fallback_exc:
                        if fallback_exc.code in [401, 403]:
                            return None, True  # Auth required
                        self._log(
                            f"Fallback repository also failed (HTTP {fallback_exc.code}): "
                            f"{component.group}:{component.name}:{component.version}"
                        )
                    except Exception as fallback_exc:  # pylint: disable=broad-exception-caught
                        self._log(
                            f"Fallback repository download failed: {fallback_exc} "
                            f"for {component.group}:{component.name}:{component.version}"
                        )
            if self.verbose:
                self._log(
                    f"Maven Central JAR download failed (HTTP {exc.code}): "
                    f"{component.group}:{component.name}:{component.version}"
                )
        except (URLError, Exception) as exc:  # pylint: disable=broad-exception-caught
            if self.verbose:
                self._log(
                    f"Maven Central JAR download failed: {exc} "
                    f"for {component.group}:{component.name}:{component.version}"
                )
        return None, False

    def _get_fallback_jar_url(self, component: Component) -> str:
        """
        Construct the fallback Maven Central JAR URL using mvnrepository.com/repos/central.

        Args:
            component: Component object with PURL or coordinates

        Returns:
            URL string for downloading the JAR from fallback repository
        """
        if component.group and component.name and component.version:
            from sbom_compile_order.parser import build_maven_central_url
            fallback_base_url = "https://mvnrepository.com/repos/central"
            return build_maven_central_url(
                component.group, component.name, component.version, "jar", base_url=fallback_base_url
            )
        return ""
