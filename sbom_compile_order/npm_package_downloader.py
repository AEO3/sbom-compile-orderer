"""
npm package downloader with caching support.

Downloads npm package tarballs from the npm registry and caches them locally.
"""

import io
import os
import sys
import tarfile
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from sbom_compile_order.npm_registry import NpmRegistryClient
from sbom_compile_order.parser import Component


class NpmPackageDownloader:
    """Downloads and caches npm package tarballs from the npm registry."""

    def __init__(self, cache_dir: Path, verbose: bool = False) -> None:
        """
        Initialize the npm package downloader.

        Args:
            cache_dir: Directory to cache downloaded npm packages
            verbose: Enable verbose output
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.verbose = verbose
        self.npm_cache_dir = self.cache_dir / "npm"
        self.npm_cache_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.cache_dir / "sbom-compile-order.log"
        self.npm_client = NpmRegistryClient(verbose=verbose)

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
        log_path = self._ensure_log_file()
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"{log_entry}\n")

    def _ensure_log_file(self) -> Path:
        """
        Ensure the downloader has a log file path and that the file exists.

        Returns:
            Path to the log file.
        """
        if not hasattr(self, "log_file") or not self.log_file:
            self.log_file = self.cache_dir / "sbom-compile-order.log"
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.log_file.exists():
            self.log_file.touch()
        return self.log_file

    def _get_tarball_url(self, component: Component) -> Optional[str]:
        """
        Get the tarball URL for an npm package from the registry.

        Args:
            component: Component to get tarball URL for

        Returns:
            Tarball URL string, or None if not available
        """
        if not component.name or not component.version:
            return None

        package_data = self.npm_client.get_comprehensive_package_data(component)
        if not package_data:
            return None

        dist = package_data.get("dist")
        if isinstance(dist, dict):
            return dist.get("tarball")

        return None

    def _validate_tarball(self, tarball_content: bytes) -> Tuple[bool, Optional[str]]:
        """
        Validate that downloaded content is a valid tarball.

        Args:
            tarball_content: Tarball file content as bytes

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not tarball_content:
            return False, "Tarball content is empty"

        if len(tarball_content) < 100:
            return False, f"Tarball content too small ({len(tarball_content)} bytes)"

        # Check for gzip magic bytes (npm tarballs are gzipped)
        if tarball_content[:2] != b"\x1f\x8b":
            return False, f"Invalid gzip magic bytes: {tarball_content[:2]}"

        # Try to open as tarfile to validate structure
        try:
            with tarfile.open(fileobj=io.BytesIO(tarball_content), mode="r:gz") as tar:
                # Test that we can read the file list (validates tar structure)
                tar.getnames()
                return True, None
        except tarfile.TarError as exc:
            return False, f"Invalid tarball structure: {exc}"
        except Exception as exc:  # pylint: disable=broad-exception-caught
            return False, f"Error validating tarball: {exc}"

    def download_package(self, component: Component) -> Tuple[Optional[str], bool]:
        """
        Download npm package tarball for a component from the npm registry.

        Args:
            component: Component to download package for

        Returns:
            Tuple of (filename of cached tarball file or None if not found, auth_required bool)
        """
        if not component.name or not component.version:
            return None, False

        # Create a cache key based on component identifier
        identifier = component.get_identifier()
        # Remove query parameters (everything after ?)
        if "?" in identifier:
            identifier = identifier.split("?")[0]
        # Remove URL fragments (everything after #)
        if "#" in identifier:
            identifier = identifier.split("#")[0]
        # Replace problematic characters for filename
        cache_key = identifier.replace("/", "_").replace(":", "_").replace("@", "_")
        cached_tarball = self.npm_cache_dir / f"{cache_key}.tgz"

        # Check if already cached
        if cached_tarball.exists():
            self._log(f"Using cached npm package for {component.name}")
            return cached_tarball.name, False

        # Get tarball URL from npm registry
        tarball_url = self._get_tarball_url(component)
        if not tarball_url:
            self._log(f"Failed to get tarball URL for {component.name}@{component.version}")
            return None, False

        self._log(f"Downloading npm package from: {tarball_url}")

        try:
            req = Request(tarball_url)
            req.add_header("User-Agent", "sbom-compile-order/1.8.10")

            with urlopen(req, timeout=60) as response:
                if response.getcode() == 200:
                    tarball_content = response.read()
                    tarball_size = len(tarball_content)

                    # Check if content is empty
                    if tarball_size == 0:
                        self._log(
                            f"[NPM DOWNLOAD] ERROR: Downloaded empty file from npm registry: "
                            f"{component.name}@{component.version}"
                        )
                        return None, False

                    # Validate tarball using tarfile module
                    is_valid, validation_error = self._validate_tarball(tarball_content)
                    if is_valid:
                        # Ensure parent directory exists
                        cached_tarball.parent.mkdir(parents=True, exist_ok=True)

                        try:
                            self._log(f"[NPM SAVE] Writing file to: {cached_tarball}")
                            with open(cached_tarball, "wb") as f:
                                bytes_written = f.write(tarball_content)
                                f.flush()
                                os.fsync(f.fileno())
                            self._log(f"[NPM SAVE] Wrote {bytes_written} bytes to {cached_tarball}")

                            # Verify file was written
                            if cached_tarball.exists():
                                file_size = cached_tarball.stat().st_size
                                if file_size == tarball_size:
                                    self._log(
                                        f"[NPM SAVE] SUCCESS: File verified on disk: {cached_tarball} ({file_size} bytes)"
                                    )
                                    self._log(
                                        f"Cached npm package from registry: {cached_tarball.name} "
                                        f"({component.name}@{component.version})"
                                    )
                                    return cached_tarball.name, False
                                else:
                                    self._log(
                                        f"[NPM SAVE] ERROR: File size mismatch - expected {tarball_size} bytes, "
                                        f"got {file_size} bytes: {cached_tarball}"
                                    )
                            else:
                                self._log(
                                    f"[NPM SAVE] ERROR: File was not written to disk: {cached_tarball}"
                                )
                        except Exception as write_exc:  # pylint: disable=broad-exception-caught
                            self._log(
                                f"[NPM SAVE] ERROR: Failed to write file: {write_exc} "
                                f"for {component.name}@{component.version}"
                            )
                            return None, False
                    else:
                        self._log(
                            f"[NPM DOWNLOAD] ERROR: Downloaded file is not a valid tarball: {validation_error} "
                            f"for {component.name}@{component.version} "
                            f"(size: {tarball_size} bytes)"
                        )
        except HTTPError as exc:
            if exc.code in [401, 403]:
                return None, True  # Auth required
            self._log(
                f"npm registry download failed (HTTP {exc.code}): "
                f"{component.name}@{component.version}"
            )
        except (URLError, Exception) as exc:  # pylint: disable=broad-exception-caught
            if self.verbose:
                self._log(
                    f"npm registry download failed: {exc} "
                    f"for {component.name}@{component.version}"
                )
        return None, False
