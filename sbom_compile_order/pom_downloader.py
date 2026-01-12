"""
POM file downloader with caching support.

Downloads POM files from git repositories and caches them locally.
Handles mono-repos by finding package-specific POM files.
"""

import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from sbom_compile_order.parser import Component


class POMDownloader:
    """Downloads and caches POM files from git repositories."""

    def __init__(self, cache_dir: Path, verbose: bool = False) -> None:
        """
        Initialize the POM downloader.

        Args:
            cache_dir: Directory to cache downloaded POM files
            verbose: Enable verbose output
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.verbose = verbose
        self.repo_cache_dir = self.cache_dir / "repos"
        self.repo_cache_dir.mkdir(parents=True, exist_ok=True)
        self.pom_cache_dir = self.cache_dir / "poms"
        self.pom_cache_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.cache_dir / "sbom-compile-order.log"

    def _log(self, message: str) -> None:
        """
        Log a message to both stderr (if verbose) and log file.

        Args:
            message: Message to log
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] {message}"

        # Write to log file
        try:
            with open(self.log_file, "a", encoding="utf-8") as log:
                log.write(log_message + "\n")
        except Exception:  # pylint: disable=broad-exception-caught
            pass  # Silently fail if log file can't be written

        # Also print to stderr if verbose
        if self.verbose:
            print(message, file=sys.stderr)

    def _get_repo_name_from_url(self, repo_url: str) -> str:
        """
        Extract a safe repository name from a URL.

        Args:
            repo_url: Git repository URL

        Returns:
            Safe directory name for the repository
        """
        # Remove protocol and .git suffix
        repo_name = repo_url.replace("https://", "").replace("http://", "").replace("git://", "")
        repo_name = repo_name.rstrip("/").rstrip(".git")

        # Replace invalid characters with underscores
        repo_name = re.sub(r"[^a-zA-Z0-9._-]", "_", repo_name)
        return repo_name

    def _clone_or_update_repo(self, repo_url: str) -> Optional[Path]:
        """
        Clone or update a git repository.

        Args:
            repo_url: Git repository URL

        Returns:
            Path to cloned repository, or None if failed
        """
        repo_name = self._get_repo_name_from_url(repo_url)
        repo_path = self.repo_cache_dir / repo_name

        try:
            if repo_path.exists():
                # Repository exists, try to update it
                self._log(f"Updating repository: {repo_url}")
                result = subprocess.run(
                    ["git", "pull"],
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                if result.returncode != 0:
                    self._log(f"Warning: Failed to update {repo_url}, using cached version")
            else:
                # Clone the repository
                self._log(f"Cloning repository: {repo_url}")
                result = subprocess.run(
                    ["git", "clone", "--depth", "1", repo_url, str(repo_path)],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                if result.returncode != 0:
                    self._log(f"Error cloning {repo_url}: {result.stderr}")
                    return None

            return repo_path
        except subprocess.TimeoutExpired:
            self._log(f"Timeout cloning/updating {repo_url}")
            return None
        except FileNotFoundError:
            self._log("Error: git command not found. Please install git.")
            return None
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._log(f"Error accessing repository {repo_url}: {exc}")
            return None

    def _find_pom_in_repo(
        self, repo_path: Path, package_name: str, group_id: Optional[str] = None
    ) -> Optional[Path]:
        """
        Find POM file in repository, handling mono-repos.

        Args:
            repo_path: Path to cloned repository
            package_name: Name of the package
            group_id: Optional group ID to help locate the POM

        Returns:
            Path to POM file if found, None otherwise
        """
        # First, try root pom.xml
        root_pom = repo_path / "pom.xml"
        if root_pom.exists():
            # Check if this is a mono-repo by looking for modules or subdirectories
            # If group_id matches, this might be the right POM
            # For now, check if there are subdirectories that match package name
            if self._is_mono_repo(repo_path):
                # Look for package-specific POM
                pom_path = self._find_package_pom(repo_path, package_name, group_id)
                if pom_path:
                    return pom_path
            # If not mono-repo or package-specific not found, return root POM
            return root_pom

        # Try to find POM in subdirectories matching package name
        return self._find_package_pom(repo_path, package_name, group_id)

    def _is_mono_repo(self, repo_path: Path) -> bool:
        """
        Check if repository is a mono-repo.

        Args:
            repo_path: Path to repository

        Returns:
            True if appears to be a mono-repo
        """
        root_pom = repo_path / "pom.xml"
        if not root_pom.exists():
            return False

        # Check if root POM has modules
        try:
            with open(root_pom, "r", encoding="utf-8") as file:
                content = file.read()
                # Look for <modules> tag
                if "<modules>" in content or "<module>" in content:
                    return True
        except Exception:  # pylint: disable=broad-exception-caught
            pass

        # Check for common mono-repo structures
        # Look for multiple directories that might contain POM files
        pom_count = len(list(repo_path.rglob("pom.xml")))
        return pom_count > 1

    def _find_package_pom(
        self, repo_path: Path, package_name: str, group_id: Optional[str] = None
    ) -> Optional[Path]:
        """
        Find package-specific POM in mono-repo.

        Args:
            repo_path: Path to repository root
            package_name: Name of the package
            group_id: Optional group ID (group:name format)

        Returns:
            Path to POM file if found, None otherwise
        """
        # Try exact package name match first
        for pom_file in repo_path.rglob("pom.xml"):
            try:
                # Check if parent directory matches package name
                parent_dir = pom_file.parent.name
                if parent_dir.lower() == package_name.lower():
                    # Verify it's a valid POM by checking for artifactId
                    if self._pom_matches_package(pom_file, package_name, group_id):
                        return pom_file
            except Exception:  # pylint: disable=broad-exception-caught
                continue

        # Try to find by artifactId in POM files
        for pom_file in repo_path.rglob("pom.xml"):
            if self._pom_matches_package(pom_file, package_name, group_id):
                return pom_file

        return None

    def _pom_matches_package(
        self, pom_path: Path, package_name: str, group_id: Optional[str] = None
    ) -> bool:
        """
        Check if a POM file matches the package.

        Args:
            pom_path: Path to POM file
            package_name: Expected package name
            group_id: Optional group ID (group:name format)

        Returns:
            True if POM matches the package
        """
        try:
            with open(pom_path, "r", encoding="utf-8") as file:
                content = file.read()

            # Extract artifactId from POM
            artifact_match = re.search(r"<artifactId>([^<]+)</artifactId>", content)
            if artifact_match:
                artifact_id = artifact_match.group(1).strip()
                if artifact_id.lower() == package_name.lower():
                    # If group_id provided, also check groupId
                    if group_id:
                        group_match = re.search(r"<groupId>([^<]+)</groupId>", content)
                        if group_match:
                            pom_group = group_match.group(1).strip()
                            # Extract group from group_id (format: group:name)
                            expected_group = group_id.split(":")[0] if ":" in group_id else group_id
                            if pom_group.lower() != expected_group.lower():
                                return False
                    return True
        except Exception:  # pylint: disable=broad-exception-caught
            pass

        return False

    def download_pom(
        self, component: Component, repo_url: str
    ) -> Optional[str]:
        """
        Download POM file for a component.

        Args:
            component: Component to download POM for
            repo_url: Git repository URL

        Returns:
            Filename of cached POM file, or None if not found
        """
        if not repo_url:
            return None

        # Create a cache key based on component identifier
        cache_key = component.get_identifier().replace("/", "_").replace(":", "_")
        cached_pom = self.pom_cache_dir / f"{cache_key}.pom"

        # Check if already cached
        if cached_pom.exists():
            self._log(f"Using cached POM for {component.name}")
            return cached_pom.name

        # Clone or update repository
        repo_path = self._clone_or_update_repo(repo_url)
        if not repo_path:
            return None

        # Find POM file
        # Extract group_id from component
        group_id = f"{component.group}:{component.name}" if component.group else component.name
        pom_path = self._find_pom_in_repo(repo_path, component.name, group_id)

        if pom_path and pom_path.exists():
            # Copy POM to cache
            try:
                shutil.copy2(pom_path, cached_pom)
                self._log(f"Cached POM: {cached_pom.name}")
                return cached_pom.name
            except Exception as exc:  # pylint: disable=broad-exception-caught
                self._log(f"Error caching POM: {exc}")
                return None

        return None
