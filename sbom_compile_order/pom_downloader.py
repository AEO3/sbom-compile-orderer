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
from typing import Optional, Tuple
from urllib.parse import urlparse
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

from sbom_compile_order.parser import Component


class POMDownloader:
    """Downloads and caches POM files from git repositories."""

    def __init__(
        self,
        cache_dir: Path,
        verbose: bool = False,
        clone_repos: bool = False,
        download_from_maven_central: bool = False,
    ) -> None:
        """
        Initialize the POM downloader.

        Args:
            cache_dir: Directory to cache downloaded POM files
            verbose: Enable verbose output
            clone_repos: If True, clone repositories to find POM files
            download_from_maven_central: If True, download POMs from Maven Central
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.verbose = verbose
        self.clone_repos = clone_repos
        self.download_from_maven_central = download_from_maven_central
        self.repo_cache_dir = self.cache_dir / "repos"
        if self.clone_repos:
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

    def _is_auth_required(self, error_output: str) -> bool:
        """
        Check if error output indicates authentication is required.

        Args:
            error_output: Error output from git command

        Returns:
            True if authentication appears to be required
        """
        error_lower = error_output.lower()
        auth_indicators = [
            "authentication failed",
            "permission denied",
            "access denied",
            "unauthorized",
            "401",
            "403",
            "could not read username",
            "could not read password",
            "repository not found",  # Often means private repo
            "fatal: could not read",
        ]
        return any(indicator in error_lower for indicator in auth_indicators)

    def _clone_or_update_repo(self, repo_url: str) -> Tuple[Optional[Path], bool]:
        """
        Clone or update a git repository.

        Args:
            repo_url: Git repository URL

        Returns:
            Tuple of (Path to cloned repository or None if failed, auth_required bool)
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
                    if self._is_auth_required(result.stderr):
                        self._log(f"Authentication required for {repo_url}")
                        return None, True
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
                    if self._is_auth_required(result.stderr):
                        self._log(f"Authentication required for {repo_url}")
                        return None, True
                    self._log(f"Error cloning {repo_url}: {result.stderr}")
                    return None, False

            return repo_path, False
        except subprocess.TimeoutExpired:
            self._log(f"Timeout cloning/updating {repo_url}")
            return None, False
        except FileNotFoundError:
            self._log("Error: git command not found. Please install git.")
            return None, False
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._log(f"Error accessing repository {repo_url}: {exc}")
            return None, False

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

    def _get_raw_pom_urls(self, repo_url: str, package_name: str, group_id: Optional[str] = None) -> list[str]:
        """
        Generate possible raw POM URLs for a repository.

        Args:
            repo_url: Git repository URL
            package_name: Package name
            group_id: Optional group ID

        Returns:
            List of possible raw POM URLs to try
        """
        urls = []
        parsed = urlparse(repo_url)

        # Common branches to try
        branches = ["master", "main", "develop", "trunk"]

        # GitHub
        if "github.com" in parsed.netloc.lower():
            match = re.match(r"^/([^/]+)/([^/]+)", parsed.path)
            if match:
                user = match.group(1)
                repo = match.group(2).rstrip(".git")
                for branch in branches:
                    # Root POM
                    urls.append(f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/pom.xml")
                    # Package-specific POM (common patterns)
                    urls.append(f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{package_name}/pom.xml")
                    if group_id and ":" in group_id:
                        group = group_id.split(":")[0]
                        # Try group path structure
                        group_path = group.replace(".", "/")
                        urls.append(f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{group_path}/{package_name}/pom.xml")

        # GitLab
        elif "gitlab.com" in parsed.netloc.lower() or "gitlab" in parsed.netloc.lower():
            match = re.match(r"^/([^/]+)/([^/]+)", parsed.path)
            if match:
                user = match.group(1)
                repo = match.group(2).rstrip(".git")
                for branch in branches:
                    urls.append(f"https://{parsed.netloc}/{user}/{repo}/-/raw/{branch}/pom.xml")
                    urls.append(f"https://{parsed.netloc}/{user}/{repo}/-/raw/{branch}/{package_name}/pom.xml")

        # Bitbucket
        elif "bitbucket.org" in parsed.netloc.lower():
            match = re.match(r"^/([^/]+)/([^/]+)", parsed.path)
            if match:
                user = match.group(1)
                repo = match.group(2).rstrip(".git")
                for branch in branches:
                    urls.append(f"https://bitbucket.org/{user}/{repo}/raw/{branch}/pom.xml")
                    urls.append(f"https://bitbucket.org/{user}/{repo}/raw/{branch}/{package_name}/pom.xml")

        return urls

    def _download_pom_from_maven_central(
        self, component: Component
    ) -> Tuple[Optional[bytes], bool]:
        """
        Download POM file from Maven Central Repository.

        Uses the official remotecontent endpoint as documented at:
        https://central.sonatype.org/search/rest-api-guide/

        Format: https://search.maven.org/remotecontent?filepath=groupId/artifactId/version/artifactId-version.pom

        Args:
            component: Component to download POM for

        Returns:
            Tuple of (POM file content as bytes or None if failed, auth_required bool)
        """
        if not component.group or not component.name or not component.version:
            return None, False

        try:
            # Convert groupId to path format (replace dots with slashes)
            # e.g., com.google.inject -> com/google/inject
            group_path = component.group.replace(".", "/")
            artifact_id = component.name
            version = component.version

            # Construct filepath: groupId/artifactId/version/artifactId-version.pom
            filepath = f"{group_path}/{artifact_id}/{version}/{artifact_id}-{version}.pom"

            # Build URL according to official API documentation
            pom_url = f"https://search.maven.org/remotecontent?filepath={filepath}"

            if self.verbose:
                self._log(f"Downloading POM from Maven Central: {pom_url}")

            req = Request(pom_url)
            req.add_header("User-Agent", "sbom-compile-order/1.3.1")
            with urlopen(req, timeout=10) as response:
                if response.status == 200:
                    pom_content = response.read()
                    # Verify it's valid XML
                    pom_text = pom_content.decode("utf-8", errors="ignore")
                    if "<?xml" in pom_text and "<artifactId>" in pom_text:
                        if self.verbose:
                            self._log(
                                f"Successfully downloaded POM from Maven Central for "
                                f"{component.group}:{component.name}:{component.version}"
                            )
                        return pom_content, False
        except HTTPError as exc:
            if exc.code in [401, 403]:
                return None, True  # Auth required
            if self.verbose:
                self._log(
                    f"Maven Central POM download failed (HTTP {exc.code}): "
                    f"{component.group}:{component.name}:{component.version}"
                )
        except (URLError, Exception) as exc:  # pylint: disable=broad-exception-caught
            if self.verbose:
                self._log(
                    f"Maven Central POM download failed: {exc} "
                    f"for {component.group}:{component.name}:{component.version}"
                )
        return None, False

    def _download_pom_direct(self, pom_url: str) -> Tuple[Optional[bytes], bool]:
        """
        Download a POM file directly via HTTP from a git repository.

        Args:
            pom_url: URL to the POM file

        Returns:
            Tuple of (POM file content as bytes or None if failed, auth_required bool)
        """
        try:
            req = Request(pom_url)
            req.add_header("User-Agent", "sbom-compile-order/1.3.1")
            with urlopen(req, timeout=10) as response:
                if response.status == 200:
                    return response.read(), False
        except HTTPError as exc:
            if exc.code in [401, 403]:
                return None, True  # Auth required
        except (URLError, Exception):  # pylint: disable=broad-exception-caught
            pass
        return None, False

    def download_pom(
        self, component: Component, repo_url: str = ""
    ) -> Tuple[Optional[str], bool]:
        """
        Download POM file for a component.

        First tries Maven Central, then falls back to git repository if provided.

        Args:
            component: Component to download POM for
            repo_url: Optional git repository URL (for fallback)

        Returns:
            Tuple of (filename of cached POM file or None if not found, auth_required bool)
        """
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
        cached_pom = self.pom_cache_dir / f"{cache_key}.pom"

        # Check if already cached
        if cached_pom.exists():
            self._log(f"Using cached POM for {component.name}")
            return cached_pom.name, False

        # Extract group_id from component
        group_id = f"{component.group}:{component.name}" if component.group else component.name

        # First, try downloading from Maven Central if requested
        # According to official API: https://central.sonatype.org/search/rest-api-guide/
        if self.download_from_maven_central and component.group and component.name and component.version:
            pom_content, auth_required = self._download_pom_from_maven_central(component)
            if auth_required:
                return None, True
            if pom_content:
                try:
                    # Verify it matches the component
                    pom_text = pom_content.decode("utf-8", errors="ignore")
                    if self._pom_content_matches(pom_text, component.name, group_id):
                        with open(cached_pom, "wb") as f:
                            f.write(pom_content)
                        self._log(f"Cached POM from Maven Central: {cached_pom.name}")
                        return cached_pom.name, False
                except Exception as exc:  # pylint: disable=broad-exception-caught
                    self._log(f"Error processing Maven Central POM: {exc}")

        # Fall back to git repository download if Maven Central not requested or failed
        if not repo_url:
            return None, False

        if self.clone_repos:
            # Clone repository approach
            repo_path, auth_required = self._clone_or_update_repo(repo_url)
            if auth_required:
                return None, True
            if not repo_path:
                return None, False

            # Find POM file
            pom_path = self._find_pom_in_repo(repo_path, component.name, group_id)

            if pom_path and pom_path.exists():
                # Copy POM to cache
                try:
                    shutil.copy2(pom_path, cached_pom)
                    self._log(f"Cached POM: {cached_pom.name}")
                    return cached_pom.name, False
                except Exception as exc:  # pylint: disable=broad-exception-caught
                    self._log(f"Error caching POM: {exc}")
                    return None, False
        else:
            # Direct download approach
            pom_urls = self._get_raw_pom_urls(repo_url, component.name, group_id)
            auth_detected = False
            for pom_url in pom_urls:
                self._log(f"Trying to download POM from: {pom_url}")
                pom_content, auth_required = self._download_pom_direct(pom_url)
                if auth_required:
                    auth_detected = True
                    continue  # Try next URL
                if pom_content:
                    try:
                        # Verify it's a valid POM by checking for XML and artifactId
                        pom_text = pom_content.decode("utf-8", errors="ignore")
                        if "<?xml" in pom_text and "<artifactId>" in pom_text:
                            # Check if it matches the package
                            if self._pom_content_matches(pom_text, component.name, group_id):
                                with open(cached_pom, "wb") as f:
                                    f.write(pom_content)
                                self._log(f"Cached POM: {cached_pom.name}")
                                return cached_pom.name, False
                    except Exception as exc:  # pylint: disable=broad-exception-caught
                        self._log(f"Error processing downloaded POM: {exc}")
                        continue

            # If we detected auth requirements, return auth_required=True
            if auth_detected:
                return None, True

        return None, False

    def _pom_content_matches(
        self, pom_content: str, package_name: str, group_id: Optional[str] = None
    ) -> bool:
        """
        Check if POM content matches the package.

        Args:
            pom_content: POM file content as string
            package_name: Expected package name
            group_id: Optional group ID (group:name format)

        Returns:
            True if POM matches the package
        """
        try:
            # Extract artifactId from POM
            artifact_match = re.search(r"<artifactId>([^<]+)</artifactId>", pom_content)
            if artifact_match:
                artifact_id = artifact_match.group(1).strip()
                if artifact_id.lower() == package_name.lower():
                    # If group_id provided, also check groupId
                    if group_id:
                        group_match = re.search(r"<groupId>([^<]+)</groupId>", pom_content)
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
