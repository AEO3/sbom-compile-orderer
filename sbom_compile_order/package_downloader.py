"""
Package (JAR) file downloader with caching support.

Downloads JAR files from Maven Central and caches them locally.
"""

import io
import os
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from sbom_compile_order.parser import Component, build_maven_central_url_from_purl


class PackageDownloader:
    """Downloads and caches JAR files from Maven Central."""

    def __init__(self, cache_dir: Path, verbose: bool = False, use_maven: Optional[bool] = None) -> None:
        """
        Initialize the package downloader.

        Args:
            cache_dir: Directory to cache downloaded JAR files
            verbose: Enable verbose output
            use_maven: If True, use Maven dependency:get plugin to download artifacts.
                      If None (default), auto-detect and use Maven when available.
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.verbose = verbose
        
        # Auto-detect Maven if not explicitly set
        if use_maven is None:
            self.use_maven = self._check_maven_available()
            if self.use_maven:
                self._log(
                    "[MAVEN] Maven detected, will use Maven for JAR/WAR downloads when available"
                )
        else:
            self.use_maven = use_maven
        
        self.jar_cache_dir = self.cache_dir / "jars"
        self.jar_cache_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.cache_dir / "sbom-compile-order.log"

    def _check_maven_available(self) -> bool:
        """
        Check if Maven is available on the system.

        Returns:
            True if Maven is available, False otherwise
        """
        try:
            result = subprocess.run(
                ["mvn", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            return False

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
            # touch to ensure the file is present
            self.log_file.touch()
        return self.log_file

    def _get_maven_central_artifact_url(self, component: Component, artifact_type: str) -> str:
        """
        Construct the Maven Central direct artifact download URL from component PURL.

        Args:
            component: Component object with PURL or coordinates
            artifact_type: Artifact type (jar, war, etc.)

        Returns:
            URL string for downloading the artifact from Maven Central
        """
        file_type = artifact_type if artifact_type else "jar"
        if component.purl:
            return build_maven_central_url_from_purl(component.purl, file_type=file_type)
        elif component.group and component.name and component.version:
            from sbom_compile_order.parser import build_maven_central_url
            return build_maven_central_url(
                component.group, component.name, component.version, file_type
            )
        return ""

    def download_package(
        self, component: Component, artifact_type: str = "jar"
    ) -> Tuple[Optional[str], bool]:
        """
        Download packaged artifact for a component from Maven Central.

        Args:
            component: Component to download artifact for

        Returns:
            Tuple of (filename of cached artifact file or None if not found, auth_required bool)
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
        artifact_type = artifact_type.lower()
        cached_artifact = self.jar_cache_dir / f"{cache_key}.{artifact_type}"
        artifact_label = artifact_type.upper()

        # Check if already cached
        if cached_artifact.exists():
            self._log(f"Using cached {artifact_label} for {component.name}")
            return cached_artifact.name, False

        # Try Maven first if enabled (more reliable, handles mirrors/proxies/auth)
        if self.use_maven:
            self._log(
                f"[{artifact_label} DOWNLOAD] Attempting Maven download for "
                f"{component.group}:{component.name}:{component.version}"
            )
            maven_result, auth_required = self._download_artifact_with_maven(
                component, cached_artifact, artifact_type
            )
            if maven_result:
                return maven_result, False
            if auth_required:
                return None, True
            # Fall through to HTTP download if Maven fails (but not due to auth)

        # Download from Maven Central via HTTP (fallback or if Maven not enabled)
        artifact_url = self._get_maven_central_artifact_url(component, artifact_type)
        if not artifact_url:
            self._log(f"Failed to build {artifact_label} URL for {component.name}")
            return None, False
        self._log(f"[URL USING TO DOWNLOAD] {artifact_url}")
        self._log(f"Downloading {artifact_label} from Maven Central: {artifact_url}")

        try:
            req = Request(artifact_url)
            req.add_header("User-Agent", "sbom-compile-order/1.4.1")
            with urlopen(req, timeout=30) as response:
                if response.getcode() == 200:
                    artifact_content = response.read()
                    artifact_size = len(artifact_content)
                    
                    # Check if content is empty
                    if artifact_size == 0:
                        self._log(
                            f"[{artifact_label} DOWNLOAD] ERROR: Downloaded empty file from Maven Central: "
                            f"{component.group}:{component.name}:{component.version}"
                        )
                        return None, False
                    
                    # Validate artifact using zipfile module (Java-like validation)
                    is_valid, validation_error = self._validate_artifact_content(artifact_content)
                    if is_valid:
                        # Ensure parent directory exists
                        cached_artifact.parent.mkdir(parents=True, exist_ok=True)
                        
                        try:
                            self._log(f"[{artifact_label} SAVE] Writing file to: {cached_artifact}")
                            with open(cached_artifact, "wb") as f:
                                bytes_written = f.write(artifact_content)
                                f.flush()
                                os.fsync(f.fileno())
                            self._log(f"[{artifact_label} SAVE] Wrote {bytes_written} bytes to {cached_artifact}")
                            
                            # Verify file was written
                            if cached_artifact.exists():
                                file_size = cached_artifact.stat().st_size
                                if file_size == artifact_size:
                                    self._log(
                                        f"[{artifact_label} SAVE] SUCCESS: File verified on disk: {cached_artifact} ({file_size} bytes)"
                                    )
                                    self._log(
                                        f"Cached {artifact_label} from Maven Central: {cached_artifact.name} "
                                        f"({component.group}:{component.name}:{component.version})"
                                    )
                                    return cached_artifact.name, False
                                else:
                                    self._log(
                                        f"[{artifact_label} SAVE] ERROR: File size mismatch - expected {artifact_size} bytes, "
                                        f"got {file_size} bytes: {cached_artifact}"
                                    )
                            else:
                                self._log(
                                    f"[{artifact_label} SAVE] ERROR: File was not written to disk: {cached_artifact}"
                                )
                        except Exception as write_exc:  # pylint: disable=broad-exception-caught
                            self._log(
                                f"[{artifact_label} SAVE] ERROR: Failed to write file: {write_exc} "
                                f"for {component.group}:{component.name}:{component.version}"
                            )
                            return None, False
                    else:
                        self._log(
                            f"[{artifact_label} DOWNLOAD] ERROR: Downloaded file is not a valid {artifact_label}: {validation_error} "
                            f"for {component.group}:{component.name}:{component.version} "
                            f"(size: {artifact_size} bytes)"
                        )
        except HTTPError as exc:
            if exc.code in [401, 403]:
                return None, True  # Auth required
            if exc.code == 404:
                # Try fallback URL: https://mvnrepository.com/repos/central
                self._log(
                    f"Maven Central {artifact_label} not found (HTTP 404), trying fallback repository: "
                    f"{component.group}:{component.name}:{component.version}"
                )
                fallback_url = self._get_fallback_artifact_url(component, artifact_type)
                if fallback_url:
                    self._log(f"[URL USING TO DOWNLOAD] {fallback_url}")
                    try:
                        fallback_req = Request(fallback_url)
                        fallback_req.add_header("User-Agent", "sbom-compile-order/1.4.1")
                        with urlopen(fallback_req, timeout=30) as fallback_response:
                            if fallback_response.getcode() == 200:
                                artifact_content = fallback_response.read()
                                artifact_size = len(artifact_content)
                                
                                # Check if content is empty
                                if artifact_size == 0:
                                    self._log(
                                        f"[{artifact_label} DOWNLOAD] ERROR: Downloaded empty file from fallback repository: "
                                        f"{component.group}:{component.name}:{component.version}"
                                    )
                                    return None, False
                                
                                # Validate artifact using zipfile module (Java-like validation)
                                is_valid, validation_error = self._validate_artifact_content(artifact_content)
                                if is_valid:
                                    # Ensure parent directory exists
                                    cached_artifact.parent.mkdir(parents=True, exist_ok=True)
                                    
                                    try:
                                        self._log(f"[{artifact_label} SAVE] Writing file to: {cached_artifact}")
                                        with open(cached_artifact, "wb") as f:
                                            bytes_written = f.write(artifact_content)
                                            f.flush()
                                            os.fsync(f.fileno())
                                        self._log(f"[{artifact_label} SAVE] Wrote {bytes_written} bytes to {cached_artifact}")
                                        
                                        # Verify file was written
                                        if cached_artifact.exists():
                                            file_size = cached_artifact.stat().st_size
                                            if file_size == artifact_size:
                                                self._log(
                                                    f"[{artifact_label} SAVE] SUCCESS: File verified on disk: {cached_artifact} ({file_size} bytes)"
                                                )
                                                self._log(
                                                    f"Cached {artifact_label} from fallback repository (mvnrepository.com/repos/central): "
                                                    f"{cached_artifact.name} ({component.group}:{component.name}:{component.version})"
                                                )
                                                return cached_artifact.name, False
                                            else:
                                                self._log(
                                                    f"[{artifact_label} SAVE] ERROR: File size mismatch - expected {artifact_size} bytes, "
                                                    f"got {file_size} bytes: {cached_artifact}"
                                                )
                                        else:
                                            self._log(
                                                f"[{artifact_label} SAVE] ERROR: File was not written to disk: {cached_artifact}"
                                            )
                                    except Exception as write_exc:  # pylint: disable=broad-exception-caught
                                        self._log(
                                            f"[{artifact_label} SAVE] ERROR: Failed to write file from fallback: {write_exc} "
                                            f"for {component.group}:{component.name}:{component.version}"
                                        )
                                else:
                                    self._log(
                                        f"[{artifact_label} DOWNLOAD] ERROR: Downloaded file from fallback is not a valid {artifact_label}: "
                                        f"{validation_error} for {component.group}:{component.name}:{component.version} "
                                        f"(size: {artifact_size} bytes)"
                                    )
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
                    f"Maven Central {artifact_label} download failed (HTTP {exc.code}): "
                    f"{component.group}:{component.name}:{component.version}"
                )
        except (URLError, Exception) as exc:  # pylint: disable=broad-exception-caught
            if self.verbose:
                self._log(
                    f"Maven Central {artifact_label} download failed: {exc} "
                    f"for {component.group}:{component.name}:{component.version}"
                )
        return None, False

    def _validate_artifact_content(self, artifact_content: bytes) -> Tuple[bool, Optional[str]]:
        """
        Validate artifact content using zipfile module (Java-like validation).

        Validates that the content is a proper ZIP-based archive by attempting to open it.
        This is more robust than just checking magic bytes.

        Args:
            artifact_content: Artifact file content as bytes

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not artifact_content:
            return False, "Artifact content is empty"
        
        if len(artifact_content) < 4:
            return False, f"Artifact content too small ({len(artifact_content)} bytes)"
        
        # Check ZIP magic bytes first (quick check)
        if artifact_content[:4] != b"PK\x03\x04":
            return False, f"Invalid ZIP magic bytes: {artifact_content[:4]}"
        
        # Validate using zipfile module (proper ZIP structure validation)
        try:
            with zipfile.ZipFile(io.BytesIO(artifact_content), 'r') as jar_file:
                # Test that we can read the file list (validates ZIP structure)
                file_list = jar_file.namelist()
                
                # Check for MANIFEST.MF (standard JAR/WAR file should have this)
                has_manifest = 'META-INF/MANIFEST.MF' in file_list
                
                # Log some metadata if verbose
                if self.verbose:
                    self._log(
                        f"[ARTIFACT VALIDATION] Valid artifact archive with {len(file_list)} entries, "
                        f"has MANIFEST.MF: {has_manifest}"
                    )
                
                return True, None
        except zipfile.BadZipFile as exc:
            return False, f"Invalid ZIP/JAR structure: {exc}"
        except Exception as exc:  # pylint: disable=broad-exception-caught
            return False, f"Error validating artifact: {exc}"

    def _download_artifact_with_maven(
        self, component: Component, cached_artifact: Path, artifact_type: str
    ) -> Tuple[Optional[str], bool]:
        """
        Download artifact using Maven dependency:get plugin.

        This uses Maven's built-in artifact resolution, which handles:
        - Repository mirrors and proxies
        - Authentication (if configured in settings.xml)
        - Multiple repository fallbacks
        - Proper artifact validation

        Args:
            component: Component to download artifact for
            cached_artifact: Path where artifact should be saved
            artifact_type: Artifact type (jar, war, etc.)

        Returns:
            Tuple of (filename of cached artifact file or None if not found, auth_required bool)
        """
        artifact_label = artifact_type.upper()
        if not component.group or not component.name or not component.version:
            return None, False

        # Check if Maven is available
        try:
            result = subprocess.run(
                ["mvn", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                self._log(f"[{artifact_label} DOWNLOAD] Maven not available, falling back to HTTP download")
                return None, False
        except FileNotFoundError:
            self._log(f"[{artifact_label} DOWNLOAD] Maven command not found, falling back to HTTP download")
            return None, False
        except subprocess.TimeoutExpired:
            self._log(
                f"[{artifact_label} DOWNLOAD] Maven version check timed out, falling back to HTTP download"
            )
            return None, False
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._log(
                f"[{artifact_label} DOWNLOAD] Error checking Maven availability: {exc}, falling back to HTTP download"
            )
            return None, False

        # Ensure parent directory exists
        cached_artifact.parent.mkdir(parents=True, exist_ok=True)

        # Build Maven artifact coordinate: groupId:artifactId:version:type
        artifact_coord = f"{component.group}:{component.name}:{component.version}:{artifact_type}"

        self._log(
            f"[{artifact_label} DOWNLOAD] Using Maven to download artifact: {artifact_coord} "
            f"to {cached_artifact}"
        )

        try:
            cmd = [
                "mvn",
                "dependency:get",
                f"-Dartifact={artifact_coord}",
                f"-Ddest={cached_artifact}",
                "-Dtransitive=false",
                "-DremoteRepositories=central::default::https://repo1.maven.org/maven2",
            ]

            if not self.verbose:
                cmd.extend(["-q"])

            self._log(f"[{artifact_label} DOWNLOAD] Executing Maven command: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode == 0:
                if not cached_artifact.exists():
                    self._try_copy_from_maven_local_repo(component, cached_artifact, artifact_type)
                if cached_artifact.exists():
                    file_size = cached_artifact.stat().st_size
                    if file_size > 0:
                        try:
                            with open(cached_artifact, "rb") as f:
                                artifact_content = f.read()
                            is_valid, validation_error = self._validate_artifact_content(artifact_content)
                            if is_valid:
                                self._log(
                                    f"[{artifact_label} DOWNLOAD] SUCCESS: Maven downloaded {artifact_label}: {cached_artifact.name} "
                                    f"({file_size} bytes) for {component.group}:{component.name}:{component.version}"
                                )
                                return cached_artifact.name, False
                            self._log(
                                f"[{artifact_label} DOWNLOAD] ERROR: Maven downloaded invalid {artifact_label}: {validation_error} "
                                f"for {component.group}:{component.name}:{component.version}"
                            )
                            cached_artifact.unlink()
                            return None, False
                        except Exception as validation_exc:  # pylint: disable=broad-exception-caught
                            self._log(
                                f"[{artifact_label} DOWNLOAD] ERROR: Failed to validate Maven-downloaded {artifact_label}: {validation_exc}"
                            )
                            return None, False
                    self._log(
                        f"[{artifact_label} DOWNLOAD] ERROR: Maven downloaded empty file: {cached_artifact}"
                    )
                    if cached_artifact.exists():
                        cached_artifact.unlink()
                    return None, False
                self._log(
                    f"[{artifact_label} DOWNLOAD] ERROR: Maven command succeeded but file not found: {cached_artifact}"
                )
                return None, False
            error_output = result.stderr + result.stdout
            if any(
                auth_indicator in error_output.lower()
                for auth_indicator in ["401", "403", "unauthorized", "authentication", "credentials"]
            ):
                self._log(
                    f"[{artifact_label} DOWNLOAD] Authentication required for Maven download: "
                    f"{component.group}:{component.name}:{component.version}"
                )
                return None, True
            self._log(
                f"[{artifact_label} DOWNLOAD] Maven download failed (exit code {result.returncode}): "
                f"{component.group}:{component.name}:{component.version}"
            )
            if self.verbose:
                self._log(f"[{artifact_label} DOWNLOAD] Maven stderr: {result.stderr}")
                self._log(f"[{artifact_label} DOWNLOAD] Maven stdout: {result.stdout}")
            return None, False

        except subprocess.TimeoutExpired:
            self._log(
                f"[{artifact_label} DOWNLOAD] Maven download timed out for "
                f"{component.group}:{component.name}:{component.version}"
            )
            return None, False
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._log(
                f"[{artifact_label} DOWNLOAD] Error executing Maven command: {exc} "
                f"for {component.group}:{component.name}:{component.version}"
            )
            return None, False

    def _get_fallback_artifact_url(self, component: Component, artifact_type: str) -> str:
        """
        Construct the fallback Maven Central artifact URL using mvnrepository.com/repos/central.

        Args:
            component: Component object with PURL or coordinates
            artifact_type: Artifact type (jar, war, etc.)

        Returns:
            URL string for downloading the artifact from fallback repository
        """
        if component.group and component.name and component.version:
            from sbom_compile_order.parser import build_maven_central_url
            fallback_base_url = "https://mvnrepository.com/repos/central"
            return build_maven_central_url(
                component.group, component.name, component.version, artifact_type, base_url=fallback_base_url
            )
        return ""

    def _try_copy_from_maven_local_repo(
        self, component: Component, cached_artifact: Path, artifact_type: str
    ) -> None:
        """
        When Maven downloads succeed but dest file isn't written, copy from Maven local repo.
        """
        if not component.group or not component.name or not component.version:
            return

        group_path = component.group.replace(".", "/")
        artifact_filename = f"{component.name}-{component.version}.{artifact_type}"
        local_repo_path = Path.home() / ".m2" / "repository" / group_path / component.name / component.version / artifact_filename
        if local_repo_path.exists():
            try:
                cached_artifact.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(local_repo_path, cached_artifact)
                self._log(
                    f"[{artifact_type.upper()} DOWNLOAD] Copied {artifact_filename} from local Maven repo to cache"
                )
            except Exception as exc:  # pylint: disable=broad-exception-caught
                self._log(
                    f"[{artifact_type.upper()} DOWNLOAD] Failed to copy artifact from local Maven repo: {exc}"
                )
