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
                self._log("[MAVEN] Maven detected, will use Maven for JAR downloads when available")
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

        # Try Maven first if enabled (more reliable, handles mirrors/proxies/auth)
        if self.use_maven:
            self._log(
                f"[JAR DOWNLOAD] Attempting Maven download for "
                f"{component.group}:{component.name}:{component.version}"
            )
            maven_result, auth_required = self._download_jar_with_maven(component, cached_jar)
            if maven_result:
                return maven_result, False
            if auth_required:
                return None, True
            # Fall through to HTTP download if Maven fails (but not due to auth)

        # Download from Maven Central via HTTP (fallback or if Maven not enabled)
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
                if response.getcode() == 200:
                    jar_content = response.read()
                    jar_size = len(jar_content)
                    
                    # Check if content is empty
                    if jar_size == 0:
                        self._log(
                            f"[JAR DOWNLOAD] ERROR: Downloaded empty file from Maven Central: "
                            f"{component.group}:{component.name}:{component.version}"
                        )
                        return None, False
                    
                    # Validate JAR using zipfile module (Java-like validation)
                    is_valid, validation_error = self._validate_jar_content(jar_content)
                    if is_valid:
                        # Ensure parent directory exists
                        cached_jar.parent.mkdir(parents=True, exist_ok=True)
                        
                        try:
                            self._log(f"[JAR SAVE] Writing JAR file to: {cached_jar}")
                            with open(cached_jar, "wb") as f:
                                bytes_written = f.write(jar_content)
                                f.flush()
                                os.fsync(f.fileno())
                            self._log(f"[JAR SAVE] Wrote {bytes_written} bytes to {cached_jar}")
                            
                            # Verify file was written
                            if cached_jar.exists():
                                file_size = cached_jar.stat().st_size
                                if file_size == jar_size:
                                    self._log(
                                        f"[JAR SAVE] SUCCESS: File verified on disk: {cached_jar} ({file_size} bytes)"
                                    )
                                    self._log(
                                        f"Cached JAR from Maven Central: {cached_jar.name} "
                                        f"({component.group}:{component.name}:{component.version})"
                                    )
                                    return cached_jar.name, False
                                else:
                                    self._log(
                                        f"[JAR SAVE] ERROR: File size mismatch - expected {jar_size} bytes, "
                                        f"got {file_size} bytes: {cached_jar}"
                                    )
                            else:
                                self._log(
                                    f"[JAR SAVE] ERROR: File was not written to disk: {cached_jar}"
                                )
                        except Exception as write_exc:  # pylint: disable=broad-exception-caught
                            self._log(
                                f"[JAR SAVE] ERROR: Failed to write JAR file: {write_exc} "
                                f"for {component.group}:{component.name}:{component.version}"
                            )
                            return None, False
                    else:
                        self._log(
                            f"[JAR DOWNLOAD] ERROR: Downloaded file is not a valid JAR: {validation_error} "
                            f"for {component.group}:{component.name}:{component.version} "
                            f"(size: {jar_size} bytes)"
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
                            if fallback_response.getcode() == 200:
                                jar_content = fallback_response.read()
                                jar_size = len(jar_content)
                                
                                # Check if content is empty
                                if jar_size == 0:
                                    self._log(
                                        f"[JAR DOWNLOAD] ERROR: Downloaded empty file from fallback repository: "
                                        f"{component.group}:{component.name}:{component.version}"
                                    )
                                    continue
                                
                                # Validate JAR using zipfile module (Java-like validation)
                                is_valid, validation_error = self._validate_jar_content(jar_content)
                                if is_valid:
                                    # Ensure parent directory exists
                                    cached_jar.parent.mkdir(parents=True, exist_ok=True)
                                    
                                    try:
                                        self._log(f"[JAR SAVE] Writing JAR file to: {cached_jar}")
                                        with open(cached_jar, "wb") as f:
                                            bytes_written = f.write(jar_content)
                                            f.flush()
                                            os.fsync(f.fileno())
                                        self._log(f"[JAR SAVE] Wrote {bytes_written} bytes to {cached_jar}")
                                        
                                        # Verify file was written
                                        if cached_jar.exists():
                                            file_size = cached_jar.stat().st_size
                                            if file_size == jar_size:
                                                self._log(
                                                    f"[JAR SAVE] SUCCESS: File verified on disk: {cached_jar} ({file_size} bytes)"
                                                )
                                                self._log(
                                                    f"Cached JAR from fallback repository (mvnrepository.com/repos/central): "
                                                    f"{cached_jar.name} ({component.group}:{component.name}:{component.version})"
                                                )
                                                return cached_jar.name, False
                                            else:
                                                self._log(
                                                    f"[JAR SAVE] ERROR: File size mismatch - expected {jar_size} bytes, "
                                                    f"got {file_size} bytes: {cached_jar}"
                                                )
                                        else:
                                            self._log(
                                                f"[JAR SAVE] ERROR: File was not written to disk: {cached_jar}"
                                            )
                                    except Exception as write_exc:  # pylint: disable=broad-exception-caught
                                        self._log(
                                            f"[JAR SAVE] ERROR: Failed to write JAR file from fallback: {write_exc} "
                                            f"for {component.group}:{component.name}:{component.version}"
                                        )
                                else:
                                    self._log(
                                        f"[JAR DOWNLOAD] ERROR: Downloaded file from fallback is not a valid JAR: "
                                        f"{validation_error} for {component.group}:{component.name}:{component.version} "
                                        f"(size: {jar_size} bytes)"
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

    def _validate_jar_content(self, jar_content: bytes) -> Tuple[bool, Optional[str]]:
        """
        Validate JAR content using zipfile module (Java-like validation).

        Validates that the content is a proper ZIP/JAR archive by attempting to open it.
        This is more robust than just checking magic bytes.

        Args:
            jar_content: JAR file content as bytes

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not jar_content:
            return False, "JAR content is empty"
        
        if len(jar_content) < 4:
            return False, f"JAR content too small ({len(jar_content)} bytes)"
        
        # Check ZIP magic bytes first (quick check)
        if jar_content[:4] != b"PK\x03\x04":
            return False, f"Invalid ZIP magic bytes: {jar_content[:4]}"
        
        # Validate using zipfile module (proper ZIP structure validation)
        try:
            with zipfile.ZipFile(io.BytesIO(jar_content), 'r') as jar_file:
                # Test that we can read the file list (validates ZIP structure)
                file_list = jar_file.namelist()
                
                # Check for MANIFEST.MF (standard JAR file should have this)
                has_manifest = 'META-INF/MANIFEST.MF' in file_list
                
                # Log some metadata if verbose
                if self.verbose:
                    self._log(
                        f"[JAR VALIDATION] Valid JAR archive with {len(file_list)} entries, "
                        f"has MANIFEST.MF: {has_manifest}"
                    )
                
                return True, None
        except zipfile.BadZipFile as exc:
            return False, f"Invalid ZIP/JAR structure: {exc}"
        except Exception as exc:  # pylint: disable=broad-exception-caught
            return False, f"Error validating JAR: {exc}"

    def _download_jar_with_maven(self, component: Component, cached_jar: Path) -> Tuple[Optional[str], bool]:
        """
        Download JAR file using Maven dependency:get plugin.

        This uses Maven's built-in artifact resolution, which handles:
        - Repository mirrors and proxies
        - Authentication (if configured in settings.xml)
        - Multiple repository fallbacks
        - Proper artifact validation

        Args:
            component: Component to download JAR for
            cached_jar: Path where JAR should be saved

        Returns:
            Tuple of (filename of cached JAR file or None if not found, auth_required bool)
        """
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
                self._log("[JAR DOWNLOAD] Maven not available, falling back to HTTP download")
                return None, False
        except FileNotFoundError:
            self._log("[JAR DOWNLOAD] Maven command not found, falling back to HTTP download")
            return None, False
        except subprocess.TimeoutExpired:
            self._log("[JAR DOWNLOAD] Maven version check timed out, falling back to HTTP download")
            return None, False
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._log(f"[JAR DOWNLOAD] Error checking Maven availability: {exc}, falling back to HTTP download")
            return None, False

        # Ensure parent directory exists
        cached_jar.parent.mkdir(parents=True, exist_ok=True)

        # Build Maven artifact coordinate: groupId:artifactId:version:jar
        artifact_coord = f"{component.group}:{component.name}:{component.version}:jar"

        self._log(
            f"[JAR DOWNLOAD] Using Maven to download artifact: {artifact_coord} "
            f"to {cached_jar}"
        )

        try:
            # Use Maven dependency:get plugin
            # -Dtransitive=false: Don't download dependencies, just the artifact
            # -Ddest: Specify output location
            # -DremoteRepositories: Use Maven Central (optional, Maven will use default if not specified)
            cmd = [
                "mvn",
                "dependency:get",
                f"-Dartifact={artifact_coord}",
                f"-Ddest={cached_jar}",
                "-Dtransitive=false",  # Only download the artifact, not dependencies
                "-DremoteRepositories=central::default::https://repo1.maven.org/maven2",
            ]

            if not self.verbose:
                # Suppress Maven output unless verbose
                cmd.extend(["-q"])  # Quiet mode

            self._log(f"[JAR DOWNLOAD] Executing Maven command: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,  # 2 minute timeout
            )

            if result.returncode == 0:
                # Verify file was downloaded
                if cached_jar.exists():
                    file_size = cached_jar.stat().st_size
                    if file_size > 0:
                        # Validate the downloaded JAR
                        try:
                            with open(cached_jar, "rb") as f:
                                jar_content = f.read()
                            is_valid, validation_error = self._validate_jar_content(jar_content)
                            if is_valid:
                                self._log(
                                    f"[JAR DOWNLOAD] SUCCESS: Maven downloaded JAR: {cached_jar.name} "
                                    f"({file_size} bytes) for {component.group}:{component.name}:{component.version}"
                                )
                                return cached_jar.name, False
                            else:
                                self._log(
                                    f"[JAR DOWNLOAD] ERROR: Maven downloaded invalid JAR: {validation_error} "
                                    f"for {component.group}:{component.name}:{component.version}"
                                )
                                # Remove invalid file
                                cached_jar.unlink()
                                return None, False
                        except Exception as validation_exc:  # pylint: disable=broad-exception-caught
                            self._log(
                                f"[JAR DOWNLOAD] ERROR: Failed to validate Maven-downloaded JAR: {validation_exc}"
                            )
                            return None, False
                    else:
                        self._log(
                            f"[JAR DOWNLOAD] ERROR: Maven downloaded empty file: {cached_jar}"
                        )
                        if cached_jar.exists():
                            cached_jar.unlink()
                        return None, False
                else:
                    self._log(
                        f"[JAR DOWNLOAD] ERROR: Maven command succeeded but file not found: {cached_jar}"
                    )
                    return None, False
            else:
                # Check if authentication is required
                error_output = result.stderr + result.stdout
                if any(
                    auth_indicator in error_output.lower()
                    for auth_indicator in ["401", "403", "unauthorized", "authentication", "credentials"]
                ):
                    self._log(
                        f"[JAR DOWNLOAD] Authentication required for Maven download: "
                        f"{component.group}:{component.name}:{component.version}"
                    )
                    return None, True

                self._log(
                    f"[JAR DOWNLOAD] Maven download failed (exit code {result.returncode}): "
                    f"{component.group}:{component.name}:{component.version}"
                )
                if self.verbose:
                    self._log(f"[JAR DOWNLOAD] Maven stderr: {result.stderr}")
                    self._log(f"[JAR DOWNLOAD] Maven stdout: {result.stdout}")
                return None, False

        except subprocess.TimeoutExpired:
            self._log(
                f"[JAR DOWNLOAD] Maven download timed out for "
                f"{component.group}:{component.name}:{component.version}"
            )
            return None, False
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._log(
                f"[JAR DOWNLOAD] Error executing Maven command: {exc} "
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
