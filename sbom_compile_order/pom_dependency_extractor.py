"""
POM Dependency Extractor.

Recursively extracts dependencies from POM files and compares them with
compile-order.csv to identify new dependencies (leaves) that are not in the
compile-order list.
"""

import csv
import json
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from sbom_compile_order.parser import Component, extract_package_type
from sbom_compile_order.pom_downloader import POMDownloader


class POMDependency:
    """Represents a dependency extracted from a POM file."""

    def __init__(
        self,
        group_id: str,
        artifact_id: str,
        version: Optional[str] = None,
        scope: Optional[str] = None,
        optional: bool = False,
    ) -> None:
        """
        Initialize a POM dependency.

        Args:
            group_id: Maven group ID
            artifact_id: Maven artifact ID
            version: Version string (may be None or contain properties)
            scope: Dependency scope (compile, test, provided, etc.)
            optional: Whether dependency is optional
        """
        self.group_id = group_id
        self.artifact_id = artifact_id
        self.version = version or ""
        self.scope = scope or "compile"
        self.optional = optional

    def get_identifier(self) -> str:
        """
        Get a unique identifier for this dependency.

        Returns:
            String identifier in format groupId:artifactId:version
        """
        if self.version:
            return f"{self.group_id}:{self.artifact_id}:{self.version}"
        return f"{self.group_id}:{self.artifact_id}"

    def get_group_id_package_name(self) -> str:
        """
        Get the Group ID format used in compile-order.csv.

        Returns:
            String in format groupId:artifactId
        """
        return f"{self.group_id}:{self.artifact_id}"

    def __eq__(self, other: object) -> bool:
        """Check equality based on identifier."""
        if not isinstance(other, POMDependency):
            return False
        return self.get_identifier() == other.get_identifier()

    def __hash__(self) -> int:
        """Hash based on identifier."""
        return hash(self.get_identifier())

    def __repr__(self) -> str:
        """Return string representation."""
        return f"POMDependency({self.get_identifier()})"


class POMDependencyExtractor:
    """Extracts dependencies from POM files."""

    def __init__(self, cache_dir: Path, verbose: bool = False, use_maven: bool = True) -> None:
        """
        Initialize the POM dependency extractor.

        Args:
            cache_dir: Directory containing cached POM files
            verbose: Enable verbose output
            use_maven: If True, use Maven commands when available (dependency:tree, help:effective-pom)
        """
        self.cache_dir = Path(cache_dir)
        self.pom_cache_dir = self.cache_dir / "poms"
        self.verbose = verbose
        self.use_maven = use_maven
        self._maven_available = None  # Cache Maven availability check

    def _log(self, message: str) -> None:
        """
        Log a message if verbose mode is enabled.

        Args:
            message: Message to log
        """
        if self.verbose:
            print(message, file=sys.stderr)

    def _is_maven_available(self) -> bool:
        """
        Check if Maven is available on the system.

        Returns:
            True if Maven is available, False otherwise
        """
        if self._maven_available is not None:
            return self._maven_available

        try:
            result = subprocess.run(
                ["mvn", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self._maven_available = result.returncode == 0
            return self._maven_available
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            self._maven_available = False
            return False

    def _get_dependencies_with_maven(
        self, group_id: str, artifact_id: str, version: str, pom_path: Optional[Path] = None
    ) -> List[POMDependency]:
        """
        Get dependencies using Maven's dependency:tree command.

        This provides complete dependency resolution including transitive dependencies
        with resolved versions (properties resolved).

        Args:
            group_id: Maven group ID
            artifact_id: Maven artifact ID
            version: Maven version
            pom_path: Optional path to POM file (if None, uses Maven coordinates)

        Returns:
            List of POMDependency objects with resolved versions
        """
        if not self._is_maven_available():
            return []

        dependencies = []
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)

                # Create a temporary POM file if not provided
                if pom_path and pom_path.exists():
                    # Use existing POM file
                    work_pom = pom_path
                else:
                    # Create minimal POM for Maven to work with
                    work_pom = temp_path / "pom.xml"
                    minimal_pom = f"""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>{group_id}</groupId>
    <artifactId>{artifact_id}</artifactId>
    <version>{version}</version>
</project>"""
                    work_pom.write_text(minimal_pom, encoding="utf-8")

                # Use Maven dependency:tree with JSON output
                output_file = temp_path / "dependency-tree.json"
                cmd = [
                    "mvn",
                    "dependency:tree",
                    f"-DoutputType=json",
                    f"-DoutputFile={output_file}",
                    "-Dtransitive=true",  # Include transitive dependencies
                    "-Dscope=compile",  # Only compile scope (exclude test)
                ]

                if not self.verbose:
                    cmd.append("-q")  # Quiet mode

                self._log(
                    f"[MAVEN] Getting dependencies for {group_id}:{artifact_id}:{version} "
                    f"using dependency:tree"
                )

                # Change to directory containing POM or temp directory
                work_dir = work_pom.parent
                result = subprocess.run(
                    cmd,
                    cwd=str(work_dir),
                    capture_output=True,
                    text=True,
                    timeout=120,
                )

                if result.returncode == 0 and output_file.exists():
                    # Parse JSON output
                    with open(output_file, "r", encoding="utf-8") as f:
                        tree_data = json.load(f)

                    # Extract dependencies from tree structure
                    # Maven JSON format uses "children" array, not "dependencies"
                    def extract_deps(node: Dict, parent_scope: str = "compile") -> None:
                        """Recursively extract dependencies from tree node."""
                        # Handle both "children" (Maven 3.7+) and "dependencies" (older formats)
                        children = node.get("children", node.get("dependencies", []))
                        
                        for dep in children:
                            # Extract dependency information
                            dep_group = dep.get("groupId", "")
                            dep_artifact = dep.get("artifactId", "")
                            dep_version = dep.get("version", "")
                            # Scope can be empty string for root, use parent scope as fallback
                            dep_scope = dep.get("scope", "") or parent_scope or "compile"
                            # Optional can be string "true"/"false" or boolean
                            dep_optional_str = dep.get("optional", "false")
                            dep_optional = (
                                dep_optional_str.lower() == "true" if isinstance(dep_optional_str, str)
                                else bool(dep_optional_str)
                            )

                            # Skip optional and test scope dependencies
                            if dep_optional or dep_scope == "test":
                                # Still process transitive deps even if skipping this one
                                child_nodes = dep.get("children", dep.get("dependencies", []))
                                if child_nodes:
                                    extract_deps(dep, dep_scope)
                                continue

                            # Create dependency object
                            pom_dep = POMDependency(
                                group_id=dep_group,
                                artifact_id=dep_artifact,
                                version=dep_version,
                                scope=dep_scope,
                                optional=dep_optional,
                            )

                            # Add if not already present (avoid duplicates)
                            dep_id = pom_dep.get_identifier()
                            if not any(d.get_identifier() == dep_id for d in dependencies):
                                dependencies.append(pom_dep)

                            # Recursively process transitive dependencies
                            child_nodes = dep.get("children", dep.get("dependencies", []))
                            if child_nodes:
                                extract_deps(dep, dep_scope)

                    # Start extraction from root (skip root node itself, process its children)
                    extract_deps(tree_data)

                    self._log(
                        f"[MAVEN] Found {len(dependencies)} dependencies for "
                        f"{group_id}:{artifact_id}:{version}"
                    )
                else:
                    if self.verbose:
                        self._log(
                            f"[MAVEN] dependency:tree failed: {result.stderr}"
                        )
                    return []

        except subprocess.TimeoutExpired:
            self._log(f"[MAVEN] dependency:tree timed out for {group_id}:{artifact_id}:{version}")
            return []
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._log(f"[MAVEN] Error getting dependencies: {exc}")
            return []

        return dependencies

    def _get_effective_pom_with_maven(
        self, group_id: str, artifact_id: str, version: str
    ) -> Optional[Path]:
        """
        Get effective POM using Maven's help:effective-pom command.

        The effective POM has all parent POMs merged and properties resolved.

        Args:
            group_id: Maven group ID
            artifact_id: Maven artifact ID
            version: Maven version

        Returns:
            Path to effective POM file, or None if failed
        """
        if not self._is_maven_available():
            return None

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                effective_pom = temp_path / "effective-pom.xml"

                # Use Maven help:effective-pom with artifact coordinates
                cmd = [
                    "mvn",
                    "help:effective-pom",
                    f"-Dartifact={group_id}:{artifact_id}:{version}",
                    f"-Doutput={effective_pom}",
                ]

                if not self.verbose:
                    cmd.append("-q")  # Quiet mode

                self._log(
                    f"[MAVEN] Getting effective POM for {group_id}:{artifact_id}:{version}"
                )

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )

                if result.returncode == 0 and effective_pom.exists():
                    # Copy to cache directory for reuse
                    cache_key = f"{group_id}_{artifact_id}_{version}".replace(":", "_").replace("/", "_")
                    cached_effective = self.pom_cache_dir / f"{cache_key}-effective.pom"
                    cached_effective.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(effective_pom, cached_effective)
                    self._log(
                        f"[MAVEN] Effective POM saved to {cached_effective}"
                    )
                    return cached_effective
                else:
                    if self.verbose:
                        self._log(
                            f"[MAVEN] help:effective-pom failed: {result.stderr}"
                        )
                    return None

        except subprocess.TimeoutExpired:
            self._log(f"[MAVEN] help:effective-pom timed out for {group_id}:{artifact_id}:{version}")
            return None
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._log(f"[MAVEN] Error getting effective POM: {exc}")
            return None

    def _parse_pom_file(self, pom_path: Path) -> List[POMDependency]:
        """
        Parse a POM file and extract dependencies.

        Uses Maven dependency:tree if available for better resolution,
        otherwise falls back to manual POM parsing.

        Args:
            pom_path: Path to the POM file

        Returns:
            List of POMDependency objects
        """
        # Try Maven first if enabled and available
        if self.use_maven and self._is_maven_available():
            try:
                # Extract groupId, artifactId, version from POM
                tree = ET.parse(pom_path)
                root = tree.getroot()
                namespaces = {"maven": "http://maven.apache.org/POM/4.0.0"}
                if root.tag.startswith("{"):
                    namespace_match = re.match(r"\{([^}]+)\}", root.tag)
                    if namespace_match:
                        namespaces["maven"] = namespace_match.group(1)

                # Get groupId
                group_elem = root.find("maven:groupId", namespaces) or root.find("groupId")
                artifact_elem = root.find("maven:artifactId", namespaces) or root.find("artifactId")
                version_elem = root.find("maven:version", namespaces) or root.find("version")

                if group_elem is not None and artifact_elem is not None and version_elem is not None:
                    group_id = group_elem.text.strip() if group_elem.text else ""
                    artifact_id = artifact_elem.text.strip() if artifact_elem.text else ""
                    version = version_elem.text.strip() if version_elem.text else ""

                    if group_id and artifact_id and version:
                        # Use Maven to get dependencies with resolved versions
                        maven_deps = self._get_dependencies_with_maven(
                            group_id, artifact_id, version, pom_path
                        )
                        if maven_deps:
                            self._log(
                                f"[MAVEN] Using Maven dependency:tree for {group_id}:{artifact_id}:{version} "
                                f"({len(maven_deps)} dependencies)"
                            )
                            return maven_deps
                        # Fall through to manual parsing if Maven fails
            except Exception as exc:  # pylint: disable=broad-exception-caught
                self._log(f"[MAVEN] Maven dependency extraction failed, using manual parsing: {exc}")
                # Fall through to manual parsing

        # Manual POM parsing (fallback or when Maven not available)
        dependencies = []
        try:
            tree = ET.parse(pom_path)
            root = tree.getroot()

            # Handle namespaces - Maven POMs use namespaces
            namespaces = {"maven": "http://maven.apache.org/POM/4.0.0"}
            if root.tag.startswith("{"):
                # Extract namespace from root tag
                namespace_match = re.match(r"\{([^}]+)\}", root.tag)
                if namespace_match:
                    namespaces["maven"] = namespace_match.group(1)

            # Find all dependency elements
            # Try with namespace first
            dep_elements = root.findall(".//maven:dependency", namespaces)
            if not dep_elements:
                # Fallback: try without namespace
                dep_elements = root.findall(".//dependency")

            for dep_elem in dep_elements:
                # Extract groupId
                group_id_elem = dep_elem.find("maven:groupId", namespaces)
                if group_id_elem is None:
                    group_id_elem = dep_elem.find("groupId")
                if group_id_elem is None or group_id_elem.text is None:
                    continue

                group_id = group_id_elem.text.strip()

                # Extract artifactId
                artifact_id_elem = dep_elem.find("maven:artifactId", namespaces)
                if artifact_id_elem is None:
                    artifact_id_elem = dep_elem.find("artifactId")
                if artifact_id_elem is None or artifact_id_elem.text is None:
                    continue

                artifact_id = artifact_id_elem.text.strip()

                # Extract version (may be None or contain properties)
                version_elem = dep_elem.find("maven:version", namespaces)
                if version_elem is None:
                    version_elem = dep_elem.find("version")
                version = version_elem.text.strip() if version_elem is not None and version_elem.text else None

                # Extract scope (defaults to "compile")
                scope_elem = dep_elem.find("maven:scope", namespaces)
                if scope_elem is None:
                    scope_elem = dep_elem.find("scope")
                scope = scope_elem.text.strip() if scope_elem is not None and scope_elem.text else "compile"

                # Extract optional flag
                optional_elem = dep_elem.find("maven:optional", namespaces)
                if optional_elem is None:
                    optional_elem = dep_elem.find("optional")
                optional = (
                    optional_elem.text.strip().lower() == "true"
                    if optional_elem is not None and optional_elem.text
                    else False
                )

                # Skip optional dependencies
                if optional:
                    continue

                # Skip test scope dependencies
                if scope == "test":
                    continue

                # Create dependency object
                dep = POMDependency(
                    group_id=group_id,
                    artifact_id=artifact_id,
                    version=version,
                    scope=scope,
                    optional=optional,
                )
                dependencies.append(dep)

        except ET.ParseError as exc:
            self._log(f"Warning: Failed to parse POM file {pom_path}: {exc}")
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._log(f"Warning: Error processing POM file {pom_path}: {exc}")

        return dependencies

    def download_poms_for_compile_order(
        self, compile_order_path: Path, pom_downloader: POMDownloader
    ) -> int:
        """
        Download POM files for all entries in compile-order.csv.

        Args:
            compile_order_path: Path to compile-order.csv file
            pom_downloader: POM downloader instance

        Returns:
            Number of POMs downloaded
        """
        downloaded_count = 0

        if not compile_order_path.exists():
            self._log(f"Warning: compile-order.csv not found: {compile_order_path}")
            return downloaded_count

        try:
            with open(compile_order_path, "r", encoding="utf-8") as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    # Skip rows that represent npm (or other non-Maven) packages.
                    # NPM leaves do not have POM files, so attempting Maven POM downloads
                    # for them only generates noise and unnecessary errors.
                    type_value = (row.get("Type") or "").strip().lower()
                    purl_value = (row.get("PURL") or "").strip()

                    is_npm = False
                    if type_value == "npm":
                        is_npm = True
                    elif purl_value:
                        try:
                            pkg_type = extract_package_type(purl_value)
                            is_npm = pkg_type == "npm"
                        except Exception:  # pylint: disable=broad-exception-caught
                            # If PURL parsing fails, fall back to treating as non-npm.
                            is_npm = False

                    if is_npm:
                        # Explicitly skip npm entries – they are handled via npm metadata / downloads.
                        self._log(
                            "Skipping POM download for npm package in compile-order.csv: "
                            f"{(row.get('Group ID') or '').strip()}:"
                            f"{(row.get('Package Name') or '').strip()}:"
                            f"{(row.get('Version/Tag') or '').strip()}"
                        )
                        continue

                    group_id = (row.get("Group ID") or "").strip()
                    package_name = (row.get("Package Name") or "").strip()
                    version = (row.get("Version/Tag") or "").strip()

                    if not group_id or not package_name or not version:
                        continue

                    # Skip if version contains properties
                    if "${" in version:
                        continue

                    # Extract groupId and artifactId from Group ID format (groupId:artifactId)
                    if ":" in group_id:
                        parts = group_id.split(":", 1)
                        group_id_part = parts[0]
                        artifact_id_part = parts[1] if len(parts) > 1 else package_name
                    else:
                        group_id_part = group_id
                        artifact_id_part = package_name

                    # Create Component object (Maven-only)
                    component = Component(
                        {
                            "bom-ref": f"pkg:maven/{group_id_part}/{artifact_id_part}@{version}?type=jar",
                            "group": group_id_part,
                            "name": artifact_id_part,
                            "version": version,
                            "purl": f"pkg:maven/{group_id_part}/{artifact_id_part}@{version}?type=jar",
                            "type": "library",
                            "scope": row.get("Scope", "required"),
                        }
                    )

                    # Check if POM already exists
                    identifier = component.get_identifier()
                    if "?" in identifier:
                        identifier = identifier.split("?")[0]
                    if "#" in identifier:
                        identifier = identifier.split("#")[0]
                    cache_key = identifier.replace("/", "_").replace(":", "_").replace("@", "_")
                    cached_pom = self.pom_cache_dir / f"{cache_key}.pom"

                    if cached_pom.exists():
                        self._log(f"POM already cached: {group_id_part}:{artifact_id_part}:{version}")
                        continue

                    # Download POM
                    self._log(f"Downloading POM for {group_id_part}:{artifact_id_part}:{version}")
                    pom_filename, auth_required = pom_downloader.download_pom(component)
                    if pom_filename:
                        downloaded_count += 1
                        self._log(f"  Successfully downloaded POM: {pom_filename}")
                    elif auth_required:
                        self._log(f"  Authentication required for {group_id_part}:{artifact_id_part}:{version}")
                    else:
                        self._log(f"  Failed to download POM for {group_id_part}:{artifact_id_part}:{version}")

        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._log(f"Error downloading POMs from compile-order.csv: {exc}")

        self._log(f"Downloaded {downloaded_count} POM files from compile-order.csv")
        return downloaded_count

    def extract_all_dependencies(self, recursive: bool = True) -> Set[POMDependency]:
        """
        Extract all dependencies from all cached POM files.

        Args:
            recursive: If True, recursively process dependencies from downloaded POMs

        Returns:
            Set of unique POMDependency objects
        """
        all_dependencies: Set[POMDependency] = set()
        processed_poms: Set[str] = set()

        if not self.pom_cache_dir.exists():
            self._log(f"POM cache directory does not exist: {self.pom_cache_dir}")
            return all_dependencies

        # Start with all cached POM files
        pom_files = list(self.pom_cache_dir.glob("*.pom"))
        self._log(f"Found {len(pom_files)} initial POM files to process")

        # Process POM files recursively
        pom_queue = list(pom_files)
        iteration = 0
        max_iterations = 10  # Prevent infinite loops

        while pom_queue and iteration < max_iterations:
            iteration += 1
            current_pom = pom_queue.pop(0)
            pom_key = current_pom.name

            # Skip if already processed
            if pom_key in processed_poms:
                continue

            processed_poms.add(pom_key)
            self._log(f"Processing POM file: {current_pom.name} (iteration {iteration})")

            # Extract dependencies from this POM
            dependencies = self._parse_pom_file(current_pom)
            all_dependencies.update(dependencies)
            self._log(f"  Extracted {len(dependencies)} dependencies from {current_pom.name}")

            # If recursive, check if we need to download POMs for new dependencies
            if recursive:
                for dep in dependencies:
                    if dep.version and "${" not in dep.version:
                        # Check if POM for this dependency exists
                        dep_component = Component(
                            {
                                "bom-ref": f"pkg:maven/{dep.group_id}/{dep.artifact_id}@{dep.version}?type=jar",
                                "group": dep.group_id,
                                "name": dep.artifact_id,
                                "version": dep.version,
                                "purl": f"pkg:maven/{dep.group_id}/{dep.artifact_id}@{dep.version}?type=jar",
                                "type": "library",
                                "scope": dep.scope,
                            }
                        )

                        # Generate expected POM filename
                        identifier = dep_component.get_identifier()
                        if "?" in identifier:
                            identifier = identifier.split("?")[0]
                        if "#" in identifier:
                            identifier = identifier.split("#")[0]
                        cache_key = identifier.replace("/", "_").replace(":", "_").replace("@", "_")
                        expected_pom = self.pom_cache_dir / f"{cache_key}.pom"

                        # If POM doesn't exist and we haven't processed it, add to queue
                        # (Note: We'll download it in the create_leaves_csv step)
                        if not expected_pom.exists() and expected_pom.name not in processed_poms:
                            # Don't add to queue here - we'll download during leaves.csv creation
                            pass

        self._log(f"Total unique dependencies extracted: {len(all_dependencies)} (from {len(processed_poms)} POM files)")
        return all_dependencies

    def load_compile_order_dependencies(self, compile_order_path: Path) -> Dict[str, Set[str]]:
        """
        Load dependencies from compile-order.csv.

        Args:
            compile_order_path: Path to compile-order.csv file

        Returns:
            Dictionary with keys:
            - 'full': Set of full identifiers (groupId:artifactId:version)
            - 'group_artifact': Set of groupId:artifactId pairs
            - 'group_artifact_version': Set of groupId:artifactId:version combinations
        """
        result = {
            "full": set(),
            "group_artifact": set(),
            "group_artifact_version": set(),
        }

        if not compile_order_path.exists():
            self._log(f"Warning: compile-order.csv not found: {compile_order_path}")
            return result

        try:
            with open(compile_order_path, "r", encoding="utf-8") as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    group_id = row.get("Group ID", "").strip()
                    package_name = row.get("Package Name", "").strip()
                    version = row.get("Version/Tag", "").strip()

                    if group_id and package_name:
                        # Group ID format in CSV is "groupId:artifactId"
                        # Extract groupId and artifactId
                        if ":" in group_id:
                            parts = group_id.split(":", 1)
                            group_id_part = parts[0]
                            artifact_id_part = parts[1] if len(parts) > 1 else package_name
                        else:
                            group_id_part = group_id
                            artifact_id_part = package_name

                        # Add full identifier: groupId:artifactId:version
                        if version:
                            full_id = f"{group_id_part}:{artifact_id_part}:{version}"
                            result["full"].add(full_id)
                            result["group_artifact_version"].add(full_id)

                        # Add groupId:artifactId pair
                        group_artifact = f"{group_id_part}:{artifact_id_part}"
                        result["group_artifact"].add(group_artifact)

                        # Also add the CSV format (groupId:artifactId)
                        result["group_artifact"].add(group_id)

        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._log(f"Error reading compile-order.csv: {exc}")

        total = len(result["full"]) + len(result["group_artifact"])
        self._log(f"Loaded {total} dependency identifiers from compile-order.csv")
        return result

    def find_new_dependencies(
        self, pom_dependencies: Set[POMDependency], compile_order_deps: Dict[str, Set[str]]
    ) -> List[POMDependency]:
        """
        Find dependencies that exist in POM files but not in compile-order.csv.

        Args:
            pom_dependencies: Set of dependencies extracted from POM files
            compile_order_deps: Dictionary of dependency identifiers from compile-order.csv

        Returns:
            List of new dependencies not in compile-order.csv
        """
        new_dependencies = []

        for dep in pom_dependencies:
            # Skip dependencies with property-based versions (e.g., ${project.version})
            if dep.version and "${" in dep.version:
                self._log(f"Skipping dependency with property version: {dep.get_identifier()}")
                continue

            # Skip dependencies without version
            if not dep.version:
                self._log(f"Skipping dependency without version: {dep.get_group_id_package_name()}")
                continue

            # Build identifiers for matching
            group_id_package = dep.get_group_id_package_name()
            full_identifier = dep.get_identifier()

            # Check if exact match exists (groupId:artifactId:version)
            if full_identifier in compile_order_deps.get("full", set()):
                continue

            # Check if groupId:artifactId:version matches
            if full_identifier in compile_order_deps.get("group_artifact_version", set()):
                continue

            # Check if groupId:artifactId matches (version may differ, but we want exact matches)
            # Only skip if we're looking for exact version matches
            # For now, we'll include it if version doesn't match

            # This is a new dependency
            new_dependencies.append(dep)

        self._log(f"Found {len(new_dependencies)} new dependencies not in compile-order.csv")
        return new_dependencies

    def create_leaves_csv(
        self,
        new_dependencies: List[POMDependency],
        leaves_csv_path: Path,
        pom_downloader: Optional[POMDownloader] = None,
        recursive: bool = True,
        compile_order_deps: Optional[Dict[str, Set[str]]] = None,
    ) -> None:
        """
        Create leaves.csv file with new dependencies.

        Args:
            new_dependencies: List of new dependencies to add
            leaves_csv_path: Path where leaves.csv should be written
            pom_downloader: Optional POM downloader to fetch POM files for dependencies
            recursive: If True, recursively process dependencies from downloaded POMs
            compile_order_deps: Dictionary of compile-order dependencies for recursive checking
        """
        # CSV header matching compile-order.csv format
        header = [
            "Order",
            "Group ID",
            "Package Name",
            "Version/Tag",
            "PURL",
            "Ref",
            "Type",
            "Scope",
            "Provided URL",
            "Repo URL",
            "Dependencies",
            "POM",
            "AUTH",
            "Homepage URL",
            "License Type",
            "External Dependency Count",
        ]

        leaves_csv_path.parent.mkdir(parents=True, exist_ok=True)

        # Track all dependencies we've added to leaves.csv
        added_dependencies: Set[str] = set()
        all_leaves: List[POMDependency] = []

        # Process dependencies recursively
        to_process = list(new_dependencies)
        iteration = 0
        max_iterations = 20  # Prevent infinite loops

        while to_process and iteration < max_iterations:
            iteration += 1
            current_dep = to_process.pop(0)
            dep_id = current_dep.get_identifier()

            # Skip if already added
            if dep_id in added_dependencies:
                continue

            # Skip if it's in compile-order.csv (shouldn't happen, but double-check)
            if compile_order_deps:
                if dep_id in compile_order_deps.get("full", set()):
                    continue
                if dep_id in compile_order_deps.get("group_artifact_version", set()):
                    continue

            added_dependencies.add(dep_id)
            all_leaves.append(current_dep)

            # Download POM if downloader is provided and not already cached
            pom_filename = None
            if current_dep.version and "${" not in current_dep.version:
                # Check if POM already exists
                component = Component(
                    {
                        "bom-ref": f"pkg:maven/{current_dep.group_id}/{current_dep.artifact_id}@{current_dep.version}?type=jar",
                        "group": current_dep.group_id,
                        "name": current_dep.artifact_id,
                        "version": current_dep.version,
                        "purl": f"pkg:maven/{current_dep.group_id}/{current_dep.artifact_id}@{current_dep.version}?type=jar",
                        "type": "library",
                        "scope": current_dep.scope,
                    }
                )
                identifier = component.get_identifier()
                if "?" in identifier:
                    identifier = identifier.split("?")[0]
                if "#" in identifier:
                    identifier = identifier.split("#")[0]
                cache_key = identifier.replace("/", "_").replace(":", "_").replace("@", "_")
                cached_pom = self.pom_cache_dir / f"{cache_key}.pom"

                if cached_pom.exists():
                    pom_filename = cached_pom.name
                    self._log(f"POM already cached: {current_dep.get_identifier()}")
                elif pom_downloader:
                    # Download POM if not cached
                    self._log(f"Downloading POM for {current_dep.get_identifier()}")
                    pom_filename, _ = pom_downloader.download_pom(component)
                    if pom_filename:
                        self._log(f"  Downloaded POM: {pom_filename}")

                        # If recursive, extract dependencies from the newly downloaded POM
                        if recursive:
                            downloaded_pom = self.pom_cache_dir / pom_filename
                            if downloaded_pom.exists():
                                self._log(f"  Extracting dependencies from downloaded POM: {pom_filename}")
                                sub_dependencies = self._parse_pom_file(downloaded_pom)
                                for sub_dep in sub_dependencies:
                                    sub_dep_id = sub_dep.get_identifier()
                                    # Only add if not in compile-order.csv and not already processed
                                    if (
                                        sub_dep_id not in added_dependencies
                                        and compile_order_deps
                                        and sub_dep_id not in compile_order_deps.get("full", set())
                                        and sub_dep_id not in compile_order_deps.get("group_artifact_version", set())
                                    ):
                                        to_process.append(sub_dep)
                                        self._log(f"    Found new sub-dependency: {sub_dep_id}")
                    else:
                        self._log(f"  Failed to download POM for {current_dep.get_identifier()}")

        # Write all leaves to CSV
        with open(leaves_csv_path, "w", encoding="utf-8", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(header)

            for idx, dep in enumerate(all_leaves, start=1):
                # Get POM filename if it was downloaded
                pom_filename = None
                if dep.version and "${" not in dep.version:
                    component = Component(
                        {
                            "bom-ref": f"pkg:maven/{dep.group_id}/{dep.artifact_id}@{dep.version}?type=jar",
                            "group": dep.group_id,
                            "name": dep.artifact_id,
                            "version": dep.version,
                            "purl": f"pkg:maven/{dep.group_id}/{dep.artifact_id}@{dep.version}?type=jar",
                            "type": "library",
                            "scope": dep.scope,
                        }
                    )
                    identifier = component.get_identifier()
                    if "?" in identifier:
                        identifier = identifier.split("?")[0]
                    if "#" in identifier:
                        identifier = identifier.split("#")[0]
                    cache_key = identifier.replace("/", "_").replace(":", "_").replace("@", "_")
                    expected_pom = self.pom_cache_dir / f"{cache_key}.pom"
                    if expected_pom.exists():
                        pom_filename = expected_pom.name

                # Build PURL
                purl = f"pkg:maven/{dep.group_id}/{dep.artifact_id}@{dep.version or 'unknown'}?type=jar"

                # Write row
                row = [
                    idx,  # Order
                    dep.get_group_id_package_name(),  # Group ID
                    dep.artifact_id,  # Package Name
                    dep.version or "",  # Version/Tag
                    purl,  # PURL
                    purl,  # Ref
                    "library",  # Type
                    dep.scope,  # Scope
                    "",  # Provided URL
                    "",  # Repo URL
                    "0",  # Dependencies
                    pom_filename or "",  # POM
                    "",  # AUTH
                    "",  # Homepage URL
                    "",  # License Type
                    "0",  # External Dependency Count
                ]
                writer.writerow(row)

        self._log(f"Created leaves.csv with {len(all_leaves)} entries: {leaves_csv_path}")
