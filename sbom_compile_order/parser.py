"""
CycloneDX SBOM Parser.

Parses CycloneDX SBOM JSON files and extracts component and dependency information.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


class Component:
    """Represents a component from the SBOM."""

    def __init__(self, component_data: Dict) -> None:
        """
        Initialize a Component from SBOM component data.

        Args:
            component_data: Dictionary containing component information from SBOM
        """
        self.ref = component_data.get("bom-ref", "")
        self.group = component_data.get("group", "")
        self.name = component_data.get("name", "")
        self.version = component_data.get("version", "")
        self.purl = component_data.get("purl", "")
        self.type = component_data.get("type", "library")
        self.scope = component_data.get("scope", "required")
        self.raw_data = component_data
        self.source_url = self._extract_source_url(component_data)

    def _extract_source_url(self, component_data: Dict) -> str:
        """
        Extract source URL from component external references.

        Looks for VCS (version control system) URLs first, then other types.

        Args:
            component_data: Dictionary containing component information

        Returns:
            Source URL string, or empty string if not found
        """
        external_refs = component_data.get("externalReferences", [])
        if not external_refs:
            return ""

        # Prefer VCS URLs (version control system)
        for ref in external_refs:
            ref_type = ref.get("type", "").lower()
            ref_url = ref.get("url", "")
            if ref_type == "vcs" and ref_url:
                return ref_url

        # Fall back to other URL types (website, distribution, etc.)
        for ref in external_refs:
            ref_url = ref.get("url", "")
            if ref_url:
                return ref_url

        return ""

    def get_identifier(self) -> str:
        """
        Get a unique identifier for this component.

        Returns:
            String identifier (prefers ref, falls back to purl or group:name:version)
        """
        if self.ref:
            return self.ref
        if self.purl:
            return self.purl
        return f"{self.group}:{self.name}:{self.version}"

    def __repr__(self) -> str:
        """Return string representation of component."""
        return f"Component({self.group}:{self.name}:{self.version})"

    def __eq__(self, other: object) -> bool:
        """Check equality based on identifier."""
        if not isinstance(other, Component):
            return False
        return self.get_identifier() == other.get_identifier()

    def __hash__(self) -> int:
        """Hash based on identifier."""
        return hash(self.get_identifier())


def parse_purl(purl: str) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """
    Parse a PURL (Package URL) to extract Maven coordinates.

    PURL format: pkg:maven/{group}/{artifact}@{version}?type={type}

    Args:
        purl: Package URL string

    Returns:
        Tuple of (group, artifact, version, type) - all may be None if parsing fails
    """
    if not purl or not purl.startswith("pkg:maven/"):
        return None, None, None, None

    try:
        # Remove the pkg:maven/ prefix
        maven_part = purl[10:]  # len("pkg:maven/") = 10

        # Split on @ to separate coordinates from version
        if "@" in maven_part:
            coords_part, rest = maven_part.split("@", 1)
        else:
            coords_part = maven_part
            rest = ""

        # Split coordinates on / to get group and artifact
        # Group may contain multiple segments separated by /
        parts = coords_part.split("/")
        if len(parts) < 2:
            return None, None, None, None

        # Last part is artifact, everything before is group
        artifact = parts[-1]
        group = ".".join(parts[:-1])

        # Extract version and type from rest
        version = None
        file_type = None

        if rest:
            # Check for query parameters
            if "?" in rest:
                version_part, query_part = rest.split("?", 1)
                version = version_part if version_part else None

                # Extract type from query parameters
                type_match = re.search(r"type=([^&]+)", query_part)
                if type_match:
                    file_type = type_match.group(1)
            else:
                version = rest if rest else None

        return group, artifact, version, file_type
    except Exception:  # pylint: disable=broad-exception-caught
        return None, None, None, None


def extract_package_type(purl: str) -> Optional[str]:
    """
    Extract package type from a PURL (Package URL).

    PURL format: pkg:{type}/{...}
    Examples:
        pkg:maven/... -> "maven"
        pkg:npm/... -> "npm"
        pkg:pypi/... -> "pypi"

    Args:
        purl: Package URL string

    Returns:
        Package type string (e.g., "maven", "npm", "pypi"), or None if PURL is invalid
    """
    if not purl or not purl.startswith("pkg:"):
        return None

    try:
        # Remove "pkg:" prefix
        rest = purl[4:]  # len("pkg:") = 4
        # Extract type up to first "/"
        if "/" in rest:
            package_type = rest.split("/", 1)[0]
            return package_type if package_type else None
        return None
    except Exception:  # pylint: disable=broad-exception-caught
        return None


def build_maven_central_url(
    group: str, artifact: str, version: str, file_type: str = "jar"
) -> str:
    """
    Build Maven Central URL from Maven coordinates.

    URL format: https://repo1.maven.org/maven2/{group_path}/{artifact}/{version}/{artifact}-{version}.{extension}

    Args:
        group: Maven group ID
        artifact: Maven artifact ID
        version: Version string
        file_type: File type (jar, pom, etc.) - defaults to jar

    Returns:
        Maven Central URL string
    """
    if not group or not artifact or not version:
        return ""

    # Convert groupId to path format (replace dots with slashes)
    group_path = group.replace(".", "/")

    # Determine file extension from type
    extension = file_type if file_type else "jar"
    if extension not in ["jar", "pom", "war", "ear"]:
        extension = "jar"  # Default to jar

    # Build URL: https://repo1.maven.org/maven2/{group_path}/{artifact}/{version}/{artifact}-{version}.{extension}
    base_url = "https://repo1.maven.org/maven2"
    url = f"{base_url}/{group_path}/{artifact}/{version}/{artifact}-{version}.{extension}"

    return url


def build_maven_central_url_from_purl(purl: str, file_type: Optional[str] = None) -> str:
    """
    Build Maven Central URL from a PURL.

    Args:
        purl: Package URL string
        file_type: Optional file type override (jar, pom, etc.)
                   If not provided, extracts from PURL query parameter

    Returns:
        Maven Central URL string, or empty string if PURL cannot be parsed
    """
    group, artifact, version, purl_type = parse_purl(purl)

    if not group or not artifact or not version:
        return ""

    # Use provided file_type or extract from PURL
    extension = file_type if file_type else (purl_type if purl_type else "jar")

    return build_maven_central_url(group, artifact, version, extension)


class SBOMParser:
    """Parser for CycloneDX SBOM files."""

    def __init__(self, sbom_path: Path) -> None:
        """
        Initialize the SBOM parser.

        Args:
            sbom_path: Path to the CycloneDX SBOM JSON file
        """
        self.sbom_path = Path(sbom_path)
        self.sbom_data: Optional[Dict] = None
        self.components: Dict[str, Component] = {}
        self.dependencies: Dict[str, List[str]] = {}

    def parse(self) -> None:
        """
        Parse the SBOM file and extract components and dependencies.

        Raises:
            FileNotFoundError: If the SBOM file doesn't exist
            json.JSONDecodeError: If the file is not valid JSON
            ValueError: If the SBOM format is invalid
        """
        if not self.sbom_path.exists():
            raise FileNotFoundError(f"SBOM file not found: {self.sbom_path}")

        with open(self.sbom_path, "r", encoding="utf-8") as file:
            self.sbom_data = json.load(file)

        # Validate SBOM format
        if not isinstance(self.sbom_data, dict):
            raise ValueError("Invalid SBOM format: root must be an object")

        if self.sbom_data.get("bomFormat") != "CycloneDX":
            raise ValueError(
                "Invalid SBOM format: bomFormat must be 'CycloneDX'"
            )

        # Parse components
        components_list = self.sbom_data.get("components", [])
        for comp_data in components_list:
            component = Component(comp_data)
            identifier = component.get_identifier()
            self.components[identifier] = component

        # Parse dependencies
        dependencies_list = self.sbom_data.get("dependencies", [])
        for dep_data in dependencies_list:
            dep_ref = dep_data.get("ref", "")
            if not dep_ref:
                continue

            depends_on = dep_data.get("dependsOn", [])
            if dep_ref not in self.dependencies:
                self.dependencies[dep_ref] = []
            self.dependencies[dep_ref].extend(depends_on)

    def get_all_components(self) -> Dict[str, Component]:
        """
        Get all components from the SBOM.

        Returns:
            Dictionary mapping component identifiers to Component objects
        """
        return self.components.copy()

    def get_dependencies(self) -> Dict[str, List[str]]:
        """
        Get dependency relationships from the SBOM.

        Returns:
            Dictionary mapping component refs to lists of dependency refs
        """
        return self.dependencies.copy()

    def get_component_by_ref(self, ref: str) -> Optional[Component]:
        """
        Get a component by its reference identifier.

        Args:
            ref: Component reference identifier

        Returns:
            Component object if found, None otherwise
        """
        return self.components.get(ref)
