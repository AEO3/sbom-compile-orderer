"""
CycloneDX SBOM Parser.

Parses CycloneDX SBOM JSON files and extracts component and dependency information.
"""

import json
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
