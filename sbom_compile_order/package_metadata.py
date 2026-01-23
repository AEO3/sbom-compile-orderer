"""
Unified package metadata lookup that supports both Maven and npm registries.
"""

from typing import Dict, List, Optional, Tuple

from sbom_compile_order.maven_central import MavenCentralClient
from sbom_compile_order.npm_registry import NpmRegistryClient
from sbom_compile_order.parser import Component, extract_package_type


class PackageMetadataClient:
    """Wraps registry-specific clients so callers can request metadata generically."""

    def __init__(self, verbose: bool = False) -> None:
        """
        Args:
            verbose: If True, enables verbose logging for downstream clients.
        """
        self._verbose = verbose
        self._maven_client = MavenCentralClient(verbose=verbose)
        self._npm_client = NpmRegistryClient(verbose=verbose)

    def _is_npm_package(self, component: Component) -> bool:
        """Check if a component is an npm package."""
        package_type = extract_package_type(component.purl)
        if not package_type:
            package_type = component.type
        return package_type is not None and package_type.lower() == "npm"

    def get_package_info(self, component: Component) -> Tuple[Optional[str], Optional[str]]:
        """
        Returns homepage URL and license for the given package.

        Delegates to Maven Central for Maven packages and to the npm registry
        for npm packages.
        """
        if self._is_npm_package(component):
            return self._npm_client.get_package_info(component)
        return self._maven_client.get_package_info(component)

    def get_comprehensive_npm_data(self, component: Component) -> Optional[Dict]:
        """
        Get comprehensive npm package data including dependencies, author, etc.

        Only works for npm packages. Returns None for non-npm packages.

        Args:
            component: Component to get data for

        Returns:
            Dictionary with comprehensive npm package data, or None
        """
        if not self._is_npm_package(component):
            return None
        return self._npm_client.get_comprehensive_package_data(component)

    def get_npm_dependencies(self, component: Component) -> List[Tuple[str, str]]:
        """
        Get dependencies for an npm package.

        Only works for npm packages. Returns empty list for non-npm packages.

        Args:
            component: Component to get dependencies for

        Returns:
            List of (package_name, version_spec) tuples
        """
        if not self._is_npm_package(component):
            return []
        return self._npm_client.get_dependencies(component)
