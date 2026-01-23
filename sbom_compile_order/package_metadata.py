"""
Unified package metadata lookup that supports both Maven and npm registries.
"""

from typing import Optional, Tuple

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
