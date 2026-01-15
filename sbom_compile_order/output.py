"""
Output formatters for compilation order.

Provides different output formats: text, JSON, CSV, etc.
"""

import csv
import io
import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple, TYPE_CHECKING
from urllib.parse import urlparse, parse_qs

from sbom_compile_order.parser import Component

if TYPE_CHECKING:
    import networkx as nx


def extract_repo_url(url: str) -> str:
    """
    Extract the root repository URL from a source URL.

    Converts various URL formats to a git clone-able repository URL.
    Only returns URLs that are actually git repositories.

    Args:
        url: Source URL from component metadata

    Returns:
        Root repository URL suitable for git clone, or empty string if not a git repo
    """
    if not url:
        return ""

    url = url.strip()
    if not url:
        return ""

    # Parse the URL
    try:
        parsed = urlparse(url)
    except Exception:  # pylint: disable=broad-exception-caught
        return ""

    # Skip SVN URLs (not git clone-able)
    if "svn" in parsed.netloc.lower() or "/svn/" in parsed.path.lower():
        return ""

    # Skip browse/view URLs that aren't git repos
    if any(
        path_part in parsed.path.lower()
        for path_part in ["/browse/", "/viewvc/", "/view/", "/tags/", "/trunk/"]
    ):
        # Check if it's Apache SVN
        if "apache.org" in parsed.netloc.lower():
            return ""
        # For other sites, try to extract repo if it looks like git
        pass

    # Handle GitHub URLs
    if "github.com" in parsed.netloc.lower():
        # Pattern: https://github.com/user/repo/tree/branch or /tree/master/ or .git
        # Extract user/repo from path, handling various formats
        match = re.match(r"^/([^/]+)/([^/]+)", parsed.path)
        if match:
            user = match.group(1)
            repo = match.group(2)
            # Remove .git suffix if present, we'll add it back
            repo = repo.rstrip(".git")
            # Use https for GitHub (more reliable than http)
            scheme = "https" if parsed.scheme in ["http", "https"] else parsed.scheme
            return f"{scheme}://{parsed.netloc}/{user}/{repo}.git"
        return ""

    # Handle GitLab URLs
    if "gitlab.com" in parsed.netloc.lower() or "gitlab" in parsed.netloc.lower():
        # Pattern: https://gitlab.com/user/repo/-/tree/branch
        match = re.match(r"^/([^/]+)/([^/]+)", parsed.path)
        if match:
            user = match.group(1)
            repo = match.group(2)
            repo = repo.rstrip(".git")
            return f"{parsed.scheme}://{parsed.netloc}/{user}/{repo}.git"
        return ""

    # Handle Bitbucket URLs
    if "bitbucket.org" in parsed.netloc.lower():
        # Pattern: https://bitbucket.org/user/repo/src
        match = re.match(r"^/([^/]+)/([^/]+)", parsed.path)
        if match:
            user = match.group(1)
            repo = match.group(2)
            repo = repo.rstrip(".git")
            scheme = "https" if parsed.scheme in ["http", "https"] else parsed.scheme
            return f"{scheme}://{parsed.netloc}/{user}/{repo}.git"
        return ""

    # Handle Apache Git (git-wip-us.apache.org)
    if "git-wip-us.apache.org" in parsed.netloc.lower() or "gitbox.apache.org" in parsed.netloc.lower():
        # Pattern: https://git-wip-us.apache.org/repos/asf?p=repo.git
        if "p=" in parsed.query:
            query_params = parse_qs(parsed.query)
            repo_param = query_params.get("p", [""])[0]
            if repo_param:
                repo = repo_param.rstrip(".git")
                return f"{parsed.scheme}://{parsed.netloc}/repos/asf/{repo}.git"
        # Pattern: https://git-wip-us.apache.org/repos/asf/repo.git
        match = re.match(r"^/repos/asf/([^/]+)", parsed.path)
        if match:
            repo = match.group(1).rstrip(".git")
            return f"{parsed.scheme}://{parsed.netloc}/repos/asf/{repo}.git"
        return ""

    # Handle Eclipse Git (git.eclipse.org)
    if "git.eclipse.org" in parsed.netloc.lower():
        # Pattern: http://git.eclipse.org/c/{project}/{repo}.git/tree or /tree/path
        # Extract up to and including .git
        match = re.match(r"^/c/([^/]+)/([^/]+\.git)", parsed.path)
        if match:
            project = match.group(1)
            repo = match.group(2)
            return f"{parsed.scheme}://{parsed.netloc}/c/{project}/{repo}"
        return ""

    # Handle generic git URLs that already end in .git
    # But check if there's a path after .git (like /tree) and remove it
    if ".git" in parsed.path:
        # Find the position of .git in the path
        git_pos = parsed.path.find(".git")
        if git_pos != -1:
            # Extract everything up to and including .git
            base_path = parsed.path[: git_pos + 4]
            return f"{parsed.scheme}://{parsed.netloc}{base_path}"

    # Handle URLs that look like git repos but don't have .git suffix
    # Check if path has typical git repo structure (user/repo)
    match = re.match(r"^/([^/]+)/([^/]+)/?$", parsed.path)
    if match:
        # Only if it's a known git hosting service
        git_hosts = ["github", "gitlab", "bitbucket", "git", "gitea", "gitee", "sourceforge"]
        if any(host in parsed.netloc.lower() for host in git_hosts):
            user = match.group(1)
            repo = match.group(2)
            return f"{parsed.scheme}://{parsed.netloc}/{user}/{repo}.git"

    # If we can't determine it's a git repo, return empty
    return ""


class OutputFormatter:
    """Base class for output formatters."""

    def format(
        self,
        order: List[str],
        components: Dict[str, Component],
        has_circular: bool,
        statistics: Optional[Dict] = None,
        include_metadata: bool = False,
        graph: Optional["nx.DiGraph"] = None,
        pom_downloader: Optional[object] = None,
    ) -> str:
        """
        Format the compilation order.

        Args:
            order: List of component identifiers in compilation order
            components: Dictionary of all components
            has_circular: Whether circular dependencies were detected
            statistics: Optional graph statistics
            include_metadata: Whether to include component metadata
            graph: Optional dependency graph for counting dependencies
            pom_downloader: Optional POM downloader instance

        Returns:
            Formatted string
        """
        raise NotImplementedError


class TextFormatter(OutputFormatter):
    """Text-based output formatter."""

    def format(
        self,
        order: List[str],
        components: Dict[str, Component],
        has_circular: bool,
        statistics: Optional[Dict] = None,
        include_metadata: bool = False,
        graph: Optional["nx.DiGraph"] = None,
        pom_downloader: Optional[object] = None,
    ) -> str:
        """
        Format compilation order as text.

        Args:
            order: List of component identifiers in compilation order
            components: Dictionary of all components
            has_circular: Whether circular dependencies were detected
            statistics: Optional graph statistics
            include_metadata: Whether to include component metadata
            graph: Optional dependency graph (not used in text format)
            pom_downloader: Optional POM downloader (not used in text format)

        Returns:
            Formatted text string
        """
        lines = []
        lines.append("=" * 80)
        lines.append("Compilation Order")
        lines.append("=" * 80)

        if has_circular:
            lines.append("")
            lines.append("WARNING: Circular dependencies detected!")
            lines.append(
                "The order below may not be complete or may require manual intervention."
            )
            lines.append("")

        if statistics:
            lines.append(f"Total Components: {statistics.get('total_components', 'N/A')}")
            lines.append(
                f"Total Dependencies: {statistics.get('total_dependencies', 'N/A')}"
            )
            lines.append("")

        lines.append("Order:")
        lines.append("")

        for idx, comp_ref in enumerate(order, 1):
            comp = components.get(comp_ref)
            if comp:
                if include_metadata:
                    lines.append(
                        f"{idx}. {comp.group}:{comp.name}:{comp.version}"
                    )
                    if comp.purl:
                        lines.append(f"   PURL: {comp.purl}")
                    if comp.ref and comp.ref != comp.get_identifier():
                        lines.append(f"   Ref: {comp.ref}")
                    lines.append("")
                else:
                    lines.append(
                        f"{idx}. {comp.group}:{comp.name}:{comp.version}"
                    )
            else:
                lines.append(f"{idx}. {comp_ref}")

        return "\n".join(lines)


class JSONFormatter(OutputFormatter):
    """JSON-based output formatter."""

    def format(
        self,
        order: List[str],
        components: Dict[str, Component],
        has_circular: bool,
        statistics: Optional[Dict] = None,
        include_metadata: bool = False,
        graph: Optional["nx.DiGraph"] = None,
        pom_downloader: Optional[object] = None,
    ) -> str:
        """
        Format compilation order as JSON.

        Args:
            order: List of component identifiers in compilation order
            components: Dictionary of all components
            has_circular: Whether circular dependencies were detected
            statistics: Optional graph statistics
            include_metadata: Whether to include component metadata
            graph: Optional dependency graph (not used in JSON format)
            pom_downloader: Optional POM downloader (not used in JSON format)

        Returns:
            Formatted JSON string
        """
        compilation_order = []

        for comp_ref in order:
            comp = components.get(comp_ref)
            if comp:
                comp_data = {
                    "ref": comp.ref,
                    "group": comp.group,
                    "name": comp.name,
                    "version": comp.version,
                    "purl": comp.purl,
                    "type": comp.type,
                    "scope": comp.scope,
                }
                if not include_metadata:
                    # Remove empty fields
                    comp_data = {
                        k: v for k, v in comp_data.items() if v
                    }
                compilation_order.append(comp_data)
            else:
                compilation_order.append({"ref": comp_ref})

        output = {
            "compilation_order": compilation_order,
            "total_components": len(order),
            "has_circular_dependencies": has_circular,
        }

        if statistics:
            output["statistics"] = statistics

        return json.dumps(output, indent=2)


class CSVFormatter(OutputFormatter):
    """CSV-based output formatter."""

    def format(
        self,
        order: List[str],
        components: Dict[str, Component],
        has_circular: bool,
        statistics: Optional[Dict] = None,
        include_metadata: bool = False,
        graph: Optional["nx.DiGraph"] = None,
        pom_downloader: Optional[object] = None,
        maven_central_client: Optional[object] = None,
        dependency_resolver: Optional[object] = None,
    ) -> str:
        """
        Format compilation order as CSV.

        Columns: Order, Group ID, Package Name, Version/Tag, Provided URL, Repo URL,
        Dependencies, POM, AUTH, Homepage URL, License Type

        Args:
            order: List of component identifiers in compilation order
            components: Dictionary of all components
            has_circular: Whether circular dependencies were detected
            statistics: Optional graph statistics (not used in CSV)
            include_metadata: Whether to include component metadata (not used in CSV)
            graph: Optional dependency graph for counting dependencies
            pom_downloader: Optional POM downloader instance
            maven_central_client: Optional Maven Central API client
            dependency_resolver: Optional dependency resolver for fetching metadata

        Returns:
            Formatted CSV string
        """
        output = io.StringIO()
        writer = csv.writer(output)

        # Write header
        writer.writerow(
            [
                "Order",
                "Group ID",
                "Package Name",
                "Version/Tag",
                "Provided URL",
                "Repo URL",
                "Dependencies",
                "POM",
                "AUTH",
                "Homepage URL",
                "License Type",
                "External Dependency Count",
            ]
        )

        # Write data rows
        for idx, comp_ref in enumerate(order, 1):
            row = self._format_row(
                idx,
                comp_ref,
                components,
                graph,
                pom_downloader,
                maven_central_client,
                dependency_resolver,
            )
            writer.writerow(row)

        return output.getvalue()

    def format_incremental(
        self,
        output_path: Path,
        order: List[str],
        components: Dict[str, Component],
        has_circular: bool,
        statistics: Optional[Dict] = None,
        include_metadata: bool = False,
        graph: Optional["nx.DiGraph"] = None,
        pom_downloader: Optional[object] = None,
        maven_central_client: Optional[object] = None,
        dependency_resolver: Optional[object] = None,
    ) -> None:
        """
        Format compilation order as CSV, writing incrementally to file.

        Always overwrites existing file to ensure it contains exactly the same number
        of rows as components in the SBOM.

        Columns: Order, Group ID, Package Name, Version/Tag, PURL, Ref, Type, Scope,
        Provided URL, Repo URL, Dependencies, POM, AUTH, Homepage URL, License Type,
        External Dependency Count, Cyclical Dependencies

        Args:
            output_path: Path to output CSV file
            order: List of component identifiers in compilation order
            components: Dictionary of all components
            has_circular: Whether circular dependencies were detected
            statistics: Optional graph statistics (not used in CSV)
            include_metadata: Whether to include component metadata (not used in CSV)
            graph: Optional dependency graph for counting dependencies
            pom_downloader: Optional POM downloader instance
            maven_central_client: Optional Maven Central API client
            dependency_resolver: Optional dependency resolver for fetching metadata
        """
        # Always overwrite existing file to ensure it matches the SBOM exactly
        with open(output_path, "w", encoding="utf-8", newline="") as file:
            writer = csv.writer(file)

            # Always write header
            writer.writerow(
                [
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
                    "Cyclical Dependencies",
                ]
            )

            # Write data rows incrementally - exactly one row per component in order
            # This file is written once and never modified again
            for idx, comp_ref in enumerate(order, 1):
                row = self._format_row(
                    idx,
                    comp_ref,
                    components,
                    graph,
                    pom_downloader,
                    maven_central_client,
                    dependency_resolver,
                    has_circular,
                )
                writer.writerow(row)
                file.flush()  # Ensure row is written immediately
                os.fsync(file.fileno())  # Force write to disk

    def _format_row(
        self,
        idx: int,
        comp_ref: str,
        components: Dict[str, Component],
        graph: Optional["nx.DiGraph"],
        pom_downloader: Optional[object],
        maven_central_client: Optional[object] = None,
        dependency_resolver: Optional[object] = None,
        has_circular: bool = False,
    ) -> List:
        """
        Format a single CSV row.

        Args:
            idx: Row index/order number
            comp_ref: Component reference identifier
            components: Dictionary of all components
            graph: Optional dependency graph
            pom_downloader: Optional POM downloader instance
            maven_central_client: Optional Maven Central API client
            dependency_resolver: Optional dependency resolver for fetching metadata

        Returns:
            List of values for the CSV row
        """
        comp = components.get(comp_ref)
        if comp:
            # Get Group ID (group:name format)
            if comp.group:
                group_id = f"{comp.group}:{comp.name}"
            else:
                group_id = comp.name

            # Get package name (just the name part)
            package_name = comp.name

            # Get version/tag
            version_tag = comp.version if comp.version else ""

            # Get metadata fields
            purl = comp.purl if comp.purl else ""
            ref = comp.ref if comp.ref else ""
            comp_type = comp.type if comp.type else ""
            scope = comp.scope if comp.scope else ""

            # Get provided URL (original source URL)
            provided_url = comp.source_url if hasattr(comp, "source_url") else ""

            # Extract repo URL (root git clone-able URL)
            # Leave empty for compile-order.csv - will be filled in enhanced.csv from POM file
            repo_url = ""

            # Count dependencies (incoming edges/predecessors)
            dependency_count = 0
            if graph is not None and comp_ref in graph:
                try:
                    # Handle potential cycles gracefully - if graph has cycles,
                    # NetworkX may raise errors during iteration
                    predecessors = list(graph.predecessors(comp_ref))
                    dependency_count = len(predecessors)
                except (RuntimeError, ValueError) as graph_exc:
                    # NetworkX can raise RuntimeError or ValueError if graph has cycles
                    # or is modified during iteration
                    if "cycle" in str(graph_exc).lower() or "iteration" in str(graph_exc).lower():
                        # Graph has cycles - try to get count safely
                        try:
                            # Use in_degree as a safer alternative
                            dependency_count = graph.in_degree(comp_ref)
                        except Exception:  # pylint: disable=broad-exception-caught
                            dependency_count = 0
                    else:
                        dependency_count = 0
                except Exception:  # pylint: disable=broad-exception-caught
                    # Any other error - default to 0
                    dependency_count = 0

            # Download POM file if downloader is available
            pom_filename = ""
            auth_required = ""
            if pom_downloader:
                try:
                    # Try downloading from Maven Central first (works without repo_url)
                    pom_result, auth_req = pom_downloader.download_pom(comp, repo_url or "")
                    pom_filename = pom_result or ""
                    auth_required = "AUTH" if auth_req else ""
                except Exception:  # pylint: disable=broad-exception-caught
                    pom_filename = ""
                    auth_required = ""

            # Fetch homepage URL and license type
            homepage_url = ""
            license_type = ""
            external_dependency_count = 0

            # Detect cyclical dependencies for this component
            cyclical_dependencies = ""
            if has_circular and graph is not None:
                import sys
                try:
                    # Import DependencyGraph to use cycle detection methods
                    # We need to create a temporary DependencyGraph instance to use its methods
                    # Or we can detect cycles directly using NetworkX
                    import networkx as nx
                    if comp_ref in graph:
                        # Get all simple cycles that include this component
                        try:
                            all_cycles = list(nx.simple_cycles(graph))
                            component_cycles = [
                                cycle for cycle in all_cycles if comp_ref in cycle
                            ]
                            
                            if component_cycles:
                                # Format cycles as: "comp1->comp2->comp3->comp1; comp4->comp5->comp4"
                                cycle_strings = []
                                for cycle in component_cycles:
                                    cycle_str = "->".join(cycle)
                                    # Close the cycle
                                    if len(cycle) > 1:
                                        cycle_str += f"->{cycle[0]}"
                                    cycle_strings.append(cycle_str)
                                
                                cyclical_dependencies = "; ".join(cycle_strings)
                                # Note: Cycle detection logging removed from stdout/stderr
                                # All cycle information is logged in cli.py when cycles are detected
                        except Exception as cycle_exc:  # pylint: disable=broad-exception-caught
                            # If cycle detection fails, mark as having cycles but can't list them
                            cyclical_dependencies = "Cycle detected (unable to list components)"
                            # Note: Error logging removed from stdout/stderr
                            # Errors are logged in cli.py when cycles are detected
                except Exception:  # pylint: disable=broad-exception-caught
                    pass
            
            if comp.group and comp.name and comp.version:
                # Try dependency resolver first (mvnrepository.com) as it has better data
                if dependency_resolver:
                    try:
                        license, homepage = dependency_resolver.get_license_and_homepage(
                            comp.group, comp.name, comp.version
                        )
                        if homepage:
                            homepage_url = homepage
                        if license:
                            license_type = license
                        
                        # Get external dependencies (dependencies not in original SBOM)
                        dependencies = dependency_resolver.get_dependencies(
                            comp.group, comp.name, comp.version
                        )
                        if dependencies:
                            # Count dependencies that are not in the original components
                            component_keys = {
                                f"{c.group}:{c.name}:{c.version or ''}"
                                for c in components.values()
                                if c.group and c.name
                            }
                            external_deps = [
                                dep
                                for dep in dependencies
                                if f"{dep[0]}:{dep[1]}:{dep[2]}" not in component_keys
                            ]
                            external_dependency_count = len(external_deps)
                    except Exception:  # pylint: disable=broad-exception-caught
                        pass

                # Fall back to Maven Central if dependency resolver didn't provide data
                if not homepage_url and maven_central_client:
                    try:
                        homepage, _ = maven_central_client.get_package_info(comp)
                        if homepage:
                            homepage_url = homepage
                    except Exception:  # pylint: disable=broad-exception-caught
                        pass

            return [
                idx,
                group_id,
                package_name,
                version_tag,
                purl,
                ref,
                comp_type,
                scope,
                provided_url,
                repo_url,
                dependency_count,
                pom_filename,
                auth_required,
                homepage_url,
                license_type,
                external_dependency_count,
                cyclical_dependencies,
            ]
        else:
            # Component not found, use ref as group ID
            dependency_count = 0
            cyclical_dependencies = ""
            if graph is not None and comp_ref in graph:
                try:
                    # Handle potential cycles gracefully - if graph has cycles,
                    # NetworkX may raise errors during iteration
                    predecessors = list(graph.predecessors(comp_ref))
                    dependency_count = len(predecessors)
                except (RuntimeError, ValueError) as graph_exc:
                    # NetworkX can raise RuntimeError or ValueError if graph has cycles
                    # or is modified during iteration
                    if "cycle" in str(graph_exc).lower() or "iteration" in str(graph_exc).lower():
                        # Graph has cycles - try to get count safely
                        try:
                            # Use in_degree as a safer alternative
                            dependency_count = graph.in_degree(comp_ref)
                        except Exception:  # pylint: disable=broad-exception-caught
                            dependency_count = 0
                    else:
                        dependency_count = 0
                except Exception:  # pylint: disable=broad-exception-caught
                    # Any other error - default to 0
                    dependency_count = 0

            # Detect cyclical dependencies for missing component
            if has_circular and graph is not None:
                try:
                    import networkx as nx
                    if comp_ref in graph:
                        try:
                            all_cycles = list(nx.simple_cycles(graph))
                            component_cycles = [
                                cycle for cycle in all_cycles if comp_ref in cycle
                            ]
                            if component_cycles:
                                cycle_strings = []
                                for cycle in component_cycles:
                                    cycle_str = "->".join(cycle)
                                    if len(cycle) > 1:
                                        cycle_str += f"->{cycle[0]}"
                                    cycle_strings.append(cycle_str)
                                cyclical_dependencies = "; ".join(cycle_strings)
                        except Exception:  # pylint: disable=broad-exception-caught
                            cyclical_dependencies = "Cycle detected (unable to list components)"
                except Exception:  # pylint: disable=broad-exception-caught
                    pass

            return [
                idx,
                comp_ref,
                "",
                "",
                "",  # PURL
                comp_ref,  # Ref (use comp_ref as fallback)
                "",  # Type
                "",  # Scope
                "",
                "",
                dependency_count,
                "",
                "",
                "",
                "",
                0,  # External Dependency Count
                cyclical_dependencies,
            ]


def write_dependencies_csv(
    output_path: Path,
    dependency_list: List[Tuple[str, str, str, int]],
    dependency_resolver: Optional[object] = None,
    verbose: bool = False,
) -> None:
    """
    Write a CSV file containing dependency information.

    Args:
        output_path: Path to output CSV file
        dependency_list: List of (group, artifact, version, depth) tuples
        dependency_resolver: Optional dependency resolver for fetching metadata
        verbose: Whether to print verbose output
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)

        # Write header
        writer.writerow(
            [
                "Order",
                "Group ID",
                "Package Name",
                "Version/Tag",
                "Depth",
                "Homepage URL",
                "License Type",
            ]
        )

        # Write data rows
        for idx, (group, artifact, version, depth) in enumerate(dependency_list, 1):
            homepage_url = ""
            license_type = ""

            # Fetch metadata if resolver provided
            if dependency_resolver and version:
                try:
                    license, homepage = dependency_resolver.get_license_and_homepage(
                        group, artifact, version
                    )
                    if homepage:
                        homepage_url = homepage
                    if license:
                        license_type = license
                except Exception:  # pylint: disable=broad-exception-caught
                    if verbose:
                        print(
                            f"Warning: Failed to fetch metadata for "
                            f"{group}:{artifact}:{version}",
                            file=__import__("sys").stderr,
                        )

            group_id = f"{group}:{artifact}"
            writer.writerow(
                [idx, group_id, artifact, version, depth, homepage_url, license_type]
            )


def get_formatter(format_type: str) -> OutputFormatter:
    """
    Get a formatter by type name.

    Args:
        format_type: Format type ('text' or 'json')

    Returns:
        OutputFormatter instance

    Raises:
        ValueError: If format type is not supported
    """
    formatters = {
        "text": TextFormatter(),
        "json": JSONFormatter(),
        "csv": CSVFormatter(),
    }

    if format_type.lower() not in formatters:
        raise ValueError(
            f"Unsupported format: {format_type}. "
            f"Supported formats: {', '.join(formatters.keys())}"
        )

    return formatters[format_type.lower()]
