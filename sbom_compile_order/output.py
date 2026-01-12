"""
Output formatters for compilation order.

Provides different output formats: text, JSON, CSV, etc.
"""

import csv
import io
import json
import re
from typing import Dict, List, Optional, TYPE_CHECKING
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
    ) -> str:
        """
        Format compilation order as CSV.

        Columns: Order, Group ID, Package Name, Version/Tag, Provided URL, Repo URL, Dependencies

        Args:
            order: List of component identifiers in compilation order
            components: Dictionary of all components
            has_circular: Whether circular dependencies were detected
            statistics: Optional graph statistics (not used in CSV)
            include_metadata: Whether to include component metadata (not used in CSV)
            graph: Optional dependency graph for counting dependencies

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
            ]
        )

        # Write data rows
        for idx, comp_ref in enumerate(order, 1):
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

                # Get provided URL (original source URL)
                provided_url = comp.source_url if hasattr(comp, "source_url") else ""

                # Extract repo URL (root git clone-able URL)
                repo_url = extract_repo_url(provided_url)

                # Count dependencies (incoming edges/predecessors)
                # In the graph, if A depends on B, edge is B -> A
                # So predecessors of A are the packages A depends on
                dependency_count = 0
                if graph is not None and comp_ref in graph:
                    try:
                        dependency_count = len(list(graph.predecessors(comp_ref)))
                    except Exception:  # pylint: disable=broad-exception-caught
                        dependency_count = 0

                writer.writerow(
                    [
                        idx,
                        group_id,
                        package_name,
                        version_tag,
                        provided_url,
                        repo_url,
                        dependency_count,
                    ]
                )
            else:
                # Component not found, use ref as group ID
                dependency_count = 0
                if graph is not None and comp_ref in graph:
                    try:
                        dependency_count = len(list(graph.predecessors(comp_ref)))
                    except Exception:  # pylint: disable=broad-exception-caught
                        dependency_count = 0
                writer.writerow([idx, comp_ref, "", "", "", "", dependency_count])

        return output.getvalue()


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
