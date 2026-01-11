"""
Output formatters for compilation order.

Provides different output formats: text, JSON, CSV, etc.
"""

import csv
import io
import json
from typing import Dict, List, Optional

from sbom_compile_order.parser import Component


class OutputFormatter:
    """Base class for output formatters."""

    def format(
        self,
        order: List[str],
        components: Dict[str, Component],
        has_circular: bool,
        statistics: Optional[Dict] = None,
        include_metadata: bool = False,
    ) -> str:
        """
        Format the compilation order.

        Args:
            order: List of component identifiers in compilation order
            components: Dictionary of all components
            has_circular: Whether circular dependencies were detected
            statistics: Optional graph statistics
            include_metadata: Whether to include component metadata

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
    ) -> str:
        """
        Format compilation order as text.

        Args:
            order: List of component identifiers in compilation order
            components: Dictionary of all components
            has_circular: Whether circular dependencies were detected
            statistics: Optional graph statistics
            include_metadata: Whether to include component metadata

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
    ) -> str:
        """
        Format compilation order as JSON.

        Args:
            order: List of component identifiers in compilation order
            components: Dictionary of all components
            has_circular: Whether circular dependencies were detected
            statistics: Optional graph statistics
            include_metadata: Whether to include component metadata

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
    ) -> str:
        """
        Format compilation order as CSV.

        Columns: Order, Group ID, Package Name, Version/Tag, Source URL

        Args:
            order: List of component identifiers in compilation order
            components: Dictionary of all components
            has_circular: Whether circular dependencies were detected
            statistics: Optional graph statistics (not used in CSV)
            include_metadata: Whether to include component metadata (not used in CSV)

        Returns:
            Formatted CSV string
        """
        output = io.StringIO()
        writer = csv.writer(output)

        # Write header
        writer.writerow(["Order", "Group ID", "Package Name", "Version/Tag", "Source URL"])

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

                # Get source URL
                source_url = comp.source_url if hasattr(comp, "source_url") else ""

                writer.writerow([idx, group_id, package_name, version_tag, source_url])
            else:
                # Component not found, use ref as group ID
                writer.writerow([idx, comp_ref, "", "", ""])

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
