"""
Command-line interface for SBOM Compile Order tool.
"""

import argparse
import json
import sys
from pathlib import Path

from sbom_compile_order.graph import DependencyGraph
from sbom_compile_order.output import get_formatter
from sbom_compile_order.parser import SBOMParser


def main() -> None:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description="Analyse CycloneDX SBOM files to determine compilation order "
        "for all dependencies including transitive dependencies.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "sbom_file",
        type=str,
        help="Path to the CycloneDX SBOM JSON file",
    )

    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="Output file path (default: stdout)",
    )

    parser.add_argument(
        "-f",
        "--format",
        type=str,
        default="text",
        choices=["text", "json", "csv"],
        help="Output format: text, json, or csv (default: text)",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    parser.add_argument(
        "--include-metadata",
        action="store_true",
        help="Include component metadata in output",
    )

    args = parser.parse_args()

    try:
        # Parse SBOM
        sbom_path = Path(args.sbom_file)
        if args.verbose:
            print(f"Parsing SBOM file: {sbom_path}", file=sys.stderr)

        sbom_parser = SBOMParser(sbom_path)
        sbom_parser.parse()

        components = sbom_parser.get_all_components()
        dependencies = sbom_parser.get_dependencies()

        if args.verbose:
            print(
                f"Found {len(components)} components and "
                f"{len(dependencies)} dependency relationships",
                file=sys.stderr,
            )

        # Build dependency graph
        if args.verbose:
            print("Building dependency graph...", file=sys.stderr)

        graph = DependencyGraph()
        graph.build_from_parser(components, dependencies)

        # Get compilation order
        if args.verbose:
            print("Determining compilation order...", file=sys.stderr)

        order, has_circular = graph.get_compilation_order()
        statistics = graph.get_statistics()

        if args.verbose:
            print(
                f"Compilation order determined: {len(order)} components",
                file=sys.stderr,
            )
            if has_circular:
                print(
                    "WARNING: Circular dependencies detected!",
                    file=sys.stderr,
                )

        # Format output
        formatter = get_formatter(args.format)
        output = formatter.format(
            order,
            components,
            has_circular,
            statistics,
            args.include_metadata,
        )

        # Write output
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as file:
                file.write(output)
            if args.verbose:
                print(f"Output written to: {output_path}", file=sys.stderr)
        else:
            print(output)

    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"Error: Invalid JSON in SBOM file: {exc}", file=sys.stderr)
        sys.exit(1)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        print(f"Unexpected error: {exc}", file=sys.stderr)
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
