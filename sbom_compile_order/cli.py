"""
Command-line interface for SBOM Compile Order tool.
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from sbom_compile_order.graph import DependencyGraph
from sbom_compile_order.output import get_formatter
from sbom_compile_order.parser import SBOMParser
from sbom_compile_order.pom_downloader import POMDownloader


def _log_to_file(message: str, log_file: Path) -> None:
    """
    Write a message to the log file.

    Args:
        message: Message to log
        log_file: Path to log file
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] {message}"
    try:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with open(log_file, "a", encoding="utf-8") as log:
            log.write(log_message + "\n")
    except Exception:  # pylint: disable=broad-exception-caught
        pass  # Silently fail if log file can't be written


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

    parser.add_argument(
        "--ignore-group-ids",
        type=str,
        nargs="+",
        default=[],
        help="Group IDs to ignore (e.g., --ignore-group-ids com.example org.test)",
    )

    parser.add_argument(
        "--clone-repos",
        action="store_true",
        help="Clone repositories to find POM files (default: download POMs directly via HTTP)",
    )

    args = parser.parse_args()

    # Set up cache directory in current working directory
    cache_dir = Path.cwd() / "cache"
    log_file = cache_dir / "sbom-compile-order.log"

    try:
        # Parse SBOM
        sbom_path = Path(args.sbom_file)
        log_msg = f"Parsing SBOM file: {sbom_path}"
        _log_to_file(log_msg, log_file)
        if args.verbose:
            print(log_msg, file=sys.stderr)

        sbom_parser = SBOMParser(sbom_path)
        sbom_parser.parse()

        components = sbom_parser.get_all_components()
        dependencies = sbom_parser.get_dependencies()

        # Filter out ignored group IDs
        if args.ignore_group_ids:
            ignored_set = set(args.ignore_group_ids)
            original_count = len(components)
            components = {
                comp_id: comp
                for comp_id, comp in components.items()
                if not comp.group or comp.group not in ignored_set
            }
            # Also filter dependencies
            dependencies = {
                dep_ref: dep_list
                for dep_ref, dep_list in dependencies.items()
                if dep_ref in components
            }
            filtered_count = original_count - len(components)
            if filtered_count > 0:
                log_msg = f"Filtered out {filtered_count} components with ignored group IDs: {', '.join(ignored_set)}"
                _log_to_file(log_msg, log_file)
                if args.verbose:
                    print(log_msg, file=sys.stderr)

        log_msg = (
            f"Found {len(components)} components and "
            f"{len(dependencies)} dependency relationships"
        )
        _log_to_file(log_msg, log_file)
        if args.verbose:
            print(log_msg, file=sys.stderr)

        # Build dependency graph
        log_msg = "Building dependency graph..."
        _log_to_file(log_msg, log_file)
        if args.verbose:
            print(log_msg, file=sys.stderr)

        graph = DependencyGraph()
        graph.build_from_parser(components, dependencies)

        # Get compilation order
        log_msg = "Determining compilation order..."
        _log_to_file(log_msg, log_file)
        if args.verbose:
            print(log_msg, file=sys.stderr)

        order, has_circular = graph.get_compilation_order()
        statistics = graph.get_statistics()

        log_msg = f"Compilation order determined: {len(order)} components"
        _log_to_file(log_msg, log_file)
        if args.verbose:
            print(log_msg, file=sys.stderr)
        if has_circular:
            log_msg = "WARNING: Circular dependencies detected!"
            _log_to_file(log_msg, log_file)
            if args.verbose:
                print(log_msg, file=sys.stderr)

        # Initialize POM downloader for CSV format
        pom_downloader = None
        if args.format == "csv":
            pom_downloader = POMDownloader(
                cache_dir, verbose=args.verbose, clone_repos=args.clone_repos
            )
            mode = "clone repositories" if args.clone_repos else "download POMs directly"
            log_msg = f"POM cache directory: {cache_dir} (mode: {mode})"
            _log_to_file(log_msg, log_file)
            if args.verbose:
                print(log_msg, file=sys.stderr)

        # Format output
        formatter = get_formatter(args.format)

        # For CSV format with output file, use incremental writing
        if args.format == "csv" and args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            log_msg = f"Writing CSV incrementally to: {output_path}"
            _log_to_file(log_msg, log_file)
            if args.verbose:
                print(log_msg, file=sys.stderr)
            formatter.format_incremental(
                output_path,
                order,
                components,
                has_circular,
                statistics,
                args.include_metadata,
                graph.graph,
                pom_downloader,
            )
            log_msg = f"Output written to: {output_path}"
            _log_to_file(log_msg, log_file)
            if args.verbose:
                print(log_msg, file=sys.stderr)
        else:
            # Standard formatting (all at once)
            output = formatter.format(
                order,
                components,
                has_circular,
                statistics,
                args.include_metadata,
                graph.graph if args.format == "csv" else None,
                pom_downloader,
            )

            # Write output
            if args.output:
                output_path = Path(args.output)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                with open(output_path, "w", encoding="utf-8") as file:
                    file.write(output)
                log_msg = f"Output written to: {output_path}"
                _log_to_file(log_msg, log_file)
                if args.verbose:
                    print(log_msg, file=sys.stderr)
            else:
                print(output)

    except FileNotFoundError as exc:
        error_msg = f"Error: {exc}"
        _log_to_file(error_msg, log_file)
        print(error_msg, file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        error_msg = f"Error: Invalid JSON in SBOM file: {exc}"
        _log_to_file(error_msg, log_file)
        print(error_msg, file=sys.stderr)
        sys.exit(1)
    except ValueError as exc:
        error_msg = f"Error: {exc}"
        _log_to_file(error_msg, log_file)
        print(error_msg, file=sys.stderr)
        sys.exit(1)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        error_msg = f"Unexpected error: {exc}"
        _log_to_file(error_msg, log_file)
        print(error_msg, file=sys.stderr)
        if args.verbose:
            import traceback

            traceback_str = traceback.format_exc()
            _log_to_file(traceback_str, log_file)
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
