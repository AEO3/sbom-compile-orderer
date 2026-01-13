"""
Command-line interface for SBOM Compile Order tool.
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from sbom_compile_order.dependency_resolver import DependencyResolver
from sbom_compile_order.graph import DependencyGraph
from sbom_compile_order.maven_central import MavenCentralClient
from sbom_compile_order.output import get_formatter, write_dependencies_csv
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
        help="Output file path (default: cache/compile-order.csv for CSV format, stdout for other formats)",
    )

    parser.add_argument(
        "-f",
        "--format",
        type=str,
        default="csv",
        choices=["text", "json", "csv"],
        help="Output format: text, json, or csv (default: csv)",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    parser.add_argument(
        "-i",
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
        "-c",
        "--clone-repos",
        action="store_true",
        help="Clone repositories to find POM files (default: download POMs directly via HTTP)",
    )

    parser.add_argument(
        "-m",
        "--maven-central-lookup",
        action="store_true",
        help="Look up package information from Maven Central API (homepage URL, license)",
    )

    parser.add_argument(
        "-r",
        "--resolve-dependencies",
        action="store_true",
        help="Resolve transitive dependencies from mvnrepository.com and create dependencies CSV",
    )

    parser.add_argument(
        "--dependencies-output",
        type=str,
        default=None,
        help="Filename for dependencies CSV in cache directory (default: dependencies.csv)",
    )

    parser.add_argument(
        "-e",
        "--extended-csv",
        type=str,
        default=None,
        help="Filename for extended CSV in cache directory (populated incrementally, can be tailed, default: extended.csv)",
    )

    parser.add_argument(
        "-d",
        "--max-dependency-depth",
        type=int,
        default=2,
        help="Maximum depth to traverse dependencies (default: 2)",
    )

    args = parser.parse_args()

    # Auto-enable extended-csv when resolve-dependencies is used
    if args.resolve_dependencies and not args.extended_csv:
        args.extended_csv = "extended-dependencies.csv"
        if args.verbose:
            print(
                "[DEBUG] Auto-enabled --extended-csv with default: extended-dependencies.csv",
                file=sys.stderr,
            )

    # Auto-enable maven-central-lookup when extended-csv is used
    if args.extended_csv and not args.maven_central_lookup:
        args.maven_central_lookup = True
        if args.verbose:
            print(
                "[DEBUG] Auto-enabled --maven-central-lookup (required for extended CSV)",
                file=sys.stderr,
            )

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

        # Initialize POM downloader only if explicitly requested (not for basic CSV)
        pom_downloader = None
        # POM downloading is optional - only enable if clone-repos flag is set
        # Basic CSV output works without POM downloading
        if args.clone_repos:
            pom_downloader = POMDownloader(
                cache_dir, verbose=args.verbose, clone_repos=args.clone_repos
            )
            mode = "clone repositories"
            log_msg = f"POM cache directory: {cache_dir} (mode: {mode})"
            _log_to_file(log_msg, log_file)
            if args.verbose:
                print(log_msg, file=sys.stderr)

        # Initialize Maven Central client if requested
        maven_central_client = None
        if args.maven_central_lookup or args.resolve_dependencies or args.extended_csv:
            maven_central_client = MavenCentralClient(verbose=args.verbose)
            log_msg = "Maven Central API client initialized"
            _log_to_file(log_msg, log_file)
            if args.verbose:
                print(log_msg, file=sys.stderr)

        # Initialize dependency resolver if requested
        dependency_resolver = None
        if args.resolve_dependencies:
            # Determine extended CSV path - always in cache directory
            # Note: extended_csv is auto-enabled when resolve-dependencies is used
            # Ensure extended_csv is set (should be set by auto-enable logic above)
            if not args.extended_csv:
                args.extended_csv = "extended-dependencies.csv"

            # Process extended CSV path
            extended_csv_path = None
            if args.extended_csv:
                # If user specifies a path, extract filename and place in cache dir
                user_path = Path(args.extended_csv)
                if user_path.is_absolute() or len(user_path.parts) > 1:
                    # User specified a path, extract just the filename
                    filename = user_path.name
                    extended_csv_path = cache_dir / filename
                    log_msg = (
                        f"Extended CSV filename '{filename}' will be written to cache directory: "
                        f"{extended_csv_path}"
                    )
                    _log_to_file(log_msg, log_file)
                    if args.verbose:
                        print(log_msg, file=sys.stderr)
                else:
                    # Just a filename, use it in cache dir
                    extended_csv_path = cache_dir / user_path
            else:
                # Fallback: Default to cache directory
                extended_csv_path = cache_dir / "extended-dependencies.csv"

            # Ensure extended_csv_path is set
            if not extended_csv_path:
                extended_csv_path = cache_dir / "extended-dependencies.csv"

            log_msg = f"Extended CSV will be written incrementally to: {extended_csv_path}"
            _log_to_file(log_msg, log_file)
            if args.verbose:
                print(log_msg, file=sys.stderr)

            dependency_resolver = DependencyResolver(
                verbose=args.verbose, extended_csv_path=extended_csv_path
            )
            log_msg = "Dependency resolver initialized"
            _log_to_file(log_msg, log_file)
            if args.verbose:
                print(log_msg, file=sys.stderr)

        # Format output
        formatter = get_formatter(args.format)

        # Determine output path - default to cache/compile-order.csv for CSV format
        if args.format == "csv":
            if args.output:
                output_path = Path(args.output)
            else:
                # Default output for CSV format
                output_path = cache_dir / "compile-order.csv"
            
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
                maven_central_client,
                dependency_resolver,
            )
            log_msg = f"Output written to: {output_path}"
            _log_to_file(log_msg, log_file)
            if args.verbose:
                print(log_msg, file=sys.stderr)
        else:
            # Standard formatting (all at once) for non-CSV formats
            output = formatter.format(
                order,
                components,
                has_circular,
                statistics,
                args.include_metadata,
                graph.graph if args.format == "csv" else None,
                pom_downloader,
                maven_central_client,
                dependency_resolver,
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

        # Resolve dependencies and create extended CSV if requested
        if args.resolve_dependencies and dependency_resolver:
            # Determine compile-order.csv path
            if args.format == "csv":
                if args.output:
                    compile_order_path = Path(args.output)
                else:
                    compile_order_path = cache_dir / "compile-order.csv"
            else:
                # If not CSV format, use default compile-order.csv in cache
                compile_order_path = cache_dir / "compile-order.csv"

            # Wait for compile-order.csv to be created if CSV format was used
            if args.format == "csv" and compile_order_path.exists():
                log_msg = (
                    f"Generating extended CSV from compile-order.csv: {compile_order_path}"
                )
                _log_to_file(log_msg, log_file)
                if args.verbose:
                    print(log_msg, file=sys.stderr)

                # Resolve dependencies from compile-order.csv
                dependency_resolver.resolve_from_compile_order_csv(
                    compile_order_path, max_depth=args.max_dependency_depth
                )

                # Log extended CSV information
                if dependency_resolver.extended_csv_path:
                    log_msg = (
                        f"Extended CSV written incrementally to: "
                        f"{dependency_resolver.extended_csv_path} "
                        f"({dependency_resolver._extended_csv_order} entries)"
                    )
                    _log_to_file(log_msg, log_file)
                    if args.verbose:
                        print(log_msg, file=sys.stderr)
            else:
                log_msg = (
                    f"Warning: compile-order.csv not found at {compile_order_path}. "
                    f"Extended CSV generation skipped."
                )
                _log_to_file(log_msg, log_file)
                if args.verbose:
                    print(log_msg, file=sys.stderr)

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
