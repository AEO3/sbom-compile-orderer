"""
Command-line interface for SBOM Compile Order tool.
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from sbom_compile_order.dependency_resolver import DependencyResolver
from sbom_compile_order.graph import DependencyGraph
from sbom_compile_order.hash_cache import HashCache
from sbom_compile_order.maven_central import MavenCentralClient
from sbom_compile_order.output import get_formatter, write_dependencies_csv
from sbom_compile_order.parser import Component, SBOMParser, extract_package_type
from sbom_compile_order.pom_downloader import POMDownloader
from sbom_compile_order.pom_dependency_extractor import POMDependencyExtractor


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
        # Ensure parent directory exists
        log_file.parent.mkdir(parents=True, exist_ok=True)
        # Open in append mode and ensure immediate flush
        with open(log_file, "a", encoding="utf-8") as log:
            log.write(log_message + "\n")
            log.flush()  # Ensure immediate write to disk
            os.fsync(log.fileno())  # Force write to disk
    except Exception as exc:  # pylint: disable=broad-exception-caught
        # Log to stderr if file logging fails
        print(f"Warning: Failed to write to log file {log_file}: {exc}", file=sys.stderr)


def _start_parallel_downloads(
    compile_order_csv_path: Path,
    pom_downloader,
    package_downloader,
    package_types: List[str],
    log_file: Path,
    verbose: bool,
    context: str,
) -> Optional["threading.Thread"]:
    """
    Start background downloads for configured POMs and artifacts.
    """
    if not pom_downloader and not package_downloader:
        return None

    from sbom_compile_order.parallel_downloader import ParallelDownloader

    download_types: List[str] = []
    if pom_downloader:
        download_types.append("POMs")
    if package_downloader and package_types:
        artifact_labels = [f"{atype.upper()}s" for atype in package_types]
        download_types.extend(artifact_labels)

    if not download_types:
        return None

    parallel_downloader = ParallelDownloader(
        compile_order_csv_path=compile_order_csv_path,
        pom_downloader=pom_downloader,
        artifact_downloader=package_downloader,
        artifact_types=package_types,
        max_workers=5,
        verbose=verbose,
        log_file=log_file,
    )

    download_types_str = " and ".join(download_types)
    log_msg = (
        f"Starting parallel background downloads ({download_types_str}) {context}"
    )
    _log_to_file(log_msg, log_file)
    if verbose:
        print(log_msg, file=sys.stderr)

    return parallel_downloader.start_background_downloads()


def _wait_for_parallel_downloads(
    parallel_download_thread: Optional["threading.Thread"],
    log_file: Path,
    verbose: bool,
) -> None:
    if not parallel_download_thread:
        return

    log_msg = "Waiting for parallel background downloads to complete..."
    _log_to_file(log_msg, log_file)
    if verbose:
        print(log_msg, file=sys.stderr)

    parallel_download_thread.join(timeout=300)

    if parallel_download_thread.is_alive():
        log_msg = "[PARALLEL DOWNLOAD] Background downloads still running (will continue in background)"
        _log_to_file(log_msg, log_file)
        if verbose:
            print(log_msg, file=sys.stderr)
    else:
        log_msg = "[PARALLEL DOWNLOAD] Background downloads completed"
        _log_to_file(log_msg, log_file)
        if verbose:
            print(log_msg, file=sys.stderr)


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
        "--exclude-types",
        type=str,
        nargs="+",
        default=[],
        help="Component types to exclude (e.g., --exclude-types library application)",
    )

    parser.add_argument(
        "--exclude-package-types",
        type=str,
        nargs="+",
        default=[],
        help="Package types to exclude (e.g., --exclude-package-types npm pypi)",
    )

    parser.add_argument(
        "-c",
        "--clone-repos",
        action="store_true",
        help="Clone repositories to find POM files",
    )

    parser.add_argument(
        "--poms",
        action="store_true",
        help="Download POM files from Maven Central",
    )

    parser.add_argument(
        "--pull-package",
        action="store_true",
        help="Download packages (JARs) from Maven Central",
    )

    parser.add_argument(
        "--jar",
        action="store_true",
        help="Download JAR artifacts when pulling packages from Maven Central",
    )

    parser.add_argument(
        "--war",
        action="store_true",
        help="Download WAR artifacts when pulling packages from Maven Central",
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

    parser.add_argument(
        "--leaves",
        action="store_true",
        help="Extract dependencies from POM files and create leaves.csv with dependencies not in compile-order.csv",
    )

    parser.add_argument(
        "--leaves-output",
        type=str,
        default=None,
        help="Filename for leaves CSV in cache directory (default: leaves.csv)",
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
    cache_dir.mkdir(parents=True, exist_ok=True)
    log_file = cache_dir / "sbom-compile-order.log"
    
    # Auto-enable maven-central-lookup when --poms is used
    if args.poms and not args.maven_central_lookup:
        args.maven_central_lookup = True
        log_msg = "[DEBUG] Auto-enabled --maven-central-lookup (required for POM downloads)"
        _log_to_file(log_msg, log_file)
        if args.verbose:
            print(log_msg, file=sys.stderr)
    
    package_types: List[str] = []
    if args.jar:
        package_types.append("jar")
    if args.war:
        package_types.append("war")

    if package_types and not args.pull_package:
        args.pull_package = True

    if args.pull_package and not package_types:
        package_types = ["jar"]

    # Auto-enable --poms and -m when --leaves is used
    if args.leaves:
        if not args.poms:
            args.poms = True
            log_msg = "[DEBUG] Auto-enabled --poms (required for leaves extraction)"
            _log_to_file(log_msg, log_file)
            if args.verbose:
                print(log_msg, file=sys.stderr)
        if not args.maven_central_lookup:
            args.maven_central_lookup = True
            log_msg = "[DEBUG] Auto-enabled --maven-central-lookup (required for leaves extraction)"
            _log_to_file(log_msg, log_file)
            if args.verbose:
                print(log_msg, file=sys.stderr)
    
    # Log program start
    log_msg = f"Starting sbom-compile-order v{__import__('sbom_compile_order').__version__}"
    _log_to_file(log_msg, log_file)
    log_msg = f"Command: {' '.join(sys.argv)}"
    _log_to_file(log_msg, log_file)
    log_msg = f"Working directory: {Path.cwd()}"
    _log_to_file(log_msg, log_file)
    log_msg = f"Cache directory: {cache_dir}"
    _log_to_file(log_msg, log_file)
    if args.verbose:
        print(f"Log file: {log_file}", file=sys.stderr)

    try:
        # Initialize hash cache for intelligent caching
        hash_cache = HashCache(cache_dir)
        
        # Parse SBOM
        sbom_path = Path(args.sbom_file)
        log_msg = f"Parsing SBOM file: {sbom_path}"
        _log_to_file(log_msg, log_file)
        if args.verbose:
            print(log_msg, file=sys.stderr)

        # Calculate and save SBOM hash
        sbom_hash = hash_cache.get_sbom_hash(sbom_path)
        if sbom_hash:
            hash_cache.save_sbom_hash(sbom_hash)
            log_msg = f"SBOM hash: {sbom_hash}"
            _log_to_file(log_msg, log_file)
            if args.verbose:
                print(log_msg, file=sys.stderr)

        sbom_parser = SBOMParser(sbom_path)
        sbom_parser.parse()
        log_msg = f"SBOM parsed successfully: {sbom_path}"
        _log_to_file(log_msg, log_file)
        if args.verbose:
            print(log_msg, file=sys.stderr)

        components = sbom_parser.get_all_components()
        dependencies = sbom_parser.get_dependencies()
        log_msg = f"Extracted {len(components)} components and {len(dependencies)} dependency entries from SBOM"
        _log_to_file(log_msg, log_file)
        if args.verbose:
            print(log_msg, file=sys.stderr)

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

        # Filter out excluded component types
        if args.exclude_types:
            excluded_types_set = set(args.exclude_types)
            original_count = len(components)
            components = {
                comp_id: comp
                for comp_id, comp in components.items()
                if comp.type not in excluded_types_set
            }
            # Also filter dependencies
            dependencies = {
                dep_ref: dep_list
                for dep_ref, dep_list in dependencies.items()
                if dep_ref in components
            }
            filtered_count = original_count - len(components)
            if filtered_count > 0:
                log_msg = f"Filtered out {filtered_count} components with excluded types: {', '.join(excluded_types_set)}"
                _log_to_file(log_msg, log_file)
                if args.verbose:
                    print(log_msg, file=sys.stderr)

        # Filter out excluded package types
        if args.exclude_package_types:
            excluded_package_types_set = set(args.exclude_package_types)
            original_count = len(components)
            components = {
                comp_id: comp
                for comp_id, comp in components.items()
                if not comp.purl or extract_package_type(comp.purl) not in excluded_package_types_set
            }
            # Also filter dependencies
            dependencies = {
                dep_ref: dep_list
                for dep_ref, dep_list in dependencies.items()
                if dep_ref in components
            }
            filtered_count = original_count - len(components)
            if filtered_count > 0:
                log_msg = f"Filtered out {filtered_count} components with excluded package types: {', '.join(excluded_package_types_set)}"
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
        log_msg = f"Dependency graph built: {graph.graph.number_of_nodes()} nodes, {graph.graph.number_of_edges()} edges"
        _log_to_file(log_msg, log_file)
        if args.verbose:
            print(log_msg, file=sys.stderr)

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
        # Log cycle detection to file (only print to stderr if verbose)
        log_msg = f"[CYCLE DETECTION] Checking for cycles: has_circular={has_circular}"
        _log_to_file(log_msg, log_file)
        if args.verbose:
            print(log_msg, file=sys.stderr)
        
        if has_circular:
            log_msg = "WARNING: Circular dependencies detected!"
            _log_to_file(log_msg, log_file)
            if args.verbose:
                print(log_msg, file=sys.stderr)
            
            # Log all cycles with package details
            try:
                import networkx as nx
                log_msg = "[CYCLE DETECTION] Attempting to detect cycles using NetworkX..."
                _log_to_file(log_msg, log_file)
                if args.verbose:
                    print(log_msg, file=sys.stderr)
                
                cycles = list(nx.simple_cycles(graph.graph))
                log_msg = f"[CYCLE DETECTION] NetworkX found {len(cycles)} cycle(s)"
                _log_to_file(log_msg, log_file)
                if args.verbose:
                    print(log_msg, file=sys.stderr)
                
                if cycles:
                    log_msg = f"[CYCLE DETECTION] Found {len(cycles)} cycle(s) in dependency graph"
                    _log_to_file(log_msg, log_file)
                    if args.verbose:
                        print(log_msg, file=sys.stderr)
                    
                    for idx, cycle in enumerate(cycles, 1):
                        cycle_str = "->".join(cycle)
                        if len(cycle) > 1:
                            cycle_str += f"->{cycle[0]}"
                        
                        # Get component names for better readability
                        cycle_packages = []
                        for comp_ref in cycle:
                            comp = components.get(comp_ref)
                            if comp:
                                package_name = f"{comp.group}:{comp.name}" if comp.group else comp.name
                                cycle_packages.append(f"{package_name} ({comp_ref})")
                            else:
                                cycle_packages.append(f"UNKNOWN ({comp_ref})")
                        
                        log_msg = (
                            f"[CYCLE DETECTION] Cycle {idx}: {cycle_str} | "
                            f"Packages: {', '.join(cycle_packages)}"
                        )
                        _log_to_file(log_msg, log_file)
                        if args.verbose:
                            print(log_msg, file=sys.stderr)
                else:
                    log_msg = "[CYCLE DETECTION] No cycles found by NetworkX (but has_circular=True)"
                    _log_to_file(log_msg, log_file)
                    if args.verbose:
                        print(log_msg, file=sys.stderr)
            except Exception as cycle_exc:  # pylint: disable=broad-exception-caught
                import traceback
                tb_str = traceback.format_exc()
                log_msg = f"[CYCLE DETECTION] Error detecting cycles: {cycle_exc}"
                _log_to_file(log_msg, log_file)
                if args.verbose:
                    print(log_msg, file=sys.stderr)
                log_msg = f"[CYCLE DETECTION] Traceback: {tb_str}"
                _log_to_file(log_msg, log_file)
                if args.verbose:
                    print(log_msg, file=sys.stderr)
        else:
            log_msg = "[CYCLE DETECTION] No circular dependencies detected (has_circular=False)"
            _log_to_file(log_msg, log_file)
            if args.verbose:
                print(log_msg, file=sys.stderr)

        # Initialize POM downloader if requested
        pom_downloader = None
        if args.clone_repos or args.poms:
            pom_downloader = POMDownloader(
                cache_dir,
                verbose=args.verbose,
                clone_repos=args.clone_repos,
                download_from_maven_central=args.poms,
            )
            mode = "clone repositories" if args.clone_repos else "Maven Central"
            log_msg = f"POM cache directory: {cache_dir} (mode: {mode})"
            _log_to_file(log_msg, log_file)
            if args.verbose:
                print(log_msg, file=sys.stderr)

        # Initialize package (JAR) downloader if requested
        package_downloader = None
        if args.pull_package:
            from sbom_compile_order.package_downloader import PackageDownloader

            package_downloader = PackageDownloader(
                cache_dir, verbose=args.verbose
            )
            if not hasattr(package_downloader, "log_file"):
                package_downloader.log_file = log_file
            log_msg = f"Package downloader initialized: {cache_dir}"
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
        log_msg = f"Formatting output as: {args.format}"
        _log_to_file(log_msg, log_file)
        if args.verbose:
            print(log_msg, file=sys.stderr)
        
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
            
            log_msg = f"Processing {len(order)} components for CSV output"
            _log_to_file(log_msg, log_file)
            if args.verbose:
                print(log_msg, file=sys.stderr)
            
            # Log POM download start if POM downloader is active
            if pom_downloader:
                if pom_downloader.download_from_maven_central:
                    log_msg = (
                        f"POM download enabled: Will download POM files from Maven Central "
                        f"for {len(order)} components"
                    )
                    _log_to_file(log_msg, log_file)
                    if args.verbose:
                        print(log_msg, file=sys.stderr)
                elif pom_downloader.clone_repos:
                    log_msg = (
                        f"POM download enabled: Will clone repositories to find POM files "
                        f"for {len(order)} components"
                    )
                    _log_to_file(log_msg, log_file)
                    if args.verbose:
                        print(log_msg, file=sys.stderr)
            
            # Check if compile-order.csv needs to be regenerated
            compile_order_needs_regen = True
            if output_path.exists():
                cached_sbom_hash = hash_cache.get_cached_sbom_hash()
                if sbom_hash and cached_sbom_hash:
                    sbom_match_msg = (
                        "match"
                        if sbom_hash == cached_sbom_hash
                        else "mismatch"
                    )
                    log_msg = (
                        f"SBOM hash found ({sbom_hash}); cached hash {sbom_match_msg}"
                        f" (cached: {cached_sbom_hash})"
                    )
                    _log_to_file(log_msg, log_file)
                    if args.verbose:
                        print(log_msg, file=sys.stderr)
                if sbom_hash and cached_sbom_hash and sbom_hash == cached_sbom_hash:
                    # SBOM unchanged, check if compile-order.csv hash matches
                    compile_order_hash = hash_cache.get_compile_order_hash(output_path)
                    cached_compile_order_hash = hash_cache.get_cached_compile_order_hash()
                    if compile_order_hash and cached_compile_order_hash:
                        compile_status = (
                            "matches" if compile_order_hash == cached_compile_order_hash else "differs"
                        )
                        log_msg = (
                            f"Compile-order hash {compile_status} cached hash "
                            f"({compile_order_hash} vs {cached_compile_order_hash})"
                        )
                        _log_to_file(log_msg, log_file)
                        if args.verbose:
                            print(log_msg, file=sys.stderr)
                    if compile_order_hash and cached_compile_order_hash and compile_order_hash == cached_compile_order_hash:
                        log_msg = (
                            f"SBOM and compile-order.csv unchanged (hash match), "
                            f"skipping compile-order.csv regeneration"
                        )
                        _log_to_file(log_msg, log_file)
                        if args.verbose:
                            print(log_msg, file=sys.stderr)
                        compile_order_needs_regen = False
                    else:
                        log_msg = (
                            f"SBOM unchanged but compile-order.csv changed, "
                            f"regenerating compile-order.csv"
                        )
                        _log_to_file(log_msg, log_file)
                        if args.verbose:
                            print(log_msg, file=sys.stderr)
                else:
                    log_msg = "SBOM changed, regenerating compile-order.csv"
                    _log_to_file(log_msg, log_file)
                    if args.verbose:
                        print(log_msg, file=sys.stderr)

            # Create compile-order.csv WITHOUT Maven Central lookups or POM downloads
            # This file is written once and never modified again
            # Pass None for pom_downloader, maven_central_client and dependency_resolver to skip lookups
            if compile_order_needs_regen:
                log_msg = "Creating compile-order.csv (base file, no Maven Central lookups, no POM downloads)"
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
                    None,  # No POM downloads for compile-order.csv - all enhanced data goes to enhanced.csv
                    None,  # No Maven Central lookups for compile-order.csv
                    None,  # No dependency resolver for compile-order.csv
                )
                
                # Save compile-order.csv hash
                compile_order_hash = hash_cache.get_compile_order_hash(output_path)
                if compile_order_hash:
                    hash_cache.save_compile_order_hash(compile_order_hash)
                
                log_msg = f"compile-order.csv written successfully: {output_path} ({len(order)} rows) - file is now static"
                _log_to_file(log_msg, log_file)
                if args.verbose:
                    print(log_msg, file=sys.stderr)
            else:
                log_msg = f"Using existing compile-order.csv: {output_path}"
                _log_to_file(log_msg, log_file)
                if args.verbose:
                    print(log_msg, file=sys.stderr)

            # Create enhanced CSV if Maven Central lookup is requested
            # This reads from compile-order.csv and writes incrementally to enhanced.csv
            # All enhanced data (Maven Central lookups, POM downloads) goes here, NOT in compile-order.csv
            if args.maven_central_lookup and maven_central_client:
                from sbom_compile_order.enhanced_csv import create_enhanced_csv

                # Determine compile-order.csv path (same as output_path)
                compile_order_path = output_path
                enhanced_csv_path = cache_dir / "enhanced.csv"

                # Check if enhanced.csv needs regeneration
                enhanced_needs_regen = True
                if enhanced_csv_path.exists() and compile_order_path.exists():
                    # Check if compile-order.csv hash matches cached hash
                    compile_order_hash = hash_cache.get_compile_order_hash(compile_order_path)
                    cached_compile_order_hash = hash_cache.get_cached_compile_order_hash()
                    if compile_order_hash and cached_compile_order_hash and compile_order_hash == cached_compile_order_hash:
                        # compile-order.csv unchanged, check if enhanced.csv needs incremental update
                        # Enhanced CSV should be updated incrementally (e.g., POM/JAR download status)
                        log_msg = (
                            f"compile-order.csv unchanged, enhanced.csv will be updated incrementally "
                            f"if needed (e.g., POM/JAR download status)"
                        )
                        _log_to_file(log_msg, log_file)
                        if args.verbose:
                            print(log_msg, file=sys.stderr)
                        # Still need to process for incremental updates
                    else:
                        log_msg = "compile-order.csv changed, regenerating enhanced.csv"
                        _log_to_file(log_msg, log_file)
                        if args.verbose:
                            print(log_msg, file=sys.stderr)

                log_msg = (
                    f"Creating/updating enhanced CSV from compile-order.csv: {compile_order_path}"
                )
                _log_to_file(log_msg, log_file)
                if args.verbose:
                    print(log_msg, file=sys.stderr)
                
                # Start parallel background downloads if requested
                parallel_download_thread = _start_parallel_downloads(
                    compile_order_path,
                    pom_downloader if args.poms else None,
                    package_downloader if args.pull_package else None,
                    package_types if args.pull_package else [],
                    log_file,
                    args.verbose,
                    "while enhanced.csv is being created",
                )
                
                # Pass pom_downloader to enhanced CSV so POM downloads happen there, not in compile-order.csv
                # Also pass hash_cache for incremental updates
                # Note: Enhanced CSV will still do downloads sequentially, but parallel downloads
                # run in background and will be available when enhanced CSV checks for them
                create_enhanced_csv(
                    compile_order_path,
                    enhanced_csv_path,
                    maven_central_client,
                    pom_downloader=pom_downloader,  # POM downloads happen in enhanced.csv
                    verbose=args.verbose,
                    log_file=log_file,
                    hash_cache=hash_cache,  # Pass hash cache for incremental updates
                )
                
                _wait_for_parallel_downloads(parallel_download_thread, log_file, args.verbose)
                
                # Save enhanced.csv hash after creation/update
                enhanced_hash = hash_cache.get_enhanced_hash(enhanced_csv_path)
                if enhanced_hash:
                    hash_cache.save_enhanced_hash(enhanced_hash)

                log_msg = f"Enhanced CSV created: {enhanced_csv_path}"
                _log_to_file(log_msg, log_file)
                if args.verbose:
                    print(log_msg, file=sys.stderr)
                
                # Log POM download summary after enhanced CSV creation (where POM downloads actually happen)
                if pom_downloader:
                    pom_cache_dir = cache_dir / "poms"
                    if pom_cache_dir.exists():
                        pom_files = list(pom_cache_dir.glob("*.pom"))
                        pom_count = len(pom_files)
                        log_msg = (
                            f"POM download summary: {pom_count} POM file(s) cached in "
                            f"{pom_cache_dir} (out of {len(order)} components processed)"
                        )
                        _log_to_file(log_msg, log_file)
                        if args.verbose:
                            print(log_msg, file=sys.stderr)
                    else:
                        log_msg = (
                            f"POM download summary: No POM files were downloaded "
                            f"(out of {len(order)} components processed)"
                        )
                        _log_to_file(log_msg, log_file)
                        if args.verbose:
                            print(log_msg, file=sys.stderr)

        # Start package downloads when Maven lookups are not requested but --pull-package is set
        if args.pull_package and not args.maven_central_lookup:
            package_download_thread = _start_parallel_downloads(
                output_path,
                None,
                package_downloader,
                package_types,
                log_file,
                args.verbose,
                "after compile-order.csv creation",
            )
            _wait_for_parallel_downloads(package_download_thread, log_file, args.verbose)

            # STUBBED OUT: Package download functionality disabled
            # if package_downloader:
            #     log_msg = "Downloading packages from Maven Central..."
            #     _log_to_file(log_msg, log_file)
            #     if args.verbose:
            #         print(log_msg, file=sys.stderr)
            #     downloaded_count = 0
            #     failed_count = 0
            #     for comp_ref in order:
            #         comp = components.get(comp_ref)
            #         if comp:
            #             try:
            #                 jar_filename, auth_req = package_downloader.download_package(comp)
            #                 if jar_filename:
            #                     downloaded_count += 1
            #                     log_msg = f"Downloaded package: {jar_filename} for {comp.group}:{comp.name}:{comp.version}"
            #                     _log_to_file(log_msg, log_file)
            #                     if args.verbose:
            #                         print(log_msg, file=sys.stderr)
            #                 elif auth_req:
            #                     log_msg = f"Authentication required for {comp.group}:{comp.name}:{comp.version}"
            #                     _log_to_file(log_msg, log_file)
            #                     if args.verbose:
            #                         print(log_msg, file=sys.stderr)
            #             except Exception as exc:  # pylint: disable=broad-exception-caught
            #                 failed_count += 1
            #                 log_msg = f"Failed to download package for {comp.group}:{comp.name}:{comp.version}: {exc}"
            #                 _log_to_file(log_msg, log_file)
            #                 if args.verbose:
            #                     print(log_msg, file=sys.stderr)
            #     log_msg = f"Package download completed: {downloaded_count} downloaded, {failed_count} failed"
            #     _log_to_file(log_msg, log_file)
            #     if args.verbose:
            #         print(log_msg, file=sys.stderr)
        else:
            # Standard formatting (all at once) for non-CSV formats
            log_msg = f"Formatting {len(order)} components as {args.format}"
            _log_to_file(log_msg, log_file)
            if args.verbose:
                print(log_msg, file=sys.stderr)
            
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
                log_msg = f"Writing {args.format} output to: {output_path}"
                _log_to_file(log_msg, log_file)
                if args.verbose:
                    print(log_msg, file=sys.stderr)
                with open(output_path, "w", encoding="utf-8") as file:
                    file.write(output)
                log_msg = f"Output written successfully: {output_path}"
                _log_to_file(log_msg, log_file)
                if args.verbose:
                    print(log_msg, file=sys.stderr)
            else:
                log_msg = "Writing output to stdout"
                _log_to_file(log_msg, log_file)
                print(output)

        # Resolve dependencies and create extended CSV if requested
        # This happens AFTER compile-order.csv is created
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

            # Ensure compile-order.csv exists before processing extended CSV
            if compile_order_path.exists():
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
                    f"Extended CSV generation skipped. "
                    f"Ensure CSV format is used to generate compile-order.csv first."
                )
                _log_to_file(log_msg, log_file)
                if args.verbose:
                    print(log_msg, file=sys.stderr)

        # Process leaves extraction if requested
        if args.leaves:
            # Determine compile-order.csv path
            if args.format == "csv":
                if args.output:
                    compile_order_path = Path(args.output)
                else:
                    compile_order_path = cache_dir / "compile-order.csv"
            else:
                # If not CSV format, use default compile-order.csv in cache
                compile_order_path = cache_dir / "compile-order.csv"

            # Determine leaves.csv path
            leaves_csv_path = None
            if args.leaves_output:
                user_path = Path(args.leaves_output)
                if user_path.is_absolute() or len(user_path.parts) > 1:
                    filename = user_path.name
                    leaves_csv_path = cache_dir / filename
                else:
                    leaves_csv_path = cache_dir / user_path
            else:
                leaves_csv_path = cache_dir / "leaves.csv"

            log_msg = f"Extracting dependencies from POM files and creating leaves.csv: {leaves_csv_path}"
            _log_to_file(log_msg, log_file)
            if args.verbose:
                print(log_msg, file=sys.stderr)

            # Ensure compile-order.csv exists
            if not compile_order_path.exists():
                log_msg = (
                    f"Warning: compile-order.csv not found at {compile_order_path}. "
                    f"Leaves extraction skipped. "
                    f"Ensure CSV format is used to generate compile-order.csv first."
                )
                _log_to_file(log_msg, log_file)
                if args.verbose:
                    print(log_msg, file=sys.stderr)
            else:
                # Initialize POM dependency extractor
                extractor = POMDependencyExtractor(cache_dir, verbose=args.verbose)

                # Step 1: Check if POMs have been downloaded, if not download them first
                pom_cache_dir = cache_dir / "poms"
                pom_files_exist = pom_cache_dir.exists() and len(list(pom_cache_dir.glob("*.pom"))) > 0

                if not pom_files_exist:
                    log_msg = "No POM files found in cache. Downloading POMs for compile-order.csv entries..."
                    _log_to_file(log_msg, log_file)
                    if args.verbose:
                        print(log_msg, file=sys.stderr)

                    # Initialize POM downloader for compile-order.csv entries
                    compile_order_pom_downloader = POMDownloader(
                        cache_dir,
                        verbose=args.verbose,
                        clone_repos=False,
                        download_from_maven_central=True,
                    )

                    # Download POMs for all entries in compile-order.csv
                    downloaded_count = extractor.download_poms_for_compile_order(
                        compile_order_path, compile_order_pom_downloader
                    )
                    log_msg = f"Downloaded {downloaded_count} POM files from compile-order.csv"
                    _log_to_file(log_msg, log_file)
                    if args.verbose:
                        print(log_msg, file=sys.stderr)
                else:
                    pom_count = len(list(pom_cache_dir.glob("*.pom")))
                    log_msg = f"Found {pom_count} existing POM files in cache. Skipping initial download."
                    _log_to_file(log_msg, log_file)
                    if args.verbose:
                        print(log_msg, file=sys.stderr)

                # Initialize POM downloader for downloading POMs of new dependencies
                leaves_pom_downloader = POMDownloader(
                    cache_dir,
                    verbose=args.verbose,
                    clone_repos=False,
                    download_from_maven_central=True,
                )

                # Load dependencies from compile-order.csv (needed for comparison)
                log_msg = f"Loading dependencies from compile-order.csv: {compile_order_path}"
                _log_to_file(log_msg, log_file)
                if args.verbose:
                    print(log_msg, file=sys.stderr)

                compile_order_deps = extractor.load_compile_order_dependencies(compile_order_path)

                # Iterative process: extract dependencies, find new ones, download POMs, repeat
                iteration = 0
                max_iterations = 20  # Prevent infinite loops
                all_new_dependencies: List[POMDependency] = []
                processed_dep_ids: Set[str] = set()

                while iteration < max_iterations:
                    iteration += 1
                    log_msg = f"=== Iteration {iteration}: Extracting dependencies from POM files ==="
                    _log_to_file(log_msg, log_file)
                    if args.verbose:
                        print(log_msg, file=sys.stderr)

                    # Step 2: Extract all dependencies from POM files (including newly downloaded ones)
                    pom_dependencies = extractor.extract_all_dependencies(recursive=False)

                    # Find new dependencies not in compile-order.csv
                    log_msg = "Comparing POM dependencies with compile-order.csv..."
                    _log_to_file(log_msg, log_file)
                    if args.verbose:
                        print(log_msg, file=sys.stderr)

                    new_dependencies = extractor.find_new_dependencies(pom_dependencies, compile_order_deps)

                    # Filter out already processed dependencies
                    new_dependencies = [
                        dep
                        for dep in new_dependencies
                        if dep.get_identifier() not in processed_dep_ids
                    ]

                    if not new_dependencies:
                        log_msg = "No new dependencies found. Process complete."
                        _log_to_file(log_msg, log_file)
                        if args.verbose:
                            print(log_msg, file=sys.stderr)
                        break

                    log_msg = f"Found {len(new_dependencies)} new dependencies in iteration {iteration}"
                    _log_to_file(log_msg, log_file)
                    if args.verbose:
                        print(log_msg, file=sys.stderr)

                    # Download POMs for new dependencies
                    log_msg = f"Downloading POMs for {len(new_dependencies)} new dependencies..."
                    _log_to_file(log_msg, log_file)
                    if args.verbose:
                        print(log_msg, file=sys.stderr)

                    downloaded_in_iteration = 0
                    for dep in new_dependencies:
                        dep_id = dep.get_identifier()
                        if dep_id in processed_dep_ids:
                            continue

                        if dep.version and "${" not in dep.version:
                            component = Component(
                                {
                                    "bom-ref": f"pkg:maven/{dep.group_id}/{dep.artifact_id}@{dep.version}?type=jar",
                                    "group": dep.group_id,
                                    "name": dep.artifact_id,
                                    "version": dep.version,
                                    "purl": f"pkg:maven/{dep.group_id}/{dep.artifact_id}@{dep.version}?type=jar",
                                    "type": "library",
                                    "scope": dep.scope,
                                }
                            )

                            pom_filename, _ = leaves_pom_downloader.download_pom(component)
                            if pom_filename:
                                downloaded_in_iteration += 1
                                log_msg = f"  Downloaded POM for {dep_id}: {pom_filename}"
                                _log_to_file(log_msg, log_file)
                                if args.verbose:
                                    print(log_msg, file=sys.stderr)

                        processed_dep_ids.add(dep_id)
                        all_new_dependencies.append(dep)

                    log_msg = f"Downloaded {downloaded_in_iteration} POM files in iteration {iteration}"
                    _log_to_file(log_msg, log_file)
                    if args.verbose:
                        print(log_msg, file=sys.stderr)

                    # Continue to next iteration to process newly downloaded POMs

                # Create leaves.csv with all found dependencies
                log_msg = f"Creating leaves.csv with {len(all_new_dependencies)} total new dependencies..."
                _log_to_file(log_msg, log_file)
                if args.verbose:
                    print(log_msg, file=sys.stderr)

                extractor.create_leaves_csv(
                    all_new_dependencies,
                    leaves_csv_path,
                    pom_downloader=None,  # POMs already downloaded
                    recursive=False,  # Already processed recursively
                    compile_order_deps=compile_order_deps,
                )

                log_msg = f"Leaves CSV created successfully: {leaves_csv_path} ({len(new_dependencies)} entries)"
                _log_to_file(log_msg, log_file)
                if args.verbose:
                    print(log_msg, file=sys.stderr)

        # Log completion
        log_msg = "Processing completed successfully"
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
