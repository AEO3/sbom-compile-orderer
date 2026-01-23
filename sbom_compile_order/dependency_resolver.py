"""
Dependency resolver for fetching transitive dependencies from mvnrepository.com.

Provides functionality to fetch dependencies for Maven packages and create
a comprehensive dependency list including transitive dependencies.
"""

import csv
import os
import re
import sys
import time

# Allow CSV fields larger than default 128KB (e.g. long PURLs, dependency lists in SBOMs)
csv.field_size_limit(sys.maxsize)
from html.parser import HTMLParser
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import quote
from urllib.request import Request, urlopen

from sbom_compile_order import __version__
from sbom_compile_order.parser import Component


class MvnRepositoryDependencyParser(HTMLParser):
    """
    HTML parser for extracting dependency information from mvnrepository.com.
    """

    def __init__(self) -> None:
        """Initialize the parser."""
        super().__init__()
        self.dependencies: List[Tuple[str, str, str]] = []  # (group, artifact, version)
        self.in_dependency_table = False
        self.in_dependency_row = False
        self.current_cells: List[str] = []
        self.in_link = False
        self.link_href = ""

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        """
        Handle HTML start tags.

        Args:
            tag: HTML tag name
            attrs: List of (name, value) tuples for tag attributes
        """
        if tag == "table":
            # Check if this is the dependencies table
            for attr_name, attr_value in attrs:
                if attr_name == "class" and attr_value:
                    class_value = attr_value.lower()
                    if "dependencies" in class_value or "versions" in class_value:
                        self.in_dependency_table = True
                        break

        if self.in_dependency_table and tag == "tr":
            # Skip header rows
            for attr_name, attr_value in attrs:
                if attr_name == "class" and attr_value and "header" in attr_value.lower():
                    return
            self.in_dependency_row = True
            self.current_cells = []

        if self.in_dependency_row and tag == "a":
            self.in_link = True
            # Extract href attribute
            for attr_name, attr_value in attrs:
                if attr_name == "href" and attr_value:
                    self.link_href = attr_value
                    # Try to extract group:artifact:version from href
                    # Format: /artifact/group/artifact/version
                    match = re.match(r"/artifact/([^/]+)/([^/]+)(?:/([^/]+))?", attr_value)
                    if match:
                        group = match.group(1)
                        artifact = match.group(2)
                        version = match.group(3) if match.group(3) else ""
                        if group and artifact:
                            self.dependencies.append((group, artifact, version))

        if self.in_dependency_row and tag in ["td", "th"]:
            self.current_cells.append("")

    def handle_endtag(self, tag: str) -> None:
        """
        Handle HTML end tags.

        Args:
            tag: HTML tag name
        """
        if tag == "a":
            self.in_link = False
            self.link_href = ""

        if tag == "table" and self.in_dependency_table:
            self.in_dependency_table = False

        if tag == "tr" and self.in_dependency_row:
            # Also try to extract from cell text if we didn't get it from links
            if self.current_cells:
                dependency_text = " ".join(self.current_cells)
                # Look for group:artifact:version pattern
                match = re.search(
                    r"([a-zA-Z0-9_.-]+):([a-zA-Z0-9_.-]+)(?::([a-zA-Z0-9_.-]+))?",
                    dependency_text,
                )
                if match:
                    group = match.group(1)
                    artifact = match.group(2)
                    version = match.group(3) if match.group(3) else ""
                    if group and artifact:
                        # Check if we already added this dependency
                        dep_key = f"{group}:{artifact}:{version}"
                        existing_keys = {f"{g}:{a}:{v}" for g, a, v in self.dependencies}
                        if dep_key not in existing_keys:
                            self.dependencies.append((group, artifact, version))
            self.in_dependency_row = False
            self.current_cells = []

    def handle_data(self, data: str) -> None:
        """
        Handle text data within HTML tags.

        Args:
            data: Text content
        """
        if self.in_dependency_row and self.current_cells:
            # Append data to the last cell
            if self.current_cells:
                self.current_cells[-1] += data.strip()


class DependencyResolver:
    """
    Resolver for fetching dependencies from mvnrepository.com.

    Provides methods to fetch dependencies for Maven packages recursively.
    """

    BASE_URL = "https://mvnrepository.com/artifact"
    RATE_LIMIT_DELAY = 0.5  # Delay between requests in seconds

    def __init__(self, verbose: bool = False, extended_csv_path: Optional[Path] = None) -> None:
        """
        Initialize the dependency resolver.

        Args:
            verbose: Whether to print verbose output
            extended_csv_path: Optional path to extended CSV file for incremental writing
        """
        self.verbose = verbose
        self._last_request_time = 0.0
        try:
            self._rate_limit_delay = float(os.environ.get("SBOM_RATE_LIMIT_MVNREPO_SEC", "0.5"))
        except (TypeError, ValueError):
            self._rate_limit_delay = self.RATE_LIMIT_DELAY
        self._cache: Dict[str, List[Tuple[str, str, str]]] = {}
        self._visited: Set[str] = set()
        self.extended_csv_path = extended_csv_path
        self._extended_csv_file = None
        self._extended_csv_writer = None
        self._extended_csv_order = 0
        self._extended_csv_header_written = False

        # Initialize extended CSV file if path provided
        # Don't initialize here - will be initialized when needed
        # This allows us to control overwrite behavior per use case

    def _init_extended_csv(self, overwrite: bool = True) -> None:
        """
        Initialize the extended CSV file with header.

        Args:
            overwrite: If True, overwrite existing file. If False, append to existing file.
        """
        if not self.extended_csv_path:
            return

        try:
            self.extended_csv_path.parent.mkdir(parents=True, exist_ok=True)
            file_exists = self.extended_csv_path.exists()

            # Open in write mode (overwrite) or append mode based on parameter
            mode = "w" if overwrite else "a"
            self._extended_csv_file = open(
                self.extended_csv_path, mode, encoding="utf-8", newline=""
            )
            self._extended_csv_writer = csv.writer(self._extended_csv_file)

            # Write header if new file or overwriting
            if not file_exists or overwrite:
                self._extended_csv_writer.writerow(
                    [
                        "Order",
                        "Group ID",
                        "Package Name",
                        "Version/Tag",
                        "Depth",
                        "Homepage URL",
                        "License Type",
                        "Status",
                        "Original Package",
                    ]
                )
                self._extended_csv_file.flush()
                self._extended_csv_header_written = True
                self._extended_csv_order = 0
                if self.verbose:
                    print(
                        f"[DEBUG] Extended CSV header written to: {self.extended_csv_path}",
                        file=sys.stderr,
                    )
            else:
                # File exists and we're appending, find the last order number
                if self.verbose:
                    print(
                        f"[DEBUG] Extended CSV file exists, appending to: {self.extended_csv_path}",
                        file=sys.stderr,
                    )
                # Read existing file to find last order number
                with open(self.extended_csv_path, "r", encoding="utf-8") as f:
                    reader = csv.reader(f)
                    rows = list(reader)
                    if len(rows) > 1:  # Has header + at least one row
                        try:
                            self._extended_csv_order = int(rows[-1][0])
                            if self.verbose:
                                print(
                                    f"[DEBUG] Resuming from order {self._extended_csv_order}",
                                    file=sys.stderr,
                                )
                        except (ValueError, IndexError):
                            self._extended_csv_order = 0
        except Exception as exc:  # pylint: disable=broad-exception-caught
            if self.verbose:
                print(
                    f"[WARNING] Failed to initialize extended CSV: {exc}",
                    file=sys.stderr,
                )

    def _write_extended_csv_row(
        self,
        group: str,
        artifact: str,
        version: str,
        depth: int,
        homepage_url: str = "",
        license_type: str = "",
        status: str = "found",
        is_original: int = 0,
    ) -> None:
        """
        Write a row to the extended CSV file incrementally.

        Args:
            group: Maven group ID
            artifact: Maven artifact ID
            version: Maven version
            depth: Dependency depth
            homepage_url: Homepage URL (if available)
            license_type: License type (if available)
            status: Status message (e.g., "found", "processing", "metadata_fetched")
            is_original: 1 if package is from original compile-order.csv, 0 otherwise
        """
        if not self._extended_csv_writer:
            return

        try:
            self._extended_csv_order += 1
            group_id = f"{group}:{artifact}"
            row = [
                self._extended_csv_order,
                group_id,
                artifact,
                version,
                depth,
                homepage_url,
                license_type,
                status,
                is_original,
            ]
            self._extended_csv_writer.writerow(row)
            self._extended_csv_file.flush()  # Ensure immediate write for tailing

            if self.verbose:
                print(
                    f"[DEBUG] Extended CSV: Added {group_id}:{version} at depth {depth} "
                    f"(order {self._extended_csv_order}, status: {status}, original: {is_original})",
                    file=sys.stderr,
                )
        except Exception as exc:  # pylint: disable=broad-exception-caught
            if self.verbose:
                print(
                    f"[WARNING] Failed to write extended CSV row: {exc}",
                    file=sys.stderr,
                )

    def _close_extended_csv(self) -> None:
        """
        Close the extended CSV file.
        """
        if self._extended_csv_file:
            try:
                self._extended_csv_file.close()
                if self.verbose:
                    print(
                        f"[DEBUG] Extended CSV file closed: {self.extended_csv_path}",
                        file=sys.stderr,
                    )
            except Exception:  # pylint: disable=broad-exception-caught
                pass
            finally:
                self._extended_csv_file = None
                self._extended_csv_writer = None

    def _rate_limit(self) -> None:
        """
        Enforce rate limiting between requests.
        Uses SBOM_RATE_LIMIT_MVNREPO_SEC env var if set (default 0.5).
        """
        current_time = time.time()
        time_since_last = current_time - self._last_request_time
        if time_since_last < self._rate_limit_delay:
            time.sleep(self._rate_limit_delay - time_since_last)
        self._last_request_time = time.time()

    def _get_dependencies_page_url(
        self, group: str, artifact: str, version: str
    ) -> str:
        """
        Construct the mvnrepository.com dependencies page URL.

        Args:
            group: Maven group ID
            artifact: Maven artifact ID
            version: Maven version

        Returns:
            URL to the dependencies page
        """
        group_path = group.replace(".", "/")
        return f"{self.BASE_URL}/{group}/{artifact}/{version}/dependencies"

    def get_dependencies(
        self, group: str, artifact: str, version: str
    ) -> List[Tuple[str, str, str]]:
        """
        Fetch dependencies for a Maven package from mvnrepository.com.

        Args:
            group: Maven group ID
            artifact: Maven artifact ID
            version: Maven version

        Returns:
            List of (group, artifact, version) tuples for dependencies
        """
        cache_key = f"{group}:{artifact}:{version}"
        if cache_key in self._cache:
            if self.verbose:
                print(
                    f"[DEBUG] Using cached dependencies for {group}:{artifact}:{version} "
                    f"({len(self._cache[cache_key])} dependencies)",
                    file=sys.stderr,
                )
            return self._cache[cache_key]

        self._rate_limit()

        url = self._get_dependencies_page_url(group, artifact, version)
        if self.verbose:
            print(
                f"[DEBUG] Fetching dependencies from: {url}",
                file=sys.stderr,
            )

        try:
            request = Request(url)
            request.add_header("User-Agent", f"sbom-compile-order/{__version__}")

            with urlopen(request, timeout=15) as response:
                html_content = response.read().decode("utf-8")

            parser = MvnRepositoryDependencyParser()
            parser.feed(html_content)
            dependencies = parser.dependencies

            self._cache[cache_key] = dependencies
            if self.verbose:
                print(
                    f"[DEBUG] Found {len(dependencies)} dependencies for "
                    f"{group}:{artifact}:{version}",
                    file=sys.stderr,
                )
            return dependencies
        except Exception as exc:  # pylint: disable=broad-exception-caught
            if self.verbose:
                print(
                    f"[WARNING] Failed to fetch dependencies for "
                    f"{group}:{artifact}:{version}: {exc}",
                    file=sys.stderr,
                )
            return []

    def get_license_and_homepage(
        self, group: str, artifact: str, version: str
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Fetch license and homepage information from mvnrepository.com.

        Args:
            group: Maven group ID
            artifact: Maven artifact ID
            version: Maven version

        Returns:
            Tuple of (license_type, homepage_url), both may be None
        """
        url = f"{self.BASE_URL}/{group}/{artifact}/{version}"
        if self.verbose:
            print(
                f"[DEBUG] Fetching metadata from: {url}",
                file=sys.stderr,
            )

        self._rate_limit()

        try:
            request = Request(url)
            request.add_header("User-Agent", f"sbom-compile-order/{__version__}")

            with urlopen(request, timeout=15) as response:
                html_content = response.read().decode("utf-8")

            # Extract license information
            license_type = None
            # Try multiple patterns for license
            license_patterns = [
                r'<th[^>]*>License</th>\s*<td[^>]*>([^<]+)</td>',
                r'<dt[^>]*>License</dt>\s*<dd[^>]*>([^<]+)</dd>',
                r'"license"[^>]*>([^<]+)</',
                r'License[^>]*>([^<]+)</',
            ]
            for pattern in license_patterns:
                license_match = re.search(pattern, html_content, re.IGNORECASE | re.DOTALL)
                if license_match:
                    license_type = license_match.group(1).strip()
                    # Clean up HTML entities and extra whitespace
                    license_type = re.sub(r'\s+', ' ', license_type)
                    if license_type:
                        if self.verbose:
                            print(
                                f"[DEBUG] Found license for {group}:{artifact}:{version}: {license_type}",
                                file=sys.stderr,
                            )
                        break

            # Extract homepage URL
            homepage_url = None
            # Try multiple patterns for homepage
            homepage_patterns = [
                r'<th[^>]*>HomePage</th>\s*<td[^>]*><a[^>]*href="([^"]+)"',
                r'<dt[^>]*>HomePage</dt>\s*<dd[^>]*><a[^>]*href="([^"]+)"',
                r'<a[^>]*href="([^"]+)"[^>]*>HomePage</a>',
                r'HomePage[^>]*href="([^"]+)"',
            ]
            for pattern in homepage_patterns:
                homepage_match = re.search(pattern, html_content, re.IGNORECASE)
                if homepage_match:
                    homepage_url = homepage_match.group(1).strip()
                    # Make sure it's a full URL
                    if homepage_url and not homepage_url.startswith("http"):
                        homepage_url = None
                    if homepage_url:
                        if self.verbose:
                            print(
                                f"[DEBUG] Found homepage for {group}:{artifact}:{version}: {homepage_url}",
                                file=sys.stderr,
                            )
                        break

            if self.verbose and not license_type and not homepage_url:
                print(
                    f"[DEBUG] No metadata found for {group}:{artifact}:{version}",
                    file=sys.stderr,
                )

            return license_type, homepage_url
        except Exception as exc:  # pylint: disable=broad-exception-caught
            if self.verbose:
                print(
                    f"[WARNING] Failed to fetch metadata for "
                    f"{group}:{artifact}:{version}: {exc}",
                    file=sys.stderr,
                )
            return None, None

    def _resolve_dependencies_dfs(
        self,
        group: str,
        artifact: str,
        version: str,
        depth: int,
        max_depth: int,
        result: List[Tuple[str, str, str, int]],
    ) -> None:
        """
        Recursively resolve dependencies using depth-first traversal.

        Args:
            group: Maven group ID
            artifact: Maven artifact ID
            version: Maven version
            depth: Current depth level
            max_depth: Maximum depth to traverse
            result: List to append results to (modified in place)
        """
        if depth > max_depth:
            if self.verbose:
                print(
                    f"[DEBUG] Max depth {max_depth} reached for {group}:{artifact}:{version}",
                    file=sys.stderr,
                )
            return

        if not version:
            if self.verbose:
                print(
                    f"[DEBUG] Skipping {group}:{artifact} (no version)",
                    file=sys.stderr,
                )
            return  # Skip if no version

        if self.verbose:
            print(
                f"[DEBUG] Processing dependencies for {group}:{artifact}:{version} at depth {depth}",
                file=sys.stderr,
            )

        # Get dependencies for this package
        dependencies = self.get_dependencies(group, artifact, version)

        if self.verbose:
            print(
                f"[DEBUG] Found {len(dependencies)} dependencies for {group}:{artifact}:{version}",
                file=sys.stderr,
            )

        # Process each dependency recursively (depth-first)
        for idx, (dep_group, dep_artifact, dep_version) in enumerate(dependencies, 1):
            # Create key including version (different versions are different packages)
            dep_key = f"{dep_group}:{dep_artifact}:{dep_version}"

            if self.verbose:
                print(
                    f"[DEBUG] Checking dependency {idx}/{len(dependencies)}: "
                    f"{dep_group}:{dep_artifact}:{dep_version}",
                    file=sys.stderr,
                )

            # Skip if we've already processed this exact package (group:artifact:version)
            if dep_key in self._visited:
                if self.verbose:
                    print(
                        f"[DEBUG] Skipping {dep_key} (already processed)",
                        file=sys.stderr,
                    )
                continue

            # Add to results
            result.append((dep_group, dep_artifact, dep_version, depth))
            self._visited.add(dep_key)

            # Fetch metadata and write to extended CSV immediately
            homepage_url = ""
            license_type = ""
            if self.extended_csv_path:
                try:
                    if self.verbose:
                        print(
                            f"[DEBUG] Fetching metadata for {dep_group}:{dep_artifact}:{dep_version}",
                            file=sys.stderr,
                        )
                    license, homepage = self.get_license_and_homepage(
                        dep_group, dep_artifact, dep_version
                    )
                    if homepage:
                        homepage_url = homepage
                    if license:
                        license_type = license
                except Exception as exc:  # pylint: disable=broad-exception-caught
                    # Continue even if metadata fetch fails (e.g., no internet)
                    if self.verbose:
                        print(
                            f"[DEBUG] Metadata fetch failed for {dep_group}:{dep_artifact}:{dep_version}: {exc}",
                            file=sys.stderr,
                        )

                # Write to extended CSV with status "found" (even if metadata is empty)
                # Note: This is for resolve_all_dependencies, dependencies are not original
                self._write_extended_csv_row(
                    dep_group,
                    dep_artifact,
                    dep_version,
                    depth,
                    homepage_url,
                    license_type,
                    "found",
                    is_original=0,  # Dependency, not from original SBOM
                )

            if self.verbose:
                print(
                    f"[DEBUG] Added {dep_key} at depth {depth} "
                    f"(total visited: {len(self._visited)})",
                    file=sys.stderr,
                )

            # Recursively process dependencies of this dependency
            if dep_version:  # Only recurse if we have a version
                if self.verbose:
                    print(
                        f"[DEBUG] Recursing into dependencies of {dep_group}:{dep_artifact}:{dep_version}",
                        file=sys.stderr,
                    )
                self._resolve_dependencies_dfs(
                    dep_group, dep_artifact, dep_version, depth + 1, max_depth, result
                )
            else:
                if self.verbose:
                    print(
                        f"[DEBUG] Skipping recursion for {dep_group}:{dep_artifact} (no version)",
                        file=sys.stderr,
                    )

    def resolve_all_dependencies(
        self, components: Dict[str, Component], max_depth: int = 2
    ) -> List[Tuple[str, str, str, int]]:
        """
        Resolve all transitive dependencies for a set of components using depth-first traversal.

        Uses depth-first traversal: for each package, processes all its dependencies
        recursively before moving to the next package. Skips packages that already exist
        (same group:artifact:version), but considers different versions as different packages.

        Args:
            components: Dictionary of component identifiers to Component objects
            max_depth: Maximum depth to traverse dependencies (default: 2)

        Returns:
            List of (group, artifact, version, depth) tuples where depth indicates
            the dependency level (0 = original, 1 = direct dependency, etc.)
        """
        result: List[Tuple[str, str, str, int]] = []
        self._visited.clear()

        # Initialize extended CSV if path provided (overwrite for fresh start)
        if self.extended_csv_path:
            self._init_extended_csv(overwrite=True)

        if self.verbose:
            print(
                f"[DEBUG] Starting dependency resolution for {len(components)} components "
                f"with max_depth={max_depth}",
                file=sys.stderr,
            )

        # First, add all original components at depth 0
        original_count = 0
        for comp in components.values():
            if comp.group and comp.name:
                key = f"{comp.group}:{comp.name}:{comp.version or ''}"
                if key not in self._visited:
                    result.append((comp.group, comp.name, comp.version or "", 0))
                    self._visited.add(key)
                    original_count += 1

                    # Write original components to extended CSV
                    if self.extended_csv_path:
                        homepage_url = ""
                        license_type = ""
                        if comp.version:
                            try:
                                if self.verbose:
                                    print(
                                        f"[DEBUG] Fetching metadata for original component "
                                        f"{comp.group}:{comp.name}:{comp.version}",
                                        file=sys.stderr,
                                    )
                                license, homepage = self.get_license_and_homepage(
                                    comp.group, comp.name, comp.version
                                )
                                if homepage:
                                    homepage_url = homepage
                                if license:
                                    license_type = license
                            except Exception as exc:  # pylint: disable=broad-exception-caught
                                # Continue even if metadata fetch fails (e.g., no internet)
                                if self.verbose:
                                    print(
                                        f"[DEBUG] Metadata fetch failed for original component "
                                        f"{comp.group}:{comp.name}:{comp.version}: {exc}",
                                        file=sys.stderr,
                                    )

                        # Write row even if metadata is empty (works offline)
                        # Note: This is for resolve_all_dependencies, not resolve_from_compile_order_csv
                        # In resolve_from_compile_order_csv, original packages get is_original=1
                        self._write_extended_csv_row(
                            comp.group,
                            comp.name,
                            comp.version or "",
                            0,
                            homepage_url,
                            license_type,
                            "original",
                            is_original=1,  # Original component from SBOM
                        )

        if self.verbose:
            print(
                f"[DEBUG] Added {original_count} original components at depth 0",
                file=sys.stderr,
            )

        # Process each original component's dependencies using depth-first traversal
        processed_count = 0
        for comp in components.values():
            if comp.group and comp.name and comp.version:
                processed_count += 1
                if self.verbose:
                    print(
                        f"[DEBUG] Processing original component {processed_count}/{len(components)}: "
                        f"{comp.group}:{comp.name}:{comp.version}",
                        file=sys.stderr,
                    )
                self._resolve_dependencies_dfs(
                    comp.group, comp.name, comp.version, 1, max_depth, result
                )

        if self.verbose:
            print(
                f"[DEBUG] Dependency resolution complete: "
                f"{len(result)} total packages found ({original_count} original, "
                f"{len(result) - original_count} dependencies)",
                file=sys.stderr,
            )

        # Close extended CSV file
        self._close_extended_csv()

        return result

    def resolve_from_compile_order_csv(
        self, compile_order_csv_path: Path, max_depth: int = 2
    ) -> None:
        """
        Resolve dependencies from compile-order.csv file.

        Reads each row from compile-order.csv, copies it to extended CSV, then
        fetches and adds dependencies under that package. Ensures no duplicates
        across compile-order.csv and extended CSV (treats different versions as
        different packages).

        Args:
            compile_order_csv_path: Path to compile-order.csv file
            max_depth: Maximum depth to traverse dependencies (default: 2)
        """
        if not self.extended_csv_path:
            if self.verbose:
                print(
                    "[WARNING] Extended CSV path not set, cannot resolve from compile-order.csv",
                    file=sys.stderr,
                )
            return

        if not compile_order_csv_path.exists():
            if self.verbose:
                print(
                    f"[WARNING] Compile order CSV not found: {compile_order_csv_path}",
                    file=sys.stderr,
                )
            return

        # Read compile-order.csv and build set of existing packages
        compile_order_packages: Set[str] = set()  # group:artifact:version
        compile_order_rows: List[Dict[str, str]] = []

        if self.verbose:
            print(
                f"[DEBUG] Reading compile-order.csv from: {compile_order_csv_path}",
                file=sys.stderr,
            )

        try:
            with open(compile_order_csv_path, "r", encoding="utf-8") as file:
                reader = csv.DictReader(file)
                for row in reader:
                    compile_order_rows.append(row)
                    # Extract package identifier: group:artifact:version
                    group_id = row.get("Group ID", "")
                    package_name = row.get("Package Name", "")
                    version = row.get("Version/Tag", "")
                    if group_id and package_name:
                        # Group ID might be in format "group:artifact" or just "group"
                        if ":" in group_id:
                            # Group ID is "group:artifact", use it as-is
                            parts = group_id.split(":")
                            if len(parts) >= 2:
                                group = parts[0]
                                artifact = parts[1]
                            else:
                                group = parts[0]
                                artifact = package_name
                        else:
                            # Group ID is just "group", use package_name as artifact
                            group = group_id
                            artifact = package_name
                        package_key = f"{group}:{artifact}:{version}"
                        compile_order_packages.add(package_key)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            if self.verbose:
                print(
                    f"[ERROR] Failed to read compile-order.csv: {exc}",
                    file=sys.stderr,
                )
            return

        if self.verbose:
            print(
                f"[DEBUG] Found {len(compile_order_rows)} packages in compile-order.csv",
                file=sys.stderr,
            )

        # Track packages already added to extended CSV
        self._visited.clear()
        self._visited.update(compile_order_packages)

        # Initialize extended CSV (always overwrite when reading from compile-order.csv)
        self._init_extended_csv(overwrite=True)

        # Process each row from compile-order.csv
        for idx, row in enumerate(compile_order_rows, 1):
            group_id = row.get("Group ID", "")
            package_name = row.get("Package Name", "")
            version = row.get("Version/Tag", "")

            if not group_id or not package_name:
                continue

            # Parse group and artifact
            if ":" in group_id:
                # Group ID is "group:artifact", use it as-is
                parts = group_id.split(":")
                if len(parts) >= 2:
                    group = parts[0]
                    artifact = parts[1]
                else:
                    group = parts[0]
                    artifact = package_name
            else:
                # Group ID is just "group", use package_name as artifact
                group = group_id
                artifact = package_name

            if self.verbose:
                print(
                    f"[DEBUG] Processing package {idx}/{len(compile_order_rows)}: "
                    f"{group}:{artifact}:{version}",
                    file=sys.stderr,
                )

            # Copy row from compile-order.csv to extended CSV
            homepage_url = row.get("Homepage URL", "")
            license_type = row.get("License Type", "")
            provided_url = row.get("Provided URL", "")
            repo_url = row.get("Repo URL", "")

            # Fetch metadata if not already present
            if version and (not homepage_url or not license_type):
                try:
                    license, homepage = self.get_license_and_homepage(
                        group, artifact, version
                    )
                    if homepage and not homepage_url:
                        homepage_url = homepage
                    if license and not license_type:
                        license_type = license
                except Exception as exc:  # pylint: disable=broad-exception-caught
                    if self.verbose:
                        print(
                            f"[DEBUG] Metadata fetch failed: {exc}",
                            file=sys.stderr,
                        )

            # Write original package row (depth 0) - mark as original (1)
            self._write_extended_csv_row(
                group,
                artifact,
                version,
                0,
                homepage_url,
                license_type,
                "from_compile_order",
                is_original=1,  # This package is from compile-order.csv
            )

            # Fetch and add dependencies for this package
            if version:
                self._add_dependencies_recursive(
                    group,
                    artifact,
                    version,
                    1,
                    max_depth,
                    compile_order_packages,
                )

        # Close extended CSV file
        self._close_extended_csv()

        if self.verbose:
            print(
                f"[DEBUG] Extended CSV complete: {self._extended_csv_order} total entries",
                file=sys.stderr,
            )

    def _add_dependencies_recursive(
        self,
        group: str,
        artifact: str,
        version: str,
        depth: int,
        max_depth: int,
        compile_order_packages: Set[str],
    ) -> None:
        """
        Recursively add dependencies for a package, checking against compile-order.csv
        and already-added packages.

        Args:
            group: Maven group ID
            artifact: Maven artifact ID
            version: Maven version
            depth: Current depth level
            max_depth: Maximum depth to traverse
            compile_order_packages: Set of packages already in compile-order.csv
        """
        if depth > max_depth:
            return

        if not version:
            return

        # Get dependencies for this package
        dependencies = self.get_dependencies(group, artifact, version)

        if self.verbose:
            print(
                f"[DEBUG] Found {len(dependencies)} dependencies for "
                f"{group}:{artifact}:{version} at depth {depth}",
                file=sys.stderr,
            )

        # Process each dependency
        for dep_group, dep_artifact, dep_version in dependencies:
            dep_key = f"{dep_group}:{dep_artifact}:{dep_version}"

            # Check if already exists in compile-order.csv or extended CSV
            if dep_key in self._visited:
                if self.verbose:
                    print(
                        f"[DEBUG] Skipping {dep_key} (already exists)",
                        file=sys.stderr,
                    )
                continue

            # Add to visited set
            self._visited.add(dep_key)

            # Fetch metadata
            homepage_url = ""
            license_type = ""
            if dep_version:
                try:
                    license, homepage = self.get_license_and_homepage(
                        dep_group, dep_artifact, dep_version
                    )
                    if homepage:
                        homepage_url = homepage
                    if license:
                        license_type = license
                except Exception as exc:  # pylint: disable=broad-exception-caught
                    if self.verbose:
                        print(
                            f"[DEBUG] Metadata fetch failed for {dep_key}: {exc}",
                            file=sys.stderr,
                        )

            # Write dependency row
            self._write_extended_csv_row(
                dep_group,
                dep_artifact,
                dep_version,
                depth,
                homepage_url,
                license_type,
                "dependency",
            )

            # Recursively process dependencies of this dependency
            if dep_version:
                self._add_dependencies_recursive(
                    dep_group,
                    dep_artifact,
                    dep_version,
                    depth + 1,
                    max_depth,
                    compile_order_packages,
                )
