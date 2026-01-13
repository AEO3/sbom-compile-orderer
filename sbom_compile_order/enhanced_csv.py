"""
Enhanced CSV generator that reads compile-order.csv and enhances it with Maven Central data.
"""

import csv
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from sbom_compile_order.parser import Component


def _log_to_file(message: str, log_file: Path) -> None:
    """
    Write a message to the log file.

    Args:
        message: Message to log
        log_file: Path to log file
    """
    import os
    import sys
    
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


def create_enhanced_csv(
    compile_order_csv_path: Path,
    enhanced_csv_path: Path,
    maven_central_client,
    verbose: bool = False,
    log_file: Optional[Path] = None,
) -> None:
    """
    Read compile-order.csv and create enhanced.csv with Maven Central data.

    Args:
        compile_order_csv_path: Path to the compile-order.csv file
        enhanced_csv_path: Path where enhanced.csv will be written
        maven_central_client: MavenCentralClient instance for lookups
        verbose: Whether to print verbose output
        log_file: Optional path to log file for logging actions
    """
    if log_file is None:
        # Default to cache directory log file
        log_file = compile_order_csv_path.parent / "sbom-compile-order.log"
    
    if not compile_order_csv_path.exists():
        error_msg = f"[ERROR] compile-order.csv not found: {compile_order_csv_path}"
        _log_to_file(error_msg, log_file)
        if verbose:
            print(error_msg, file=sys.stderr)
        return

    log_msg = f"Reading compile-order.csv: {compile_order_csv_path}"
    _log_to_file(log_msg, log_file)
    if verbose:
        print(f"[INFO] {log_msg}", file=sys.stderr)
    
    log_msg = f"Creating enhanced CSV: {enhanced_csv_path}"
    _log_to_file(log_msg, log_file)
    if verbose:
        print(f"[INFO] {log_msg}", file=sys.stderr)

    # Read compile-order.csv
    rows = []
    with open(compile_order_csv_path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)  # Read header
        rows = list(reader)

    log_msg = f"Found {len(rows)} rows to enhance"
    _log_to_file(log_msg, log_file)
    if verbose:
        print(f"[INFO] {log_msg}", file=sys.stderr)

    # Write enhanced CSV incrementally (row by row) so it can be tailed
    # Open file and keep it open for incremental writing
    enhanced_file = open(enhanced_csv_path, "w", encoding="utf-8", newline="")
    writer = csv.writer(enhanced_file)
    
    # Write header (same as compile-order.csv)
    writer.writerow(header)
    enhanced_file.flush()
    os.fsync(enhanced_file.fileno())
    
    log_msg = f"Enhanced CSV header written, starting incremental processing"
    _log_to_file(log_msg, log_file)
    if verbose:
        print(f"[INFO] {log_msg}", file=sys.stderr)

    # Process each row incrementally
    for idx, row in enumerate(rows, 1):
        if len(row) < 4:
            # Skip malformed rows
            writer.writerow(row)
            enhanced_file.flush()
            os.fsync(enhanced_file.fileno())
            continue

        # Parse row data
        # Columns: Order, Group ID, Package Name, Version/Tag, PURL, Ref, Type, Scope,
        #          Provided URL, Repo URL, Dependencies, POM, AUTH, Homepage URL,
        #          License Type, External Dependency Count
        order_num = row[0]
        group_id_col = row[1]  # Format: "group:artifact" or just "group"
        package_name = row[2]
        version = row[3]

        # Parse Group ID column - it may be "group:artifact" or just "group"
        group = ""
        artifact = package_name  # Default to package_name if not in group_id
        if group_id_col:
            if ":" in group_id_col:
                # Format is "group:artifact"
                parts = group_id_col.split(":", 1)
                group = parts[0]
                artifact = parts[1] if len(parts) > 1 else package_name
            else:
                # Format is just "group"
                group = group_id_col
                artifact = package_name

        # Create a Component object for Maven Central lookup
        component_data = {
            "bom-ref": f"{group}:{artifact}:{version}" if group else f"{artifact}:{version}",
            "group": group,
            "name": artifact,
            "version": version,
        }
        comp = Component(component_data)

        # Lookup Maven Central data
        homepage_url = ""
        license_type = ""
        if maven_central_client and comp.group and comp.name:
            try:
                homepage, license = maven_central_client.get_package_info(comp)
                if homepage:
                    homepage_url = homepage
                    log_msg = f"Found homepage for {group}:{artifact}:{version}: {homepage_url}"
                    _log_to_file(log_msg, log_file)
                if license:
                    license_type = license
                    log_msg = f"Found license for {group}:{artifact}:{version}: {license_type}"
                    _log_to_file(log_msg, log_file)
            except Exception as exc:  # pylint: disable=broad-exception-caught
                log_msg = f"[WARNING] Failed to lookup Maven Central data for {group}:{artifact}:{version}: {exc}"
                _log_to_file(log_msg, log_file)
                if verbose:
                    print(log_msg, file=sys.stderr)

        # Enhance the row - update Homepage URL and License Type columns
        # Ensure row has enough columns (now 16 columns total)
        while len(row) < 16:
            row.append("")

        # Always update columns 13 (Homepage URL) and 14 (License Type) with Maven Central data
        # This ensures the enhanced CSV has the latest data from Maven Central
        # Column positions: 0=Order, 1=Group ID, 2=Package Name, 3=Version/Tag,
        # 4=PURL, 5=Ref, 6=Type, 7=Scope, 8=Provided URL, 9=Repo URL, 10=Dependencies,
        # 11=POM, 12=AUTH, 13=Homepage URL, 14=License Type, 15=External Dependency Count
        if homepage_url:
            row[13] = homepage_url
        if license_type:
            row[14] = license_type

        # Write row immediately and flush to disk for tailing
        writer.writerow(row)
        enhanced_file.flush()
        os.fsync(enhanced_file.fileno())

        if idx % 100 == 0:
            log_msg = f"Processed {idx}/{len(rows)} rows"
            _log_to_file(log_msg, log_file)
            if verbose:
                print(f"[INFO] {log_msg}", file=sys.stderr)

    # Close the file
    enhanced_file.close()

    log_msg = f"Enhanced CSV created successfully: {enhanced_csv_path} ({len(rows)} rows)"
    _log_to_file(log_msg, log_file)
    if verbose:
        print(f"[INFO] {log_msg}", file=sys.stderr)
