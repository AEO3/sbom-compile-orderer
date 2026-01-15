"""
Enhanced CSV generator that reads compile-order.csv and enhances it with Maven Central data.
"""

import csv
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from sbom_compile_order.parser import Component, build_maven_central_url_from_purl
from sbom_compile_order.output import extract_repo_url


def _extract_scm_url_from_pom(pom_content: str) -> str:
    """
    Extract SCM URL from POM file content.

    Looks for <scm><url>...</url></scm> in the POM XML.

    Args:
        pom_content: POM file content as string

    Returns:
        SCM URL if found, empty string otherwise
    """
    if not pom_content:
        return ""

    # Look for <scm><url>...</url></scm> pattern
    # Handle both single-line and multi-line formats
    scm_pattern = r"<scm>.*?<url>([^<]+)</url>.*?</scm>"
    match = re.search(scm_pattern, pom_content, re.DOTALL | re.IGNORECASE)
    if match:
        scm_url = match.group(1).strip()
        return scm_url

    # Also try just <url> within <scm> tags (more flexible)
    scm_section_match = re.search(r"<scm>(.*?)</scm>", pom_content, re.DOTALL | re.IGNORECASE)
    if scm_section_match:
        scm_section = scm_section_match.group(1)
        url_match = re.search(r"<url>([^<]+)</url>", scm_section, re.IGNORECASE)
        if url_match:
            scm_url = url_match.group(1).strip()
            return scm_url

    return ""


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
    pom_downloader=None,
    verbose: bool = False,
    log_file: Optional[Path] = None,
) -> None:
    """
    Read compile-order.csv and create enhanced.csv with Maven Central data and POM downloads.

    Args:
        compile_order_csv_path: Path to the compile-order.csv file
        enhanced_csv_path: Path where enhanced.csv will be written
        maven_central_client: MavenCentralClient instance for lookups
        pom_downloader: Optional POMDownloader instance for downloading POM files
        verbose: Whether to print verbose output
        log_file: Optional path to log file for logging actions
    """
    if log_file is None:
        # Default to cache directory log file
        log_file = compile_order_csv_path.parent / "sbom-compile-order.log"
    
    # Get POM cache directory path
    pom_cache_dir = compile_order_csv_path.parent / "poms"
    
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
    
    # Write header - add new columns "Downloaded", "File Location", "POM URL", and "JAR URL" to the end
    enhanced_header = list(header) + ["Downloaded", "File Location", "POM URL", "JAR URL"]
    writer.writerow(enhanced_header)
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

        # Build Maven Central URLs for POM and JAR from PURL
        pom_url_maven = ""
        jar_url_maven = ""
        if comp.purl:
            pom_url_maven = build_maven_central_url_from_purl(comp.purl, file_type="pom")
            jar_url_maven = build_maven_central_url_from_purl(comp.purl, file_type="jar")
        elif comp.group and comp.name and comp.version:
            # Fallback: build URLs from coordinates if PURL not available
            from sbom_compile_order.parser import build_maven_central_url
            pom_url_maven = build_maven_central_url(comp.group, comp.name, comp.version, "pom")
            jar_url_maven = build_maven_central_url(comp.group, comp.name, comp.version, "jar")
        
        # Download POM file if pom_downloader is provided
        pom_filename = ""
        auth_required = ""
        downloaded_status = ""
        file_location = ""
        repo_url_from_pom = ""  # Will be extracted from POM file
        repo_url = row[9] if len(row) > 9 else ""  # Repo URL is in column 9 (original from SBOM)
        if pom_downloader and comp.group and comp.name and comp.version:
            try:
                pom_result, auth_req = pom_downloader.download_pom(comp, repo_url or "")
                pom_filename = pom_result or ""
                auth_required = "AUTH" if auth_req else ""
                if pom_filename:
                    downloaded_status = "yes"
                    file_location = f"./poms/{pom_filename}"
                    log_msg = (
                        f"Downloaded POM for {group}:{artifact}:{version}: {pom_filename}"
                    )
                    _log_to_file(log_msg, log_file)
                    if verbose:
                        print(f"[INFO] {log_msg}", file=sys.stderr)
                    
                    # Read POM file and extract SCM URL
                    pom_file_path = pom_cache_dir / pom_filename
                    if pom_file_path.exists():
                        try:
                            with open(pom_file_path, "r", encoding="utf-8") as pom_file:
                                pom_content = pom_file.read()
                                scm_url = _extract_scm_url_from_pom(pom_content)
                                if scm_url:
                                    # Convert SCM URL to git clone-able URL
                                    repo_url_from_pom = extract_repo_url(scm_url)
                                    if repo_url_from_pom:
                                        log_msg = (
                                            f"Extracted repo URL from POM for {group}:{artifact}:{version}: "
                                            f"{repo_url_from_pom}"
                                        )
                                        _log_to_file(log_msg, log_file)
                                        if verbose:
                                            print(f"[INFO] {log_msg}", file=sys.stderr)
                                    else:
                                        log_msg = (
                                            f"SCM URL found in POM but not a git repository: "
                                            f"{group}:{artifact}:{version}: {scm_url}"
                                        )
                                        _log_to_file(log_msg, log_file)
                                        if verbose:
                                            print(f"[INFO] {log_msg}", file=sys.stderr)
                                else:
                                    repo_url_from_pom = "not found in pom"
                                    log_msg = (
                                        f"No SCM URL found in POM for {group}:{artifact}:{version}"
                                    )
                                    _log_to_file(log_msg, log_file)
                                    if verbose:
                                        print(f"[INFO] {log_msg}", file=sys.stderr)
                        except Exception as pom_read_exc:  # pylint: disable=broad-exception-caught
                            log_msg = (
                                f"[WARNING] Failed to read POM file {pom_filename} to extract repo URL: "
                                f"{pom_read_exc}"
                            )
                            _log_to_file(log_msg, log_file)
                            if verbose:
                                print(log_msg, file=sys.stderr)
                elif auth_req:
                    downloaded_status = "Authentication required"
                    log_msg = (
                        f"Authentication required for POM download: "
                        f"{group}:{artifact}:{version}"
                    )
                    _log_to_file(log_msg, log_file)
                    if verbose:
                        print(f"[INFO] {log_msg}", file=sys.stderr)
                else:
                    downloaded_status = "Failed to download (not found or unavailable)"
                    log_msg = (
                        f"POM download failed for {group}:{artifact}:{version}: "
                        f"not found or unavailable"
                    )
                    _log_to_file(log_msg, log_file)
                    if verbose:
                        print(f"[INFO] {log_msg}", file=sys.stderr)
            except Exception as exc:  # pylint: disable=broad-exception-caught
                error_msg = str(exc)
                downloaded_status = f"Error: {error_msg}"
                log_msg = (
                    f"[WARNING] Failed to download POM for {group}:{artifact}:{version}: {exc}"
                )
                _log_to_file(log_msg, log_file)
                if verbose:
                    print(log_msg, file=sys.stderr)
        elif pom_downloader:
            # POM downloader available but missing required component data
            if not comp.group or not comp.name:
                downloaded_status = "Missing group or artifact name"
            elif not comp.version:
                downloaded_status = "Missing version"
            else:
                downloaded_status = "Not attempted"

        # Enhance the row - update Homepage URL, License Type, POM, AUTH, Downloaded, and File Location columns
        # Ensure row has enough columns (now 16 columns from compile-order.csv)
        while len(row) < 16:
            row.append("")

        # Always update columns 9 (Repo URL), 11 (POM), 12 (AUTH), 13 (Homepage URL), and 14 (License Type)
        # with enhanced data from Maven Central and POM downloads
        # Column positions: 0=Order, 1=Group ID, 2=Package Name, 3=Version/Tag,
        # 4=PURL, 5=Ref, 6=Type, 7=Scope, 8=Provided URL, 9=Repo URL, 10=Dependencies,
        # 11=POM, 12=AUTH, 13=Homepage URL, 14=License Type, 15=External Dependency Count
        
        # Update Repo URL (column 9) with URL from POM file if available
        if repo_url_from_pom:
            row[9] = repo_url_from_pom
        
        if pom_filename:
            row[11] = pom_filename
        if auth_required:
            row[12] = auth_required
        if homepage_url:
            row[13] = homepage_url
        if license_type:
            row[14] = license_type
        
        # Add new columns: Downloaded (16), File Location (17), POM URL (18), and JAR URL (19)
        row.append(downloaded_status)
        row.append(file_location)
        row.append(pom_url_maven)
        row.append(jar_url_maven)

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
