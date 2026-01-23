"""
Enhanced CSV generator that reads compile-order.csv and enhances it with package metadata.
"""

import csv
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from sbom_compile_order.package_metadata import PackageMetadataClient
from sbom_compile_order.parser import Component, build_maven_central_url_from_purl, extract_package_type
from sbom_compile_order.output import extract_repo_url


def _normalize_npm_repo_url(url: str) -> str:
    """
    Normalize npm repository URL by removing git+ prefixes and converting to https://.

    Handles formats like:
    - git+https://github.com/user/repo.git -> https://github.com/user/repo.git
    - git+ssh://git@github.com/user/repo.git -> https://github.com/user/repo.git
    - git://github.com/user/repo.git -> https://github.com/user/repo.git
    - https://github.com/user/repo.git -> https://github.com/user/repo.git (unchanged)

    Args:
        url: Repository URL that may have git+ prefix

    Returns:
        Normalized URL starting with https://, or empty string if invalid
    """
    if not url:
        return ""

    url = url.strip()

    # Remove git+ prefix if present
    if url.startswith("git+"):
        url = url[4:]

    # Handle git:// protocol
    if url.startswith("git://"):
        url = url.replace("git://", "https://", 1)

    # Handle git@ssh format: git@github.com:user/repo.git -> https://github.com/user/repo.git
    if url.startswith("git@") or url.startswith("ssh://git@"):
        # Remove ssh:// prefix if present
        if url.startswith("ssh://"):
            url = url[6:]
        # Remove git@ prefix
        if url.startswith("git@"):
            url = url[4:]
        # Replace : with / after domain (git@github.com:user/repo -> github.com/user/repo)
        if ":" in url:
            parts = url.split(":", 1)
            if len(parts) == 2:
                domain = parts[0]
                path = parts[1]
                url = f"{domain}/{path}"
        url = f"https://{url}"

    # Ensure it starts with https://
    if not url.startswith("http://") and not url.startswith("https://"):
        # If it looks like a domain, add https://
        if "/" in url or "." in url:
            url = f"https://{url}"

    # Remove .git suffix if present (we'll add it back if needed for git clone)
    if url.endswith(".git"):
        url = url[:-4]

    # Add .git back for git clone compatibility
    if url and not url.endswith(".git"):
        # Only add .git if it looks like a git repository URL
        if any(host in url.lower() for host in ["github.com", "gitlab.com", "bitbucket.org", "git"]):
            url = f"{url}.git"

    return url


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
    metadata_client: Optional[PackageMetadataClient],
    pom_downloader=None,
    verbose: bool = False,
    log_file: Optional[Path] = None,
    hash_cache=None,
) -> None:
    """
    Read compile-order.csv and create enhanced.csv with additional metadata and optional POM downloads.

    Supports incremental updates: if compile-order.csv is unchanged and enhanced.csv exists,
    only updates rows where POM/JAR download status might have changed.

    Args:
        compile_order_csv_path: Path to the compile-order.csv file
        enhanced_csv_path: Path where enhanced.csv will be written
        metadata_client: PackageMetadataClient instance for lookups
        pom_downloader: Optional POMDownloader instance for downloading POM files
        verbose: Whether to print verbose output
        log_file: Optional path to log file for logging actions
        hash_cache: Optional HashCache instance for checking if incremental update is needed
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

    # Read existing enhanced.csv if available to reuse download state
    existing_enhanced_rows = {}
    existing_row_count = 0
    if enhanced_csv_path.exists():
        try:
            with open(enhanced_csv_path, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                existing_header = next(reader)
                for existing_row in reader:
                    if len(existing_row) > 3:
                        key = f"{existing_row[1]}:{existing_row[2]}:{existing_row[3]}"
                        existing_enhanced_rows[key] = existing_row
                        existing_row_count += 1
            log_msg = f"Existing enhanced.csv found ({existing_row_count} rows) - using download history when available"
            _log_to_file(log_msg, log_file)
            if verbose:
                print(f"[INFO] {log_msg}", file=sys.stderr)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            log_msg = f"Failed to read existing enhanced.csv for reuse: {exc}"
            _log_to_file(log_msg, log_file)
            if verbose:
                print(f"[INFO] {log_msg}", file=sys.stderr)

    # Check if incremental update is possible
    incremental_update = False
    if hash_cache and enhanced_csv_path.exists():
        compile_order_hash = hash_cache.get_compile_order_hash(compile_order_csv_path)
        cached_compile_order_hash = hash_cache.get_cached_compile_order_hash()
        if compile_order_hash and cached_compile_order_hash and compile_order_hash == cached_compile_order_hash:
            incremental_update = True
            log_msg = (
                f"compile-order.csv unchanged, performing incremental update of enhanced.csv "
                f"({len(existing_enhanced_rows)} existing rows)"
            )
            _log_to_file(log_msg, log_file)
            if verbose:
                print(f"[INFO] {log_msg}", file=sys.stderr)

    log_msg = f"Reading compile-order.csv: {compile_order_csv_path}"
    _log_to_file(log_msg, log_file)
    if verbose:
        print(f"[INFO] {log_msg}", file=sys.stderr)
    
    if incremental_update:
        log_msg = f"Updating enhanced CSV incrementally: {enhanced_csv_path}"
    else:
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
    if incremental_update:
        # Append mode for incremental updates (but we'll rewrite the file)
        # Actually, we need to rewrite to maintain order, so use write mode
        enhanced_file = open(enhanced_csv_path, "w", encoding="utf-8", newline="")
    else:
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

        # Create key for incremental update lookup
        row_key = f"{group_id_col}:{package_name}:{version}"
        existing_row_entry = existing_enhanced_rows.get(row_key)
        use_existing_data = False
        existing_row_data = None
        if incremental_update and existing_row_entry:
            existing_row_data = existing_row_entry
            use_existing_data = True

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

        # Create a Component object for metadata lookup
        # Get PURL from row if available (column 4)
        purl = row[4] if len(row) > 4 else ""
        package_type = extract_package_type(purl) if purl else None
        
        component_data = {
            "bom-ref": f"{group}:{artifact}:{version}" if group else f"{artifact}:{version}",
            "group": group,
            "name": artifact,
            "version": version,
            "purl": purl,
        }
        comp = Component(component_data)
        is_maven = package_type == "maven"
        is_npm = package_type == "npm"

        # Lookup package metadata (skip if using existing data to avoid unnecessary API calls)
        homepage_url = ""
        license_type = ""
        if use_existing_data and existing_row_data and len(existing_row_data) > 13:
            # Use existing homepage and license (skip API call in incremental mode)
            homepage_url = existing_row_data[13] if len(existing_row_data) > 13 else ""
            license_type = existing_row_data[14] if len(existing_row_data) > 14 else ""
            if verbose and (homepage_url or license_type):
                package_id = f"{group}:{artifact}:{version}" if group else f"{artifact}:{version}"
                log_msg = (
                    f"Using existing metadata for {package_id} "
                    f"(incremental update mode)"
                )
                _log_to_file(log_msg, log_file)
        elif metadata_client and comp.name:
            # For npm packages, we only need name. For Maven, we need group and name.
            if is_npm or (is_maven and comp.group):
                try:
                    homepage, license = metadata_client.get_package_info(comp)
                    if homepage:
                        homepage_url = homepage
                        package_id = f"{group}:{artifact}:{version}" if group else f"{artifact}:{version}"
                        log_msg = f"Found homepage for {package_id}: {homepage_url}"
                        _log_to_file(log_msg, log_file)
                    if license:
                        license_type = license
                        package_id = f"{group}:{artifact}:{version}" if group else f"{artifact}:{version}"
                        log_msg = f"Found license for {package_id}: {license_type}"
                        _log_to_file(log_msg, log_file)
                    
                    # For npm packages, extract comprehensive data
                    if is_npm:
                        try:
                            npm_data = metadata_client.get_comprehensive_npm_data(comp)
                            if npm_data:
                                package_id = f"{artifact}:{version}"
                                
                                # Log additional npm metadata
                                if npm_data.get("description"):
                                    log_msg = f"[npm] Description for {package_id}: {npm_data.get('description')[:100]}"
                                    _log_to_file(log_msg, log_file)
                                
                                if npm_data.get("author"):
                                    author_info = npm_data.get("author")
                                    if isinstance(author_info, dict):
                                        author_str = author_info.get("name", "")
                                        if author_info.get("email"):
                                            author_str += f" <{author_info.get('email')}>"
                                    else:
                                        author_str = str(author_info)
                                    if author_str:
                                        log_msg = f"[npm] Author for {package_id}: {author_str}"
                                        _log_to_file(log_msg, log_file)
                                
                                # Log dependency counts
                                deps_count = len(npm_data.get("dependencies", {}))
                                dev_deps_count = len(npm_data.get("devDependencies", {}))
                                peer_deps_count = len(npm_data.get("peerDependencies", {}))
                                optional_deps_count = len(npm_data.get("optionalDependencies", {}))
                                
                                if deps_count > 0 or dev_deps_count > 0 or peer_deps_count > 0 or optional_deps_count > 0:
                                    log_msg = (
                                        f"[npm] Dependencies for {package_id}: "
                                        f"{deps_count} runtime, {dev_deps_count} dev, "
                                        f"{peer_deps_count} peer, {optional_deps_count} optional"
                                    )
                                    _log_to_file(log_msg, log_file)
                                
                                # Extract and normalize repository URL
                                npm_repo_url_raw = npm_data.get("repository")
                                if npm_repo_url_raw:
                                    # Normalize the repository URL (remove git+ prefix, convert to https://)
                                    repo_url_from_npm = _normalize_npm_repo_url(npm_repo_url_raw)
                                    if repo_url_from_npm:
                                        log_msg = (
                                            f"[npm] Normalized repository URL for {package_id}: "
                                            f"{npm_repo_url_raw} -> {repo_url_from_npm}"
                                        )
                                        _log_to_file(log_msg, log_file)
                                        if verbose:
                                            print(f"[INFO] {log_msg}", file=sys.stderr)
                                    elif npm_repo_url_raw != homepage_url:
                                        log_msg = f"[npm] Repository for {package_id}: {npm_repo_url_raw}"
                                        _log_to_file(log_msg, log_file)
                                
                                # Log keywords if available
                                keywords = npm_data.get("keywords", [])
                                if keywords:
                                    keywords_str = ", ".join(keywords[:10])  # Limit to first 10
                                    log_msg = f"[npm] Keywords for {package_id}: {keywords_str}"
                                    _log_to_file(log_msg, log_file)
                        except Exception as npm_data_exc:  # pylint: disable=broad-exception-caught
                            # Non-fatal: continue even if comprehensive data extraction fails
                            if verbose:
                                package_id = f"{artifact}:{version}"
                                log_msg = f"[npm] Note: Could not extract comprehensive data for {package_id}: {npm_data_exc}"
                                _log_to_file(log_msg, log_file)
                except Exception as exc:  # pylint: disable=broad-exception-caught
                    package_id = f"{group}:{artifact}:{version}" if group else f"{artifact}:{version}"
                    log_msg = f"[WARNING] Failed to lookup metadata for {package_id}: {exc}"
                    _log_to_file(log_msg, log_file)
                    if verbose:
                        print(log_msg, file=sys.stderr)

        # Build Maven Central URLs for POM and JAR from PURL (only for Maven packages)
        pom_url_maven = ""
        jar_url_maven = ""
        if is_maven:
            if comp.purl:
                pom_url_maven = build_maven_central_url_from_purl(comp.purl, file_type="pom")
                jar_url_maven = build_maven_central_url_from_purl(comp.purl, file_type="jar")
            elif comp.group and comp.name and comp.version:
                # Fallback: build URLs from coordinates if PURL not available
                from sbom_compile_order.parser import build_maven_central_url
                pom_url_maven = build_maven_central_url(comp.group, comp.name, comp.version, "pom")
                jar_url_maven = build_maven_central_url(comp.group, comp.name, comp.version, "jar")

        # Determine if we already have the POM downloaded (even if enhanced.csv is stale)
        downloaded_col_idx = len(header)
        file_location_col_idx = downloaded_col_idx + 1
        existing_downloaded_status = ""
        existing_file_location = ""
        if existing_row_entry and len(existing_row_entry) > downloaded_col_idx:
            existing_downloaded_status = existing_row_entry[downloaded_col_idx]
            if len(existing_row_entry) > file_location_col_idx:
                existing_file_location = existing_row_entry[file_location_col_idx]
        skip_pom_download = False
        if (
            pom_downloader
            and existing_downloaded_status.lower() == "yes"
            and existing_file_location
        ):
            relative_path = existing_file_location.lstrip("./")
            existing_file_path = compile_order_csv_path.parent / relative_path
            if existing_file_path.exists():
                pom_filename = existing_file_path.name
                downloaded_status = "yes"
                file_location = existing_file_location
                skip_pom_download = True
            else:
                log_msg = (
                    f"Previously recorded POM missing on disk, will re-download: "
                    f"{existing_file_location}"
                )
                _log_to_file(log_msg, log_file)
                if verbose:
                    print(f"[INFO] {log_msg}", file=sys.stderr)
        
        # Download POM file if pom_downloader is provided
        # In incremental mode, always check POM download status to update if needed
        pom_filename = ""
        auth_required = ""
        downloaded_status = ""
        file_location = ""
        repo_url_from_pom = ""  # Will be extracted from POM file
        repo_url = row[9] if len(row) > 9 else ""  # Repo URL is in column 9 (original from SBOM)
        repo_url_from_npm = ""  # Will be extracted from npm package data (normalized to https://)
        
        # Always check POM download status if pom_downloader is available (only for Maven packages)
        # This ensures download status is up-to-date even in incremental mode
        if pom_downloader and is_maven and comp.group and comp.name and comp.version and not skip_pom_download:
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
        elif pom_downloader and not skip_pom_download:
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
        
        # Update Repo URL (column 9) with URL from POM file (Maven) or npm data (npm)
        # For npm packages, also check Provided URL (column 8) if it contains git+ prefixes
        # In incremental mode, preserve existing if no new URL found
        if is_maven and repo_url_from_pom:
            row[9] = repo_url_from_pom
        elif is_npm:
            # Prefer normalized URL from npm registry data
            if repo_url_from_npm:
                row[9] = repo_url_from_npm
            else:
                # Fallback: normalize Provided URL (column 8) if it exists and has git+ prefix
                provided_url = row[8] if len(row) > 8 else ""
                if provided_url and ("git+" in provided_url or provided_url.startswith("git@") or provided_url.startswith("git://")):
                    normalized_provided_url = _normalize_npm_repo_url(provided_url)
                    if normalized_provided_url:
                        row[9] = normalized_provided_url
                        log_msg = (
                            f"[npm] Normalized Provided URL to Repo URL for {artifact}:{version}: "
                            f"{provided_url} -> {normalized_provided_url}"
                        )
                        _log_to_file(log_msg, log_file)
                        if verbose:
                            print(f"[INFO] {log_msg}", file=sys.stderr)
        elif use_existing_data and existing_row_data and len(existing_row_data) > 9:
            row[9] = existing_row_data[9]  # Preserve existing Repo URL
        
        # Update POM and AUTH columns
        # Always update if we have new data, otherwise preserve existing in incremental mode
        if pom_filename:
            row[11] = pom_filename
        elif use_existing_data and existing_row_data and len(existing_row_data) > 11:
            row[11] = existing_row_data[11]  # Preserve existing POM filename
            
        if auth_required:
            row[12] = auth_required
        elif use_existing_data and existing_row_data and len(existing_row_data) > 12:
            row[12] = existing_row_data[12]  # Preserve existing AUTH status
        
        # Update Homepage URL and License Type (preserve existing if no new data)
        if homepage_url:
            row[13] = homepage_url
        elif use_existing_data and existing_row_data and len(existing_row_data) > 13:
            row[13] = existing_row_data[13]  # Preserve existing Homepage URL
            
        if license_type:
            row[14] = license_type
        elif use_existing_data and existing_row_data and len(existing_row_data) > 14:
            row[14] = existing_row_data[14]  # Preserve existing License Type
        
        # Add new columns: Downloaded (16), File Location (17), POM URL (18), and JAR URL (19)
        # In incremental mode with existing data, preserve existing values if we didn't check downloads
        # Otherwise use new values (either from download check or empty if no downloader)
        if use_existing_data and existing_row_data and len(existing_row_data) > 19 and not pom_downloader:
            # Incremental mode, no downloader - preserve all existing data
            row.append(existing_row_data[16] if len(existing_row_data) > 16 else downloaded_status)
            row.append(existing_row_data[17] if len(existing_row_data) > 17 else file_location)
            row.append(existing_row_data[18] if len(existing_row_data) > 18 else pom_url_maven)
            row.append(existing_row_data[19] if len(existing_row_data) > 19 else jar_url_maven)
        else:
            # Use new values (either from download check or defaults)
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
