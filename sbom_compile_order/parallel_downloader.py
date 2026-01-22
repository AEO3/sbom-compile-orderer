"""
Parallel downloader for POM and JAR files.

Downloads files in parallel using threading while enhanced.csv is being created.
"""

import csv
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from queue import Queue
from typing import List, Optional, Tuple

from sbom_compile_order.parser import Component


class ParallelDownloader:
    """Downloads POM and JAR files in parallel using background threads."""

    def __init__(
        self,
        compile_order_csv_path: Path,
        pom_downloader=None,
        jar_downloader=None,
        max_workers: int = 5,
        verbose: bool = False,
        log_file: Optional[Path] = None,
    ) -> None:
        """
        Initialize the parallel downloader.

        Args:
            compile_order_csv_path: Path to compile-order.csv file
            pom_downloader: Optional POMDownloader instance
            jar_downloader: Optional PackageDownloader instance
            max_workers: Maximum number of parallel download threads
            verbose: Enable verbose output
            log_file: Optional path to log file
        """
        self.compile_order_csv_path = compile_order_csv_path
        self.pom_downloader = pom_downloader
        self.jar_downloader = jar_downloader
        self.max_workers = max_workers
        self.verbose = verbose
        self.log_file = log_file
        self._download_queue: Queue = Queue()
        self._results: List[Tuple[str, bool, str]] = []  # (component_id, success, file_type)
        self._lock = threading.Lock()
        self._running = False

    def _log(self, message: str) -> None:
        """
        Log a message to log file and optionally stderr.

        Args:
            message: Message to log
        """
        if self.log_file:
            try:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(f"{message}\n")
            except Exception:  # pylint: disable=broad-exception-caught
                pass
        if self.verbose:
            print(message, file=sys.stderr)

    def _read_compile_order_components(self) -> List[Component]:
        """
        Read components from compile-order.csv.

        Returns:
            List of Component objects
        """
        components = []
        if not self.compile_order_csv_path.exists():
            self._log(f"[PARALLEL DOWNLOAD] ERROR: compile-order.csv not found: {self.compile_order_csv_path}")
            return components

        try:
            with open(self.compile_order_csv_path, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                header = next(reader)  # Skip header

                for row in reader:
                    if len(row) < 4:
                        continue

                    # Parse row: Order, Group ID, Package Name, Version/Tag, ...
                    group_id_col = row[1]  # Format: "group:artifact" or just "group"
                    package_name = row[2]
                    version = row[3]
                    purl = row[4] if len(row) > 4 else ""

                    # Parse Group ID
                    group = ""
                    artifact = package_name
                    if group_id_col:
                        if ":" in group_id_col:
                            parts = group_id_col.split(":", 1)
                            group = parts[0]
                            artifact = parts[1] if len(parts) > 1 else package_name
                        else:
                            group = group_id_col
                            artifact = package_name

                    # Create Component
                    component_data = {
                        "bom-ref": f"{group}:{artifact}:{version}" if group else f"{artifact}:{version}",
                        "group": group,
                        "name": artifact,
                        "version": version,
                        "purl": purl,
                    }
                    comp = Component(component_data)
                    components.append(comp)

        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._log(f"[PARALLEL DOWNLOAD] ERROR: Failed to read compile-order.csv: {exc}")

        return components

    def _download_pom(self, component: Component) -> Tuple[str, bool, str]:
        """
        Download POM for a component.

        Args:
            component: Component to download POM for

        Returns:
            Tuple of (component_id, success, "pom")
        """
        component_id = f"{component.group}:{component.name}:{component.version}"
        try:
            if self.pom_downloader:
                pom_filename, auth_required = self.pom_downloader.download_pom(component, "")
                if pom_filename:
                    self._log(f"[PARALLEL DOWNLOAD] Downloaded POM: {component_id} -> {pom_filename}")
                    return component_id, True, "pom"
                elif auth_required:
                    self._log(f"[PARALLEL DOWNLOAD] POM requires auth: {component_id}")
                    return component_id, False, "pom"
                else:
                    self._log(f"[PARALLEL DOWNLOAD] POM download failed: {component_id}")
                    return component_id, False, "pom"
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._log(f"[PARALLEL DOWNLOAD] ERROR downloading POM for {component_id}: {exc}")
        return component_id, False, "pom"

    def _download_jar(self, component: Component) -> Tuple[str, bool, str]:
        """
        Download JAR for a component.

        Args:
            component: Component to download JAR for

        Returns:
            Tuple of (component_id, success, "jar")
        """
        component_id = f"{component.group}:{component.name}:{component.version}"
        try:
            if self.jar_downloader:
                jar_filename, auth_required = self.jar_downloader.download_package(component)
                if jar_filename:
                    self._log(f"[PARALLEL DOWNLOAD] Downloaded JAR: {component_id} -> {jar_filename}")
                    return component_id, True, "jar"
                elif auth_required:
                    self._log(f"[PARALLEL DOWNLOAD] JAR requires auth: {component_id}")
                    return component_id, False, "jar"
                else:
                    self._log(f"[PARALLEL DOWNLOAD] JAR download failed: {component_id}")
                    return component_id, False, "jar"
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._log(f"[PARALLEL DOWNLOAD] ERROR downloading JAR for {component_id}: {exc}")
        return component_id, False, "jar"

    def start_background_downloads(self) -> Optional[threading.Thread]:
        """
        Start background downloads in a separate thread.

        Returns:
            Thread object that can be joined later, or None if no downloaders configured
        """
        if not self.pom_downloader and not self.jar_downloader:
            self._log("[PARALLEL DOWNLOAD] No downloaders configured, skipping parallel downloads")
            return None

        def download_worker():
            """Worker function that runs in background thread."""
            self._running = True
            self._log("[PARALLEL DOWNLOAD] Starting background download thread")

            # Read components from compile-order.csv
            components = self._read_compile_order_components()
            if not components:
                self._log("[PARALLEL DOWNLOAD] No components found in compile-order.csv")
                self._running = False
                return

            self._log(f"[PARALLEL DOWNLOAD] Found {len(components)} components to download")

            # Create download tasks
            download_tasks = []
            for comp in components:
                if not comp.group or not comp.name or not comp.version:
                    continue

                if self.pom_downloader:
                    download_tasks.append(("pom", comp))
                if self.jar_downloader:
                    download_tasks.append(("jar", comp))

            if not download_tasks:
                self._log("[PARALLEL DOWNLOAD] No download tasks created")
                self._running = False
                return

            self._log(f"[PARALLEL DOWNLOAD] Starting {len(download_tasks)} downloads with {self.max_workers} workers")

            # Execute downloads in parallel
            success_count = 0
            fail_count = 0
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Submit all tasks
                future_to_task = {}
                for file_type, comp in download_tasks:
                    if file_type == "pom":
                        future = executor.submit(self._download_pom, comp)
                    else:  # jar
                        future = executor.submit(self._download_jar, comp)
                    future_to_task[future] = (file_type, comp)

                # Process completed downloads
                for future in as_completed(future_to_task):
                    file_type, comp = future_to_task[future]
                    try:
                        component_id, success, _ = future.result()
                        with self._lock:
                            self._results.append((component_id, success, file_type))
                            if success:
                                success_count += 1
                            else:
                                fail_count += 1
                    except Exception as exc:  # pylint: disable=broad-exception-caught
                        component_id = f"{comp.group}:{comp.name}:{comp.version}"
                        self._log(f"[PARALLEL DOWNLOAD] ERROR in download task for {component_id}: {exc}")
                        with self._lock:
                            self._results.append((component_id, False, file_type))
                            fail_count += 1

            self._log(
                f"[PARALLEL DOWNLOAD] Background downloads complete: "
                f"{success_count} succeeded, {fail_count} failed (out of {len(download_tasks)} total)"
            )
            self._running = False

        # Start background thread (daemon=True so it doesn't block program exit)
        download_thread = threading.Thread(target=download_worker, daemon=True, name="ParallelDownloader")
        download_thread.start()
        self._log(f"[PARALLEL DOWNLOAD] Background download thread started: {download_thread.name}")
        return download_thread

    def wait_for_completion(self, timeout: Optional[float] = None) -> bool:
        """
        Wait for background downloads to complete.

        Args:
            timeout: Optional timeout in seconds (None = wait indefinitely)

        Returns:
            True if completed, False if timeout
        """
        # Find the download thread (we'd need to store it)
        # For now, just check if running
        import time
        start_time = time.time()
        while self._running:
            if timeout and (time.time() - start_time) > timeout:
                return False
            time.sleep(0.1)
        return True

    def get_results(self) -> List[Tuple[str, bool, str]]:
        """
        Get download results.

        Returns:
            List of (component_id, success, file_type) tuples
        """
        with self._lock:
            return list(self._results)

    def is_running(self) -> bool:
        """
        Check if downloads are still running.

        Returns:
            True if downloads are in progress, False otherwise
        """
        return self._running
