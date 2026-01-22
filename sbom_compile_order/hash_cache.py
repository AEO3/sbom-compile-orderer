"""
Hash-based caching for SBOM and CSV files.

Provides functionality to calculate and store MD5 hashes of SBOM files,
compile-order.csv, and enhanced.csv to enable intelligent caching.
"""

import hashlib
from pathlib import Path
from typing import Optional, Tuple


def calculate_file_hash(file_path: Path) -> Optional[str]:
    """
    Calculate MD5 hash of a file.

    Args:
        file_path: Path to the file

    Returns:
        MD5 hash string, or None if file doesn't exist or error occurs
    """
    if not file_path.exists():
        return None

    try:
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            # Read file in chunks to handle large files efficiently
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception:  # pylint: disable=broad-exception-caught
        return None


def read_hash_from_file(hash_file_path: Path) -> Optional[str]:
    """
    Read hash value from a hash file.

    Args:
        hash_file_path: Path to the hash file

    Returns:
        Hash string, or None if file doesn't exist or error occurs
    """
    if not hash_file_path.exists():
        return None

    try:
        with open(hash_file_path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:  # pylint: disable=broad-exception-caught
        return None


def write_hash_to_file(hash_file_path: Path, hash_value: str) -> bool:
    """
    Write hash value to a hash file.

    Args:
        hash_file_path: Path to the hash file
        hash_value: Hash string to write

    Returns:
        True if successful, False otherwise
    """
    try:
        hash_file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(hash_file_path, "w", encoding="utf-8") as f:
            f.write(hash_value)
        return True
    except Exception:  # pylint: disable=broad-exception-caught
        return False


class HashCache:
    """Manages hash-based caching for SBOM and CSV files."""

    def __init__(self, cache_dir: Path) -> None:
        """
        Initialize the hash cache.

        Args:
            cache_dir: Cache directory where hash files are stored
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.sbom_hash_file = self.cache_dir / "sbom.md5"
        self.compile_order_hash_file = self.cache_dir / "compile-order.csv.md5"
        self.enhanced_hash_file = self.cache_dir / "enhanced.csv.md5"

    def get_sbom_hash(self, sbom_path: Path) -> Optional[str]:
        """
        Calculate and cache MD5 hash of SBOM file.

        Args:
            sbom_path: Path to the SBOM file

        Returns:
            MD5 hash string, or None if error occurs
        """
        return calculate_file_hash(sbom_path)

    def get_compile_order_hash(self, compile_order_path: Path) -> Optional[str]:
        """
        Calculate MD5 hash of compile-order.csv file.

        Args:
            compile_order_path: Path to compile-order.csv

        Returns:
            MD5 hash string, or None if file doesn't exist or error occurs
        """
        return calculate_file_hash(compile_order_path)

    def get_enhanced_hash(self, enhanced_path: Path) -> Optional[str]:
        """
        Calculate MD5 hash of enhanced.csv file.

        Args:
            enhanced_path: Path to enhanced.csv

        Returns:
            MD5 hash string, or None if file doesn't exist or error occurs
        """
        return calculate_file_hash(enhanced_path)

    def get_cached_sbom_hash(self) -> Optional[str]:
        """
        Get cached SBOM hash from previous run.

        Returns:
            Cached hash string, or None if not found
        """
        return read_hash_from_file(self.sbom_hash_file)

    def get_cached_compile_order_hash(self) -> Optional[str]:
        """
        Get cached compile-order.csv hash from previous run.

        Returns:
            Cached hash string, or None if not found
        """
        return read_hash_from_file(self.compile_order_hash_file)

    def get_cached_enhanced_hash(self) -> Optional[str]:
        """
        Get cached enhanced.csv hash from previous run.

        Returns:
            Cached hash string, or None if not found
        """
        return read_hash_from_file(self.enhanced_hash_file)

    def save_sbom_hash(self, hash_value: str) -> bool:
        """
        Save SBOM hash to cache.

        Args:
            hash_value: Hash string to save

        Returns:
            True if successful, False otherwise
        """
        return write_hash_to_file(self.sbom_hash_file, hash_value)

    def save_compile_order_hash(self, hash_value: str) -> bool:
        """
        Save compile-order.csv hash to cache.

        Args:
            hash_value: Hash string to save

        Returns:
            True if successful, False otherwise
        """
        return write_hash_to_file(self.compile_order_hash_file, hash_value)

    def save_enhanced_hash(self, hash_value: str) -> bool:
        """
        Save enhanced.csv hash to cache.

        Args:
            hash_value: Hash string to save

        Returns:
            True if successful, False otherwise
        """
        return write_hash_to_file(self.enhanced_hash_file, hash_value)

    def is_sbom_unchanged(self, sbom_path: Path) -> bool:
        """
        Check if SBOM file has changed since last run.

        Args:
            sbom_path: Path to the SBOM file

        Returns:
            True if SBOM hash matches cached hash, False otherwise
        """
        current_hash = self.get_sbom_hash(sbom_path)
        cached_hash = self.get_cached_sbom_hash()

        if current_hash is None or cached_hash is None:
            return False

        return current_hash == cached_hash

    def is_compile_order_unchanged(self, compile_order_path: Path) -> bool:
        """
        Check if compile-order.csv has changed since last run.

        Args:
            compile_order_path: Path to compile-order.csv

        Returns:
            True if compile-order.csv hash matches cached hash, False otherwise
        """
        current_hash = self.get_compile_order_hash(compile_order_path)
        cached_hash = self.get_cached_compile_order_hash()

        if current_hash is None or cached_hash is None:
            return False

        return current_hash == cached_hash

    def is_enhanced_unchanged(self, enhanced_path: Path) -> bool:
        """
        Check if enhanced.csv has changed since last run.

        Args:
            enhanced_path: Path to enhanced.csv

        Returns:
            True if enhanced.csv hash matches cached hash, False otherwise
        """
        current_hash = self.get_enhanced_hash(enhanced_path)
        cached_hash = self.get_cached_enhanced_hash()

        if current_hash is None or cached_hash is None:
            return False

        return current_hash == cached_hash

    def check_cache_status(
        self, sbom_path: Path, compile_order_path: Path, enhanced_path: Path
    ) -> Tuple[bool, bool, bool]:
        """
        Check cache status for all files.

        Args:
            sbom_path: Path to the SBOM file
            compile_order_path: Path to compile-order.csv
            enhanced_path: Path to enhanced.csv

        Returns:
            Tuple of (sbom_unchanged, compile_order_unchanged, enhanced_unchanged)
        """
        sbom_unchanged = self.is_sbom_unchanged(sbom_path)
        compile_order_unchanged = self.is_compile_order_unchanged(compile_order_path)
        enhanced_unchanged = self.is_enhanced_unchanged(enhanced_path)

        return sbom_unchanged, compile_order_unchanged, enhanced_unchanged
