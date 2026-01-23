"""
SBOM Compile Order Tool.

A tool for analysing CycloneDX SBOM files to determine compilation order
for all dependencies including transitive dependencies.
"""

import csv
import sys

# Raise CSV field size limit before any submodule uses csv. Required when SBOMs or
# compile-order CSVs have very long fields (e.g. long PURLs, large dependency lists).
# Must run at package import so it applies in the current process and in any thread
# (e.g. parallel_downloader's worker) or in a freshly spawned process that imports
# this package before using csv.
csv.field_size_limit(sys.maxsize)

__version__ = "1.9.2"
