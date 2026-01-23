# SBOM Compile Order Tool - Usage Guide

## Overview

This tool analyses CycloneDX SBOM files to determine the optimal compilation order for all dependencies, ensuring that dependencies are compiled before components that depend on them. It handles transitive dependencies automatically by building a complete dependency graph.

## Installation

```bash
cd sbom-compile-order
pip install -e .
```

Or use directly with Python:

```bash
cd sbom-compile-order
python3 -m sbom_compile_order.cli <sbom-file.json>
```

## Basic Usage

```bash
# Output compilation order to CSV (default format, saved to cache/compile-order.csv)
sbom-compile-order examples/example_sbom.json

# Output to stdout in JSON
sbom-compile-order examples/example_sbom.json -f json

# Use output directory for JSON (writes compile-order.json there)
sbom-compile-order examples/example_sbom.json -o out -f json

# Verbose output with metadata
sbom-compile-order examples/example_sbom.json -v --include-metadata
```

## How It Works

1. **Parse SBOM**: Reads the CycloneDX JSON file and extracts:
   - All components (libraries, applications, etc.)
   - Dependency relationships between components

2. **Build Dependency Graph**: Creates a directed graph where:
   - Each component is a node
   - Edges represent dependencies (A depends on B means B must be compiled before A)

3. **Topological Sort**: Determines compilation order by:
   - Finding all components with no dependencies first
   - Then components whose dependencies are already in the order
   - Continuing until all components are ordered

4. **Handle Transitive Dependencies**: The graph includes all dependency relationships, so transitive dependencies are automatically handled. For example:
   - If A depends on B, and B depends on C
   - The order will be: C, B, A
   - This ensures C is compiled before B, and B before A

## Example Output

### Text Format
```
================================================================================
Compilation Order
================================================================================
Total Components: 4
Total Dependencies: 4

Order:

1. org.example:base:0.5.0
2. org.example:core:1.0.0
3. org.example:utils:2.0.0
4. org.example:api:3.0.0
```

### JSON Format
```json
{
  "compilation_order": [
    {
      "ref": "pkg:maven/org.example/base@0.5.0",
      "group": "org.example",
      "name": "base",
      "version": "0.5.0",
      "purl": "pkg:maven/org.example/base@0.5.0"
    },
    ...
  ],
  "total_components": 4,
  "has_circular_dependencies": false,
  "statistics": {
    "total_components": 4,
    "total_dependencies": 4,
    "has_circular_dependencies": false,
    "strongly_connected_components": 4
  }
}
```

### CSV Format (compile-order.csv)

The CSV has 17 columns. Example (abbreviated):

```csv
Order,Group ID,Package Name,Version/Tag,PURL,Ref,Type,Scope,Provided URL,Repo URL,Dependencies,POM,AUTH,Homepage URL,License Type,External Dependency Count,Cyclical Dependencies
1,org.example:base,base,0.5.0,pkg:maven/org.example/base@0.5.0,,library,,https://github.com/example/base.git,,0,,,https://example.com,Apache-2.0,0,
```

The CSV format is useful for importing into spreadsheets, scripting build processes, and tracking source URLs and versions.

**CSV Columns:** Order, Group ID, Package Name, Version/Tag, PURL, Ref, Type, Scope, Provided URL, Repo URL, Dependencies, POM, AUTH, Homepage URL, License Type, External Dependency Count, Cyclical Dependencies. See [README](README.md) for descriptions.

## Command-Line Options

Run `sbom-compile-order --help` for the full list. Summary:

**Output**
- `-o, --output DIR`: Working directory for all generated files (default: cache). For text/json without `-o`, output goes to stdout.
- `-f, --format FORMAT`: Output format: `text`, `json`, or `csv` (default: `csv`)
- `-v, --verbose`: Enable verbose output
- `--include-metadata`: Include full component metadata in output

**Filtering**
- `--ignore-group-ids IDS`: Group IDs to ignore (space-separated)
- `--exclude-types TYPES`: Component types to exclude
- `--exclude-package-types TYPES`: Package types to exclude (e.g. npm, pypi)

**Maven**
- `-m, --maven-central-lookup`: Look up package metadata (homepage, license) from Maven Central and npm registry
- `--poms`: Download POM files from Maven Central
- `--pull-package`: Download JARs/WARs from Maven Central
- `--jar`, `--war`: Artifact types when using `--pull-package`
- `-c, --clone-repos`: Clone repositories to find POM files

**npm**
- `--npm`: Download npm package tarballs from the npm registry

**Dependencies and POM analysis**
- `-r, --resolve-dependencies`: Resolve transitive dependencies (mvnrepository.com)
- `-d, --max-dependency-depth N`: Max depth (default: 2)
- `-e, --extended-csv FILE`: Extended CSV filename in output directory
- `--leaves`: Extract dependencies from POMs into leaves.csv
- `--leaves-output FILE`: Leaves CSV filename in output directory

## Handling Circular Dependencies

If circular dependencies are detected, the tool will:
1. Attempt to break cycles and provide a partial order
2. Warn the user about circular dependencies
3. Still provide a best-effort compilation order

## Transitive Dependencies

The tool automatically includes transitive dependencies in the compilation order. For example:

If your SBOM shows:
- Component A depends on B
- Component B depends on C

The compilation order will be: C → B → A

This ensures that all dependencies (direct and transitive) are compiled in the correct order.

## Requirements

- Python 3.12+
- networkx (for graph operations)

## Limitations

- The tool only processes dependencies explicitly listed in the SBOM's `dependencies` section
- Components must be listed in the `components` section to be included in the order
- Circular dependencies may result in a partial order
