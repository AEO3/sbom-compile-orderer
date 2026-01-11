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
# Output compilation order to stdout (text format)
sbom-compile-order example_sbom.json

# Output to file in JSON format
sbom-compile-order example_sbom.json -o compile-order.json -f json

# Verbose output with metadata
sbom-compile-order example_sbom.json -v --include-metadata
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

### CSV Format
```csv
Order,Source URL,Package Name,Version/Tag
1,https://github.com/example/base.git,org.example:base,0.5.0
2,https://github.com/example/core.git,org.example:core,1.0.0
3,https://github.com/example/utils.git,org.example:utils,2.0.0
4,https://github.com/example/api.git,org.example:api,3.0.0
```

The CSV format is particularly useful for:
- Importing into spreadsheets for analysis
- Scripting build processes
- Tracking source URLs and versions for compilation

**CSV Columns:**
- **Order**: Sequential compilation order number
- **Source URL**: Source repository URL extracted from SBOM external references (VCS URLs preferred)
- **Package Name**: Full package identifier (group:name format)
- **Version/Tag**: Version or tag to use when checking out the source code

## Command-Line Options

- `sbom_file`: Path to the CycloneDX SBOM JSON file (required)
- `-o, --output FILE`: Output file path (default: stdout)
- `-f, --format FORMAT`: Output format: `text`, `json`, or `csv` (default: `text`)
- `-v, --verbose`: Enable verbose output showing progress
- `--include-metadata`: Include full component metadata in output

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
