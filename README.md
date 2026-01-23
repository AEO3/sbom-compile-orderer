# SBOM Compile Order Tool

A Python application that analyses CycloneDX SBOM (Software Bill of Materials) files to determine the optimal compilation order for all dependencies, including transitive dependencies. This tool ensures that when compiling from source, all dependencies are built in the correct order.

## Features

- ✅ **CycloneDX SBOM Parsing**: Reads and parses standard CycloneDX JSON format SBOM files
- ✅ **Dependency Graph Building**: Constructs a complete dependency graph from SBOM data
- ✅ **Transitive Dependency Handling**: Automatically includes dependencies of dependencies
- ✅ **Topological Sorting**: Determines optimal compilation order using graph algorithms
- ✅ **Circular Dependency Detection**: Identifies and handles circular dependencies gracefully
- ✅ **Multiple Output Formats**: Supports human-readable text, machine-readable JSON, and CSV output
- ✅ **Component Metadata**: Optional inclusion of full component metadata in output
- ✅ **npm Registry Metadata**: Resolve homepage and license info for npm packages when metadata lookups are enabled

## Installation

### Prerequisites

- Python 3.12 or higher
- pip (Python package manager) or pipx

### Install with pipx (Recommended)

[pipx](https://pipx.pypa.io/) installs Python applications in isolated environments, preventing dependency conflicts:

```bash
# Install from source directory
pipx install .

# Or install from a built wheel
pipx install dist/sbom_compile_order-*.whl

# Or install from Git repository
pipx install git+https://github.com/yourusername/sbom-compile-order.git
```

After installation with pipx, the `sbom-compile-order` command will be available globally.

### Install from Source (Editable Mode)

```bash
cd sbom-compile-order
pip install -e .
```

This will install the tool and make the `sbom-compile-order` command available in your PATH.

### Install from Source (Regular Install)

```bash
cd sbom-compile-order
pip install .
```

### Install from Requirements File

```bash
cd sbom-compile-order
pip install -r requirements.txt
pip install -e .
```

### Install with Development Dependencies

```bash
cd sbom-compile-order
pip install -e ".[dev]"
# Or using requirements file:
pip install -r requirements-dev.txt
```

### Install Dependencies Only

If you prefer to run the tool directly without installation:

```bash
cd sbom-compile-order
pip install -r requirements.txt
```

### Build Distribution Packages

To build wheel and source distribution packages:

```bash
cd sbom-compile-order
pip install build
python -m build
```

This will create `dist/` directory with `.whl` and `.tar.gz` files that can be installed via pip:

```bash
pip install dist/sbom_compile_order-*-py3-none-any.whl
```

## Quick Start

```bash
# Basic usage - output compilation order to CSV (default format)
sbom-compile-order examples/example_sbom.json

# Use a different output directory (writes compile-order.json there)
sbom-compile-order examples/example_sbom.json -o out -f json

# Use output directory for CSV (writes compile-order.csv, enhanced.csv, poms, etc. there)
sbom-compile-order examples/example_sbom.json -o out -f csv

# Verbose output with full metadata
sbom-compile-order examples/example_sbom.json -v --include-metadata
```

## Usage Examples

### Basic Examples

```bash
# Generate CSV compilation order (saved to cache/compile-order.csv by default)
sbom-compile-order my-project.sbom.json

# Generate JSON output to stdout
sbom-compile-order my-project.sbom.json -f json

# Generate text output to a file (in output directory out/)
sbom-compile-order my-project.sbom.json -f text -o out

# Verbose mode to see detailed processing information
sbom-compile-order my-project.sbom.json -v
```

### Advanced Examples

```bash
# Download POM files from Maven Central and create enhanced CSV
sbom-compile-order my-project.sbom.json --poms

# Look up package metadata (homepage, license) from Maven Central and npm registry
sbom-compile-order my-project.sbom.json -m

# Resolve transitive dependencies and create extended CSV
sbom-compile-order my-project.sbom.json -r --max-dependency-depth 3

# Extract dependencies from POM files and create leaves.csv
sbom-compile-order my-project.sbom.json --leaves

# Filter out specific group IDs
sbom-compile-order my-project.sbom.json --ignore-group-ids com.example org.test

# Exclude specific component types
sbom-compile-order my-project.sbom.json --exclude-types application

# Exclude specific package types (e.g., npm, pypi)
sbom-compile-order my-project.sbom.json --exclude-package-types npm pypi

# Download npm packages to cache/npm directory
sbom-compile-order my-project.sbom.json --npm

# Clone repositories to find POM files (instead of Maven Central)
sbom-compile-order my-project.sbom.json -c

# Combine multiple options: download POMs, resolve dependencies, verbose output
sbom-compile-order my-project.sbom.json --poms -r -v --max-dependency-depth 2
```

### Output Files

The tool creates several output files in the output directory (default: `cache/`; override with `-o`):

- **compile-order.csv**: Base compilation order (created by default)
- **enhanced.csv**: Enhanced CSV with package metadata (Maven Central and npm registry), POM downloads, and artifact URLs (created with `-m` or `--poms`)
- **extended-dependencies.csv**: Extended dependencies with transitive resolution (created with `-r`)
- **leaves.csv**: Dependencies found in POM files but not in compile-order.csv (created with `--leaves`)
- **poms/**: Cached POM files (when `--poms` is used)
- **jars/**: Cached JAR/WAR artifacts (when `--pull-package` with `--jar`/`--war` is used)
- **npm/**: Cached npm package tarballs (when `--npm` is used)
- **sbom-compile-order.log**: Detailed log file with all processing information

## Usage

### Command-Line Options

```
sbom-compile-order <sbom-file.json> [OPTIONS]

Arguments:
  sbom_file                 Path to the CycloneDX SBOM JSON file (required)

Output Options:
  -o, --output DIR          Working directory for all generated files (default: cache). For text/json without -o, stdout.
  -f, --format FORMAT       Output format: text, json, or csv (default: csv)
  -v, --verbose             Enable verbose output
  -i, --include-metadata     Include component metadata in output

Filtering Options:
  --ignore-group-ids IDS    Group IDs to ignore (space-separated)
  --exclude-types TYPES      Component types to exclude (space-separated)
  --exclude-package-types TYPES    Package types to exclude (space-separated, e.g. npm pypi)

Maven Central Integration:
  -m, --maven-central-lookup    Look up package metadata (homepage, license) from Maven Central
                                for Maven packages and from the npm registry for npm packages
  --poms                        Download POM files from Maven Central
  --pull-package                Download packages (JARs) from Maven Central
  --jar                         Download JAR artifacts when pulling packages (implies --pull-package)
  --war                         Download WAR artifacts when pulling packages (implies --pull-package)
  -c, --clone-repos              Clone repositories to find POM files

npm Integration:
  --npm                         Download npm package tarballs from the npm registry

Dependency Resolution:
  -r, --resolve-dependencies     Resolve transitive dependencies
  -d, --max-dependency-depth N   Maximum depth to traverse dependencies (default: 2)
  -e, --extended-csv FILE        Filename for extended CSV in output directory
  --dependencies-output FILE     Filename for dependencies CSV in output directory

POM Analysis:
  --leaves                       Extract dependencies from POM files and create leaves.csv
  --leaves-output FILE           Filename for leaves CSV in output directory

Help:
  -h, --help                     Show help message
```

### Example Output

**Text Format:**
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

**JSON Format:**
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
    "has_circular_dependencies": false
  }
}
```

**CSV Format (compile-order.csv):**

The CSV has 17 columns. Example (abbreviated):

```csv
Order,Group ID,Package Name,Version/Tag,PURL,Ref,Type,Scope,Provided URL,Repo URL,Dependencies,POM,AUTH,Homepage URL,License Type,External Dependency Count,Cyclical Dependencies
1,org.example:base,base,0.5.0,pkg:maven/org.example/base@0.5.0,,library,,https://github.com/example/base.git,,0,,,https://example.com,Apache-2.0,0,
```

- **Order**: Compilation order number
- **Group ID**: Package identifier (group:name for Maven; name for npm)
- **Package Name**: Package name only
- **Version/Tag**: Version or tag
- **PURL**: Package URL (e.g. `pkg:maven/...` or `pkg:npm/...`)
- **Ref**, **Type**, **Scope**: SBOM component fields
- **Provided URL**: Source URL from SBOM external references
- **Repo URL**: Git-cloneable repo (filled in enhanced.csv from POM/npm)
- **Dependencies**: Incoming dependency count
- **POM**, **AUTH**: POM filename and auth flag (filled in enhanced.csv)
- **Homepage URL**, **License Type**: From Maven Central/npm (filled in enhanced.csv)
- **External Dependency Count**: Dependencies not in the SBOM (when `-r` used)
- **Cyclical Dependencies**: Cycle description when circular deps exist

## How It Works

1. **Parse SBOM**: The tool reads the CycloneDX JSON file and extracts:
   - All components (libraries, applications, etc.)
   - Dependency relationships between components

2. **Build Dependency Graph**: Creates a directed graph where:
   - Each component is a node
   - Edges represent dependencies (if A depends on B, B must be compiled before A)

3. **Topological Sort**: Determines compilation order by:
   - Finding components with no dependencies first
   - Then components whose dependencies are already in the order
   - Continuing until all components are ordered

4. **Handle Transitive Dependencies**: The graph includes all dependency relationships, so transitive dependencies are automatically handled. For example:
   - If Component A depends on B, and B depends on C
   - The compilation order will be: C → B → A
   - This ensures C is compiled before B, and B before A

## Project Structure

```
sbom-compile-order/
├── README.md                     # This file
├── USAGE.md                      # Detailed usage guide
├── pyproject.toml                # Project configuration and dependencies
├── examples/                     # Example SBOM files
│   ├── example_sbom.json
│   ├── juice-shop-bom.json
│   └── keycloak-10.0.2.sbom.json
└── sbom_compile_order/
    ├── __init__.py               # Package initialization and csv field size limit
    ├── cli.py                    # Command-line interface
    ├── parser.py                 # SBOM parsing and PURL handling
    ├── graph.py                  # Dependency graph and topological sort
    ├── output.py                 # Output formatters (text, JSON, CSV)
    ├── enhanced_csv.py           # Enhanced CSV with metadata and POM/JAR URLs
    ├── hash_cache.py             # Hash-based caching for incremental runs
    ├── dependency_resolver.py    # Transitive dependencies (mvnrepository.com)
    ├── package_metadata.py       # Unified metadata (Maven Central + npm registry)
    ├── maven_central.py          # Maven Central API client
    ├── npm_registry.py           # npm registry API client
    ├── pom_downloader.py         # POM file downloader
    ├── package_downloader.py     # JAR/WAR downloader
    ├── npm_package_downloader.py # npm tarball downloader
    ├── parallel_downloader.py    # Background POM, artifact, and npm downloads
    └── pom_dependency_extractor.py # POM parsing and leaves.csv
```

## Requirements

- **Python**: 3.12 or higher
- **networkx**: >=3.2 (for graph operations and topological sorting)

## Use Cases

This tool is particularly useful when:

- **Compiling from Source**: You need to compile all dependencies from source and want to know the correct order
- **Build System Integration**: Integrating SBOM analysis into CI/CD pipelines
- **Dependency Analysis**: Understanding the complete dependency graph of your project
- **Build Optimization**: Determining parallel build opportunities (components without dependencies can be built in parallel)

## Limitations

- The tool only processes dependencies explicitly listed in the SBOM's `dependencies` section
- Components must be listed in the `components` section to be included in the order
- Circular dependencies may result in a partial order (the tool will warn you)

## Development

### Running Tests

Requires Python 3.12+ (see `requires-python` in `pyproject.toml`).

```bash
# Run the tool with example SBOM (from project root)
python3 -m sbom_compile_order.cli examples/example_sbom.json

# Test JSON output
python3 -m sbom_compile_order.cli examples/example_sbom.json -f json

# Run pytest (use Python 3.12: python3.12 -m pytest if available)
pytest tests/ -v
```

### Code Style

The project follows Python best practices:
- Type hints throughout
- Comprehensive docstrings
- Pylint compliance
- Canadian spelling (as per project standards)

## Contributing

When contributing to this project:

1. Follow the existing code style and structure
2. Add docstrings to all functions and classes
3. Use type hints
4. Handle exceptions appropriately (avoid catching generic `Exception` without good reason)
5. Update version numbers when adding features (Major.Minor.feature.fix format)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## See Also

- [USAGE.md](USAGE.md) - Detailed usage guide with examples
- [CycloneDX Specification](https://cyclonedx.org/) - Official CycloneDX SBOM format documentation
