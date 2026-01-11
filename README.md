# SBOM Compile Order Tool

A Python application that analyses CycloneDX SBOM (Software Bill of Materials) files to determine the optimal compilation order for all dependencies, including transitive dependencies. This tool ensures that when compiling from source, all dependencies are built in the correct order.

## Features

- ✅ **CycloneDX SBOM Parsing**: Reads and parses standard CycloneDX JSON format SBOM files
- ✅ **Dependency Graph Building**: Constructs a complete dependency graph from SBOM data
- ✅ **Transitive Dependency Handling**: Automatically includes dependencies of dependencies
- ✅ **Topological Sorting**: Determines optimal compilation order using graph algorithms
- ✅ **Circular Dependency Detection**: Identifies and handles circular dependencies gracefully
- ✅ **Multiple Output Formats**: Supports both human-readable text and machine-readable JSON output
- ✅ **Component Metadata**: Optional inclusion of full component metadata in output

## Installation

### Prerequisites

- Python 3.12 or higher
- pip (Python package manager)

### Install from Source

```bash
cd sbom-compile-order
pip install -e .
```

This will install the tool and make the `sbom-compile-order` command available in your PATH.

### Install Dependencies Only

If you prefer to run the tool directly without installation:

```bash
cd sbom-compile-order
pip install networkx
```

## Quick Start

```bash
# Basic usage - output compilation order to stdout
sbom-compile-order example_sbom.json

# Output to file in JSON format
sbom-compile-order example_sbom.json -o compile-order.json -f json

# Verbose output with full metadata
sbom-compile-order example_sbom.json -v --include-metadata
```

## Usage

### Command-Line Options

```
sbom-compile-order <sbom-file.json> [OPTIONS]

Arguments:
  sbom_file                 Path to the CycloneDX SBOM JSON file (required)

Options:
  -o, --output FILE         Output file path (default: stdout)
  -f, --format FORMAT       Output format: text or json (default: text)
  -v, --verbose             Enable verbose output
  --include-metadata         Include component metadata in output
  -h, --help                Show help message
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
├── README.md                    # This file
├── USAGE.md                     # Detailed usage guide
├── pyproject.toml               # Project configuration and dependencies
├── example_sbom.json             # Example SBOM file for testing
└── sbom_compile_order/
    ├── __init__.py              # Package initialization
    ├── parser.py                # SBOM parsing logic
    ├── graph.py                 # Dependency graph and topological sort
    ├── output.py                # Output formatters (text, JSON)
    └── cli.py                   # Command-line interface
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

```bash
# Run the tool with example SBOM
python3 -m sbom_compile_order.cli example_sbom.json

# Test JSON output
python3 -m sbom_compile_order.cli example_sbom.json -f json
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
