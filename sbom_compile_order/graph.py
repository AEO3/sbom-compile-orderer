"""
Dependency Graph Builder and Topological Sorter.

Builds a dependency graph from SBOM data and determines compilation order.
"""

from typing import Dict, List, Optional, Set, Tuple

import networkx as nx

from sbom_compile_order.parser import Component


class DependencyGraph:
    """Manages dependency graph and topological sorting."""

    def __init__(self) -> None:
        """Initialize an empty dependency graph."""
        self.graph = nx.DiGraph()
        self.components: Dict[str, Component] = {}

    def add_component(self, component: Component) -> None:
        """
        Add a component to the graph.

        Args:
            component: Component to add
        """
        identifier = component.get_identifier()
        self.components[identifier] = component
        self.graph.add_node(identifier)

    def add_dependency(self, component_ref: str, dependency_ref: str) -> None:
        """
        Add a dependency relationship.

        Args:
            component_ref: Reference of the component that depends on something
            dependency_ref: Reference of the dependency
        """
        # Ensure both nodes exist
        if component_ref not in self.graph:
            self.graph.add_node(component_ref)
        if dependency_ref not in self.graph:
            self.graph.add_node(dependency_ref)

        # Add edge: dependency -> component (dependency must be built first)
        # So we reverse: component depends on dependency means
        # dependency must come before component in compilation order
        self.graph.add_edge(dependency_ref, component_ref)

    def build_from_parser(
        self, components: Dict[str, Component], dependencies: Dict[str, List[str]]
    ) -> None:
        """
        Build graph from parsed SBOM data.

        Args:
            components: Dictionary of components by identifier
            dependencies: Dictionary mapping component refs to dependency refs
        """
        # Add all components
        for component in components.values():
            self.add_component(component)

        # Add dependency relationships
        for component_ref, dep_refs in dependencies.items():
            for dep_ref in dep_refs:
                # Try to find component by ref
                comp = components.get(component_ref)
                dep_comp = components.get(dep_ref)

                if comp and dep_comp:
                    self.add_dependency(component_ref, dep_ref)
                elif dep_ref in components:
                    # Dependency exists but component might not be in components dict
                    # Add it anyway - it might be referenced but not listed
                    self.add_dependency(component_ref, dep_ref)

    def get_compilation_order(self) -> Tuple[List[str], bool]:
        """
        Get compilation order using topological sort.

        Returns:
            Tuple of (ordered list of component identifiers, has_circular_deps)
        """
        try:
            # Perform topological sort
            order = list(nx.topological_sort(self.graph))
            return order, False
        except (nx.NetworkXUnfeasible, nx.NetworkXError) as exc:
            # Circular dependency detected
            # NetworkXUnfeasible is raised when graph has cycles
            # Also catch NetworkXError in case it wraps NetworkXUnfeasible
            if isinstance(exc, nx.NetworkXUnfeasible) or "circular" in str(exc).lower() or "cycle" in str(exc).lower():
                # Try to get a partial order by removing cycles
                # Use strongly connected components to detect cycles
                try:
                    cycles = list(nx.simple_cycles(self.graph))
                    if cycles:
                        # Return a partial order by breaking cycles
                        # Remove edges that create cycles (heuristic: remove last edge)
                        temp_graph = self.graph.copy()
                        for cycle in cycles:
                            if len(cycle) > 1:
                                # Remove edge from last to first in cycle
                                temp_graph.remove_edge(cycle[-1], cycle[0])

                        try:
                            order = list(nx.topological_sort(temp_graph))
                            return order, True
                        except (nx.NetworkXUnfeasible, nx.NetworkXError):
                            pass

                    # If we can't resolve, return nodes in arbitrary order
                    return list(self.graph.nodes()), True
                except Exception as cycle_exc:  # pylint: disable=broad-exception-caught
                    # If cycle detection fails, still return nodes with has_circular=True
                    return list(self.graph.nodes()), True

            # Re-raise if it's not a cycle-related error
            raise

    def get_all_dependencies(self, component_ref: str) -> Set[str]:
        """
        Get all transitive dependencies for a component.

        Args:
            component_ref: Reference of the component

        Returns:
            Set of all dependency identifiers (transitive closure)
        """
        if component_ref not in self.graph:
            return set()

        # Get all ancestors (dependencies) of this node
        try:
            ancestors = set(nx.ancestors(self.graph, component_ref))
            return ancestors
        except (nx.NetworkXError, KeyError):
            return set()

    def get_dependents(self, component_ref: str) -> Set[str]:
        """
        Get all components that depend on this component.

        Args:
            component_ref: Reference of the component

        Returns:
            Set of all dependent component identifiers
        """
        if component_ref not in self.graph:
            return set()

        try:
            descendants = set(nx.descendants(self.graph, component_ref))
            return descendants
        except (nx.NetworkXError, KeyError):
            return set()

    def has_circular_dependencies(self) -> bool:
        """
        Check if the graph has circular dependencies.

        Returns:
            True if circular dependencies exist, False otherwise
        """
        try:
            nx.topological_sort(self.graph)
            return False
        except nx.NetworkXUnfeasible:
            return True

    def get_cycles_for_component(self, component_ref: str) -> List[List[str]]:
        """
        Get all cycles that involve a specific component.

        Args:
            component_ref: Reference of the component to check

        Returns:
            List of cycles (each cycle is a list of component refs)
        """
        if component_ref not in self.graph:
            return []

        try:
            # Get all simple cycles in the graph
            all_cycles = list(nx.simple_cycles(self.graph))
            # Filter to only cycles that include this component
            component_cycles = [
                cycle for cycle in all_cycles if component_ref in cycle
            ]
            return component_cycles
        except Exception:  # pylint: disable=broad-exception-caught
            return []

    def format_cycles_for_component(self, component_ref: str) -> str:
        """
        Format cycles for a component as a string for CSV output.

        Args:
            component_ref: Reference of the component to check

        Returns:
            String representation of cycles, or empty string if no cycles
        """
        cycles = self.get_cycles_for_component(component_ref)
        if not cycles:
            return ""

        # Format cycles as: "cycle1_component1->cycle1_component2->...; cycle2_component1->..."
        cycle_strings = []
        for cycle in cycles:
            # Create a cycle string: comp1->comp2->comp3->comp1
            cycle_str = "->".join(cycle)
            # Close the cycle by adding the first component at the end
            if len(cycle) > 1:
                cycle_str += f"->{cycle[0]}"
            cycle_strings.append(cycle_str)

        return "; ".join(cycle_strings)

    def get_statistics(self) -> Dict:
        """
        Get graph statistics.

        Returns:
            Dictionary with graph statistics
        """
        return {
            "total_components": self.graph.number_of_nodes(),
            "total_dependencies": self.graph.number_of_edges(),
            "has_circular_dependencies": self.has_circular_dependencies(),
            "strongly_connected_components": nx.number_strongly_connected_components(
                self.graph
            ),
        }
