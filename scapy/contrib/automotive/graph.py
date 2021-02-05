# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = Graph for AutomotiveTestCaseExecutor
# scapy.contrib.status = library

from collections import defaultdict

from scapy.compat import Union, List, Optional, Dict, Tuple, Set, TYPE_CHECKING
from scapy.contrib.automotive.ecu import EcuState
from scapy.contrib.automotive.profiler import Profiler
from scapy.error import log_interactive

_Edge = Tuple[EcuState, EcuState]

if TYPE_CHECKING:
    from scapy.contrib.automotive.enumerator import _TransitionTuple


class Graph(object):
    def __init__(self):
        # type: () -> None
        """
        self.edges is a dict of all possible next nodes
        e.g. {'X': ['A', 'B', 'C', 'E'], ...}
        self.__transition_functions has all the transition_functions
        between two nodes, with the two nodes as a tuple as the key
        e.g. {('X', 'A'): 7, ('X', 'B'): 2, ...}
        """
        self.edges = defaultdict(list)  # type: Dict[EcuState, List[EcuState]]
        self.__transition_functions = {}  # type: Dict[_Edge, Optional["_TransitionTuple"]]  # noqa: E501

    def add_edge(self, edge, transition_function=None):
        # type: (_Edge, Optional["_TransitionTuple"]) -> None
        """
        Inserts new edge in directional graph
        :param edge: edge from node to node
        :param transition_function: tuple with enter and cleanup function
        """
        Profiler.write_milestone(repr(edge[1]))
        self.edges[edge[0]].append(edge[1])
        self.__transition_functions[edge] = transition_function

    def get_transition_tuple_for_edge(self, edge):
        # type: (_Edge) -> Optional["_TransitionTuple"]
        try:
            return self.__transition_functions[edge]
        except KeyError:
            return None

    @property
    def transition_functions(self):
        # type: () -> Dict[_Edge, Optional["_TransitionTuple"]]
        return self.__transition_functions

    @property
    def nodes(self):
        # type: () -> Union[List[EcuState], Set[EcuState]]
        return set([n for _, p in self.edges.items() for n in p])

    def render(self, filename="SystemStateGraph.gv"):
        try:
            from graphviz import Digraph
        except ImportError:
            log_interactive.info("Please install graphviz.")
            return

        ps = Digraph(name="SystemStateGraph",
                     node_attr={"fillcolor": "lightgrey",
                                "style": "filled",
                                "shape": "box"},
                     graph_attr={"concentrate": "true"})
        for n in self.nodes:
            ps.node(str(n))

        for e, f in self.__transition_functions.items():
            ps.edge(str(e[0]), str(e[1]))

        ps.render(filename, view=True)

    @staticmethod
    def dijkstra(graph, initial, end):
        # type: (Graph, EcuState, EcuState) -> List[EcuState]
        """
        Compute shortest paths from initial to end in graph
        Partly from https://benalexkeen.com/implementing-djikstras-shortest-path-algorithm-with-python/  # noqa: E501
        :param graph: Graph where path is computed
        :param initial: Start node
        :param end: End node
        :return: A path as list of nodes
        """
        shortest_paths = {initial: (None, 0)}  # type: Dict[EcuState, Tuple[Optional[EcuState], int]]  # noqa: E501
        current_node = initial
        visited = set()

        while current_node != end:
            visited.add(current_node)
            destinations = graph.edges[current_node]
            weight_to_current_node = shortest_paths[current_node][1]

            for next_node in destinations:
                weight = 1 + weight_to_current_node
                if next_node not in shortest_paths:
                    shortest_paths[next_node] = (current_node, weight)
                else:
                    current_shortest_weight = shortest_paths[next_node][1]
                    if current_shortest_weight > weight:
                        shortest_paths[next_node] = (current_node, weight)

            next_destinations = {node: shortest_paths[node] for node in
                                 shortest_paths if node not in visited}
            if not next_destinations:
                return []
            # next node is the destination with the lowest weight
            current_node = min(next_destinations,
                               key=lambda k: next_destinations[k][1])

        # Work back through destinations in shortest path
        last_node = shortest_paths[current_node][0]
        path = [current_node]
        while last_node is not None:
            path.append(last_node)
            last_node = shortest_paths[last_node][0]
        # Reverse path
        path.reverse()
        return path
