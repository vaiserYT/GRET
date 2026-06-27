from __future__ import annotations

from collections import defaultdict
from typing import Any, Optional

import networkx as nx

from core.models import (
    ObjectInfo,
    ProjectIndex,
    Reference,
    ReferenceType,
    ResourceType,
    RoomInfo,
    RoomTransition,
    ScriptInfo,
)


class DependencyGraph:
    def __init__(self) -> None:
        self._graph: nx.DiGraph = nx.DiGraph()
        self._resource_types: dict[str, ResourceType] = {}

    def build(self, index: ProjectIndex) -> None:
        self._graph.clear()
        self._resource_types = dict(index.all_resources)

        for obj_name, obj_info in index.objects.items():
            self._add_node(obj_name, ResourceType.OBJECT, obj_info)
        for room_name, room_info in index.rooms.items():
            self._add_node(room_name, ResourceType.ROOM, room_info)
        for script_name, script_info in index.scripts.items():
            self._add_node(script_name, ResourceType.SCRIPT, script_info)
        for sprite_name in index.sprites:
            self._add_node(sprite_name, ResourceType.SPRITE)
        for sound_name in index.sounds:
            self._add_node(sound_name, ResourceType.SOUND)
        for font_name in index.fonts:
            self._add_node(font_name, ResourceType.FONT)

        for obj_name, obj_info in index.objects.items():
            if obj_info.sprite and obj_info.sprite in self._graph:
                self._add_edge(obj_name, obj_info.sprite, "uses_sprite")
            if obj_info.parent and obj_info.parent in self._graph:
                self._add_edge(obj_name, obj_info.parent, "inherits")

        for room_name, room_info in index.rooms.items():
            for inst in room_info.instances:
                if inst.object_name in self._graph:
                    self._add_edge(room_name, inst.object_name, "contains")
                    self._add_edge(inst.object_name, room_name, "placed_in")

        for transition in index.transitions:
            if transition.source_room in self._graph and transition.target_room in self._graph:
                self._add_edge(
                    transition.source_room,
                    transition.target_room,
                    f"transitions_{transition.transition_type}",
                )

        for target, refs in index.call_targets.items():
            for ref in refs:
                if ref.source.resource_name in self._graph and target in self._graph:
                    edge_type = ref.ref_type.name.lower()
                    self._add_edge(ref.source.resource_name, target, edge_type)

        self._add_script_call_edges(index)
        self._add_object_event_edges(index)

    def _add_node(self, name: str, rtype: ResourceType, data: Any = None) -> None:
        attrs = {"type": rtype.name.lower()}
        if data is not None:
            attrs["data"] = data
        self._graph.add_node(name, **attrs)

    def _add_edge(self, source: str, target: str, label: str = "") -> None:
        if self._graph.has_node(source) and self._graph.has_node(target):
            self._graph.add_edge(source, target, label=label)

    def _add_script_call_edges(self, index: ProjectIndex) -> None:
        for script_name, script_info in index.scripts.items():
            for func_name, _ in self._extract_function_calls(script_info.code):
                if func_name in index.scripts:
                    self._add_edge(script_name, func_name, "calls")
                if func_name in index.objects:
                    self._add_edge(script_name, func_name, "references")

    def _add_object_event_edges(self, index: ProjectIndex) -> None:
        for obj_name, obj_info in index.objects.items():
            for event_key, event in obj_info.events.items():
                for func_name, _ in self._extract_function_calls(event.code):
                    if func_name in index.scripts:
                        self._add_edge(obj_name, func_name, f"event_{event_key}_calls")
                    if func_name in index.objects:
                        self._add_edge(obj_name, func_name, f"event_{event_key}_references")

    @staticmethod
    def _extract_function_calls(code: str) -> list[tuple[str, int]]:
        import re
        calls: list[tuple[str, int]] = []
        pattern = re.compile(r"(\w+)\s*\(")
        for match in pattern.finditer(code):
            func_name = match.group(1)
            if func_name and len(func_name) > 1 and not func_name.startswith(("if", "for", "while", "switch", "case", "var", "global", "self", "other", "with", "return", "break", "continue", "enum", "try", "catch", "throw", "new", "delete")):
                line_num = code[: match.start()].count("\n") + 1
                calls.append((func_name, line_num))
        return calls

    @property
    def graph(self) -> nx.DiGraph:
        return self._graph

    def subgraph(self, nodes: set[str]) -> nx.DiGraph:
        return self._graph.subgraph(nodes).copy()

    def predecessors(self, node: str) -> list[str]:
        return list(self._graph.predecessors(node)) if self._graph.has_node(node) else []

    def successors(self, node: str) -> list[str]:
        return list(self._graph.successors(node)) if self._graph.has_node(node) else []

    def in_degree(self, node: str) -> int:
        return self._graph.in_degree(node) if self._graph.has_node(node) else 0

    def out_degree(self, node: str) -> int:
        return self._graph.out_degree(node) if self._graph.has_node(node) else 0

    def has_node(self, node: str) -> bool:
        return self._graph.has_node(node)

    def node_count(self) -> int:
        return self._graph.number_of_nodes()

    def edge_count(self) -> int:
        return self._graph.number_of_edges()

    def find_connected_components(self) -> list[set[str]]:
        return list(nx.weakly_connected_components(self._graph))

    def find_cycles(self) -> list[list[str]]:
        try:
            return list(nx.simple_cycles(self._graph))
        except nx.NetworkXNoCycle:
            return []

    def find_isolated_nodes(self) -> list[str]:
        return [n for n in self._graph.nodes() if self._graph.degree(n) == 0]

    def find_sinks(self) -> list[str]:
        return [n for n in self._graph.nodes() if self._graph.out_degree(n) == 0 and self._graph.in_degree(n) > 0]

    def find_sources(self) -> list[str]:
        return [n for n in self._graph.nodes() if self._graph.in_degree(n) == 0 and self._graph.out_degree(n) > 0]

    def shortest_path(self, source: str, target: str) -> Optional[list[str]]:
        try:
            return nx.shortest_path(self._graph, source, target)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    def resource_type(self, name: str) -> Optional[ResourceType]:
        node_data = self._graph.nodes.get(name)
        if node_data:
            type_name = node_data.get("type", "")
            for rt in ResourceType:
                if rt.name.lower() == type_name:
                    return rt
        return self._resource_types.get(name)

    def to_dict(self) -> dict:
        return {
            "nodes": [
                {"id": n, "type": d.get("type", "unknown")}
                for n, d in self._graph.nodes(data=True)
            ],
            "edges": [
                {"source": u, "target": v, "label": d.get("label", "")}
                for u, v, d in self._graph.edges(data=True)
            ],
            "stats": {
                "nodes": self.node_count(),
                "edges": self.edge_count(),
                "components": len(self.find_connected_components()),
                "cycles": len(self.find_cycles()),
                "isolated": len(self.find_isolated_nodes()),
            },
        }

    def find_unreachable_from(self, source: str) -> set[str]:
        if not self._graph.has_node(source):
            return set()
        reachable = set(nx.descendants(self._graph, source))
        reachable.add(source)
        all_nodes = set(self._graph.nodes())
        return all_nodes - reachable

    def find_reachable_to(self, target: str) -> set[str]:
        if not self._graph.has_node(target):
            return set()
        return set(nx.ancestors(self._graph, target))
