"""ResourceGraph: precomputed relationship graphs over resolved game resources.

Builds four directed graphs after resolver has indexed everything:
  1. room_graph    — room transitions
  2. call_graph    — code-to-code call relationships
  3. object_graph  — room→instance→object→parent→sprite
  4. flag_graph    — flag read/write dependencies

All graphs use resolved object references, never raw IDs.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Optional

import networkx as nx

from code.opcodes import Opcode, CallKind, is_call


class ResourceGraph:
    def __init__(self, game, resolver) -> None:
        self.game = game
        self.resolver = resolver
        self.room: nx.DiGraph = nx.DiGraph()
        self.call: nx.DiGraph = nx.DiGraph()
        self.object: nx.DiGraph = nx.DiGraph()
        self.flag: nx.DiGraph = nx.DiGraph()

    def build_all(self) -> None:
        self._build_room_graph()
        self._build_call_graph()
        self._build_object_graph()

    def _build_room_graph(self) -> None:
        """Build room graph from resolver's room_transitions.

        If transitions are found, connect first_room -> target for each.
        Otherwise fall back to connecting rooms by instance-sharing (rooms
        that reference the same object are connected) to produce a useful
        graph even without detected transition calls.
        """
        for room in self.game.rooms.values():
            self.room.add_node(room.id, name=room.name, type="room")

        if not self.game.rooms:
            return

        first_room_id = min(self.game.rooms.keys())

        if self.resolver.room_transitions:
            for code_id, trans_type, target_room_id in self.resolver.room_transitions:
                if target_room_id is None or target_room_id not in self.game.rooms:
                    continue
                if first_room_id in self.game.rooms and target_room_id in self.game.rooms:
                    self.room.add_edge(first_room_id, target_room_id, type=trans_type)
        else:
            # Fallback: connect rooms that share object instances
            obj_to_rooms: dict[int, set[int]] = defaultdict(set)
            for room_id, room in self.game.rooms.items():
                for inst in room.instances:
                    if inst.object_id >= 0:
                        obj_to_rooms[inst.object_id].add(room_id)

            added = set()
            for obj_id, room_ids in obj_to_rooms.items():
                rid_list = sorted(room_ids)
                for i in range(1, len(rid_list)):
                    edge = (rid_list[0], rid_list[i])
                    if edge not in added:
                        self.room.add_edge(edge[0], edge[1],
                            type="shares_object", label=f"obj_{obj_id}")
                        added.add(edge)

    def _build_call_graph(self) -> None:
        """Build call graph using resolver's callee/caller maps.

        Nodes are CODE entry IDs, edges are function calls.
        """
        # Add all CODE entries as nodes
        for cid, entry in self.game.code_entries.items():
            label = self.resolver.owner_of(cid) or entry.name or f"code_{cid}"
            self.call.add_node(cid, name=label, type="code")

        # Add edges from resolver's callee map
        for caller_id, callees in self.resolver.callees.items():
            if caller_id not in self.game.code_entries:
                continue
            for callee_id in callees:
                if callee_id in self.game.code_entries:
                    self.call.add_edge(caller_id, callee_id, type="calls")

    def _build_object_graph(self) -> None:
        """Build object graph connecting rooms → instances → objects → parents → sprites."""
        for obj in self.game.objects.values():
            self.object.add_node(f"obj_{obj.id}", id=obj.id, name=obj.name, type="object")

        # Room → instance → object edges
        for room_id, instances in self.resolver.room_instances.items():
            room = self.game.room_by_id(room_id)
            if room is None:
                continue
            room_node = f"room_{room_id}"
            self.object.add_node(room_node, id=room_id, name=room.name, type="room")
            for inst in instances:
                obj = self.game.object_by_id(inst.object_id)
                if obj is None:
                    continue
                obj_node = f"obj_{inst.object_id}"
                inst_node = f"inst_{inst.instance_id}"
                self.object.add_node(inst_node, id=inst.instance_id, type="instance")
                self.object.add_edge(room_node, inst_node, relation="contains")
                self.object.add_edge(inst_node, obj_node, relation="is_instance_of")

        # Inheritance edges: child → parent
        for child_id, parent in self.resolver.object_parent.items():
            child_node = f"obj_{child_id}"
            parent_node = f"obj_{parent.id}"
            self.object.add_edge(child_node, parent_node, relation="inherits")

        # Sprite usage: object → sprite
        for obj_id, sprite in self.resolver.object_sprite.items():
            obj_node = f"obj_{obj_id}"
            spr_node = f"spr_{sprite.id}"
            self.object.add_node(spr_node, id=sprite.id, name=sprite.name, type="sprite")
            self.object.add_edge(obj_node, spr_node, relation="uses_sprite")

    def unreachable_rooms(self) -> set[int]:
        if not self.room.nodes():
            return {r.id for r in self.game.rooms.values()}
        sources = [n for n in self.room.nodes() if self.room.in_degree(n) == 0]
        if not sources:
            return set()
        reachable = set()
        for s in sources:
            reachable.update(nx.dfs_preorder_nodes(self.room, s))
        return {r.id for r in self.game.rooms.values()} - reachable

    def room_graph_summary(self) -> dict:
        return {
            "nodes": self.room.number_of_nodes(),
            "edges": self.room.number_of_edges(),
            "components": nx.number_weakly_connected_components(self.room) if self.room.number_of_nodes() > 0 else 0,
            "unreachable": sorted(self.unreachable_rooms()),
        }

    def call_graph_summary(self) -> dict:
        return {
            "nodes": self.call.number_of_nodes(),
            "edges": self.call.number_of_edges(),
        }
