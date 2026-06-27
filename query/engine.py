"""QueryEngine: thin graph query wrapper over SemanticReferenceGraph.

No duplicated analysis. No independent bytecode scanning.
Every method is a pure graph traversal against the single unified graph.
"""
from __future__ import annotations

from typing import Any, Callable, Optional

from ir.semantic_graph import (
    SemanticReferenceGraph,
    SuspiciousItem,
    TraceNode,
    NT_OBJECT, NT_ROOM, NT_SPRITE, NT_CODE, NT_FLAG,
    NT_INSTANCE, NT_STRING, NT_SOUND, NT_FUNCTION, NT_SCRIPT,
    READS_FLAG, WRITES_FLAG, CREATES, HAS_EVENT, HAS_CREATION_CODE,
    IS_INSTANCE_OF, CONTAINS, CONNECTED_TO, REFERENCES,
    REFERENCES_SOUND, CALLS, OWNS, ENTRY_POINT,
)


ProgressCB = Optional[Callable[[int, int, str], None]]


class QueryEngine:
    """Minimal stateless query interface over the pre-built graph."""

    def __init__(self, game, graph: SemanticReferenceGraph) -> None:
        self.game = game
        self.graph = graph

    def _done(self, cb: ProgressCB, msg: str = "Done") -> None:
        if cb:
            cb(1, 1, msg)

    # ── TRACE ────────────────────────────────────────────────────────

    def trace(self, pattern: str, on_progress: ProgressCB = None) -> list[dict[str, Any]]:
        """Semantic graph traversal showing the relationship chain."""
        raw = self.graph.trace(pattern)
        results = []
        for tn in raw:
            chains = []
            for rel, target, tname in tn.edges[:12]:
                direction = "\u2190" if rel.startswith("<--") else "\u2192"
                r = rel.replace("<--", "")
                chains.append(f"{direction} {r} {tname}")
            results.append({
                "type": tn.type,
                "name": tn.name,
                "node_id": tn.node_id,
                "summary": "; ".join(chains) if chains else "Isolated node",
                "edge_count": len(tn.edges),
            })
        self._done(on_progress, "Trace complete")
        return results[:100]

    # ── WHO_USES ─────────────────────────────────────────────────────

    def who_uses(self, resource_name: str, on_progress: ProgressCB = None) -> dict[str, list[str]]:
        """Inverse graph query — grouped incoming references."""
        result = self.graph.who_uses(resource_name)
        self._done(on_progress, "Query complete")
        return result

    # ── WHY OBJECT ───────────────────────────────────────────────────

    def why_object(self, name: str, on_progress: ProgressCB = None) -> dict[str, Any]:
        """Full semantic trace for a single object. Never crashes."""
        try:
            obj = next((o for o in self.game.objects.values() if o.name == name), None)
        except Exception:
            return {"error": f"Failed to search for object '{name}'"}
        if not obj:
            return {"error": f"Object '{name}' not found"}

        node = f"obj_{obj.id}"
        if not self.graph.G.has_node(node):
            return {"error": f"Object '{name}' not in graph"}

        inc = self.graph.incoming(node)
        out = self.graph.outgoing(node)

        placed_in = []
        created_by = []
        for e in inc:
            try:
                if e.get("relation") == IS_INSTANCE_OF and e.get("type") == NT_INSTANCE:
                    for src2, _, d2 in self.graph.G.in_edges(e["source"], data=True):
                        if d2.get("relation") == CONTAINS:
                            rname = self.graph.G.nodes[src2].get("name", src2)
                            placed_in.append(rname)
                if e.get("relation") == CREATES:
                    created_by.append(f"{e.get('name', '?')} ({e.get('source', '?')})")
            except Exception:
                continue

        sprite = None
        parent = None
        children = []
        events = []
        for e in out:
            try:
                if e.get("relation") == "uses_sprite":
                    sprite = e.get("name")
                if e.get("relation") == "inherits":
                    parent = e.get("name")
            except Exception:
                continue

        # Get event info from the object itself, not graph (more reliable)
        try:
            for ev in obj.events:
                events.append((ev.event_type, ev.subtype))
        except Exception:
            pass

        for e in inc:
            try:
                if e.get("relation") == "inherits":
                    children.append(e.get("name", "?"))
            except Exception:
                continue

        self._done(on_progress, "Analysis complete")
        return {
            "name": obj.name,
            "id": obj.id,
            "sprite": sprite or "None",
            "parent": parent or "None",
            "depth": getattr(obj, "depth", 0),
            "persistent": getattr(obj, "persistent", False),
            "visible": getattr(obj, "visible", True),
            "events": events[:30],
            "children": children[:20],
            "placed_in_rooms": placed_in,
            "created_dynamically_by": created_by,
            "incoming_refs": [f"{e.get('name', '?')} ({e.get('relation', '?')})" for e in inc[:15]],
            "outgoing_refs": [f"{e.get('name', '?')} ({e.get('relation', '?')})" for e in out[:15]],
            "in_degree": self.graph.G.in_degree(node),
            "out_degree": self.graph.G.out_degree(node),
        }

    # ── ROOM ─────────────────────────────────────────────────────────

    def show_room(self, name: str) -> dict[str, Any]:
        room = next((r for r in self.game.rooms.values() if r.name == name), None)
        if not room:
            return {"error": f"Room '{name}' not found"}

        node = f"room_{room.id}"
        inc = self.graph.incoming(node)
        out = self.graph.outgoing(node)

        instances_info = []
        for e in out:
            if e["relation"] == CONTAINS and e["type"] == NT_INSTANCE:
                inst_node = e["target"]
                obj_edges = self.graph.outgoing(inst_node, IS_INSTANCE_OF)
                obj_name = obj_edges[0]["name"] if obj_edges else "?"
                cc_edges = self.graph.outgoing(inst_node, HAS_CREATION_CODE)
                instances_info.append({
                    "object": obj_name,
                    "instance_id": self.graph.G.nodes[inst_node].get("id"),
                    "x": self.graph.G.nodes[inst_node].get("x", 0),
                    "y": self.graph.G.nodes[inst_node].get("y", 0),
                    "has_creation_code": len(cc_edges) > 0,
                })

        incoming_names = [
            f"{e['name']} ({e['relation']})" for e in inc[:20]
        ]
        outgoing_names = [
            f"{e['name']} ({e['relation']})" for e in out[:20] if e["type"] != NT_INSTANCE
        ]

        return {
            "name": room.name,
            "size": f"{room.width}x{room.height}",
            "speed": room.speed,
            "persistent": room.persistent,
            "instances": instances_info,
            "view_count": len(room.views),
            "background_count": len(room.backgrounds),
            "has_creation_code": room.creation_code_id >= 0,
            "reachable": room.id not in self.graph.unreachable_rooms(),
            "incoming_transitions": incoming_names,
            "outgoing_transitions": outgoing_names,
        }

    # ── FLAG ─────────────────────────────────────────────────────────

    def who_writes_flag(self, flag_idx: int) -> list[str]:
        """Find code that writes to a flag via graph edges."""
        flag_node = f"flag_{flag_idx}"
        writers = self.graph.incoming(flag_node, WRITES_FLAG)
        readers = self.graph.incoming(flag_node, READS_FLAG)
        result = [
            f"{e['name']} ({e['source']}) — writes"
            for e in writers
        ] + [
            f"{e['name']} ({e['source']}) — reads"
            for e in readers
        ]
        return result[:30]

    # ── UNREACHABLE ──────────────────────────────────────────────────

    def unreachable_rooms(self) -> list[str]:
        return sorted(
            self.game.room_by_id(rid).name
            for rid in self.graph.unreachable_rooms()
            if self.game.room_by_id(rid)
        )

    def unreachable_dialogue(self, on_progress: ProgressCB = None) -> list[tuple[str, str]]:
        """Find strings not referenced by any code entry, via the graph."""
        results = []
        for nid, data in self.graph.G.nodes(data=True):
            if data.get("type") != NT_STRING:
                continue
            str_id = data.get("id", -1)
            if str_id < 0:
                continue
            inc = self.graph.incoming(nid, REFERENCES)
            if not inc:
                text = data.get("name", "")
                results.append((f"str[{str_id}]", text[:80]))
        self._done(on_progress, f"Found {len(results)} unused strings")
        return results[:200]

    def dead_objects(self, on_progress: ProgressCB = None) -> list[str]:
        """Objects with no path from any runtime root, via the graph."""
        dead = self.graph.dead_resources()
        result = sorted(dead.get(NT_OBJECT, []))
        self._done(on_progress, f"Found {len(result)} dead objects")
        return result

    # ── SECRET ───────────────────────────────────────────────────────

    def hidden_resources(self, on_progress: ProgressCB = None) -> list[SuspiciousItem]:
        """Find suspicious resources via graph property inspection."""
        items = self.graph.suspicious_resources()
        self._done(on_progress, f"Found {len(items)} suspicious items")
        return items

    # ── SEARCH ───────────────────────────────────────────────────────

    def search(self, pattern: str, on_progress: ProgressCB = None) -> list[dict[str, Any]]:
        return self.trace(pattern, on_progress=on_progress)
