"""SemanticReferenceGraph: single unified graph over every game resource.

Every resource (object, room, sprite, sound, code, function, variable,
string, flag, timeline, path, font, script, etc.) is a NODE.

Every relationship (contains, uses_sprite, inherits, calls, creates,
reads_flag, writes_flag, etc.) is an EDGE.

All analysis is done ONCE during graph building. Subsequent queries are
pure graph traversals — no duplicated bytecode scanning, no repeated
string heuristics, no per-command analysis phases.

Build ONE graph. Query ONE graph.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional

import networkx as nx

from code.opcodes import Opcode, is_call


# ── Edge relation constants ──────────────────────────────────────────
CONTAINS         = "contains"
IS_INSTANCE_OF   = "is_instance_of"
USES_SPRITE      = "uses_sprite"
INHERITS         = "inherits"
PLACED_IN        = "placed_in"
CALLS            = "calls"
CALLS_FUNCTION   = "calls_function"
CREATES          = "creates"
DESTROYS         = "destroys"
READS_FLAG       = "reads_flag"
WRITES_FLAG      = "writes_flag"
REFERENCES       = "references"       # generic reference
REFERENCES_SPRITE = "references_sprite"
REFERENCES_SOUND = "references_sound"
REFERENCES_VAR   = "references_variable"
REFERENCES_OBJ   = "references_object"
CONNECTED_TO     = "connected_to"
HAS_EVENT        = "has_event"
HAS_CREATION_CODE = "has_creation_code"
WITH_REF         = "with_reference"
ASSET_GET_REF    = "asset_get_index_ref"
COLLISION_REF    = "collision_reference"
OWNS             = "owns"
ENTRY_POINT      = "entry_point"

# ── Node type constants ──────────────────────────────────────────────
NT_OBJECT    = "object"
NT_ROOM      = "room"
NT_SPRITE    = "sprite"
NT_SOUND     = "sound"
NT_CODE      = "code"
NT_FUNCTION  = "function"
NT_SCRIPT    = "script"
NT_VARIABLE  = "variable"
NT_STRING    = "string"
NT_FLAG      = "flag"
NT_INSTANCE  = "instance"
NT_TIMELINE  = "timeline"
NT_PATH      = "path"
NT_FONT      = "font"
NT_SHADER    = "shader"
NT_SEQUENCE  = "sequence"
NT_BACKGROUND = "background"
NT_SCENE     = "scene"

# ── Helpers ──────────────────────────────────────────────────────────

CREATION_FUNC_PATTERNS = [
    "instance_create", "instance_change", "layer_instance_create",
    "instance_create_region", "instance_copy",
]
EXECUTE_FUNC_PATTERNS = ["event_execute_object", "event_user"]
ASSET_FUNC_PATTERNS = ["asset_get_index", "object_get_name"]
SOUND_FUNC_PATTERNS = ["audio_play_sound", "audio_play_sound_at", "audio_stop_sound"]


def _nid(prefix: str, idx: int) -> str:
    return f"{prefix}_{idx}"


def _parse_nid(nid: str) -> tuple[str, int]:
    prefix, _, rest = nid.partition("_")
    return prefix, int(rest)


# ── Graph node info for trace output ─────────────────────────────────

@dataclass
class TraceNode:
    node_id: str
    type: str
    name: str
    depth: int = 0
    edges: list[tuple[str, str, str]] = field(default_factory=list)  # (relation, target_id, target_name)


@dataclass
class SuspiciousItem:
    name: str
    resource_type: str
    confidence: int
    reasons: list[str] = field(default_factory=list)
    evidence_for: list[str] = field(default_factory=list)
    evidence_against: list[str] = field(default_factory=list)
    details: str = ""

    def __lt__(self, other: SuspiciousItem) -> bool:
        return self.confidence > other.confidence


SUSPICIOUS_NAMES = [
    "test", "debug", "proto", "wip", "placeholder", "tmp", "temp",
    "sandbox", "unused", "legacy", "old_", "backup", "deprecated",
    "hidden", "secret", "easteregg", "bonus", "beta", "unimplemented",
]


# ── The One Graph ────────────────────────────────────────────────────

class SemanticReferenceGraph:
    """Single unified graph over all game resources and their relationships.

    Usage:
        graph = SemanticReferenceGraph(game, resolver)
        graph.build()                          # one-time construction
        graph.incoming("obj_42")               # who references this?
        graph.outgoing("obj_42", CREATES)      # what does this create?
        graph.trace("obj_ch5_LW21")            # full semantic trace
        graph.who_uses("spr_kris_rise")        # inverse query
        graph.suspicious_resources()            # secret-finder
        graph.dead_resources()                 # unreachable
        graph.flag_analysis()                  # flag stats
    """

    def __init__(self, game, resolver) -> None:
        self.game = game
        self.resolver = resolver
        self.G: nx.MultiDiGraph = nx.MultiDiGraph()
        self._built = False

    # ── BUILD ────────────────────────────────────────────────────────

    def build(self) -> None:
        """One-time construction of the entire graph."""
        self._add_resource_nodes()
        self._add_room_instances()
        self._add_object_relationships()
        self._add_code_relationships()
        self._add_call_edges()
        self._add_flag_edges()
        self._add_room_transitions()
        self._add_bytecode_edges()
        self._built = True

    def build_all(self) -> None:
        """Alias for build() — backward compatibility."""
        self.build()

    def _add_resource_nodes(self) -> None:
        """Add every resource as a node with type/name/id attributes."""
        for obj in self.game.objects.values():
            self.G.add_node(_nid("obj", obj.id), type=NT_OBJECT, name=obj.name, id=obj.id)
        for room in self.game.rooms.values():
            self.G.add_node(_nid("room", room.id), type=NT_ROOM, name=room.name, id=room.id)
        for spr in self.game.sprites.values():
            self.G.add_node(_nid("spr", spr.id), type=NT_SPRITE, name=spr.name, id=spr.id)
        for snd in self.game.sounds.values():
            self.G.add_node(_nid("snd", snd.id), type=NT_SOUND, name=snd.name, id=snd.id)
        for cid in self.game.code_entries:
            entry = self.game.code_entries[cid]
            label = self.resolver.owner_of(cid) or entry.name or f"code_{cid}"
            self.G.add_node(_nid("code", cid), type=NT_CODE, name=label, id=cid, raw_name=entry.name)
        for func_id in range(len(self.game.func_names)):
            fname = self.game.func_names[func_id] or f"func_{func_id}"
            self.G.add_node(_nid("func", func_id), type=NT_FUNCTION, name=fname, id=func_id)
        for var_id in self.game.variables:
            var = self.game.variables[var_id]
            self.G.add_node(_nid("var", var_id), type=NT_VARIABLE, name=var.name, id=var_id)
        for str_id in range(len(self.game.strings)):
            s = self.game.string(str_id)
            self.G.add_node(_nid("str", str_id), type=NT_STRING, name=s[:60], id=str_id)
        for name in self.game.scripts:
            self.G.add_node(f"script_{name}", type=NT_SCRIPT, name=name, id=name)
        if hasattr(self.game, "timelines"):
            for t in self.game.timelines.values():
                self.G.add_node(f"timeline_{t.name}", type=NT_TIMELINE, name=t.name, id=t.name)
        if hasattr(self.game, "paths"):
            for p in self.game.paths.values():
                self.G.add_node(f"path_{p.name}", type=NT_PATH, name=p.name, id=p.name)
        if hasattr(self.game, "fonts"):
            for f in self.game.fonts.values():
                self.G.add_node(f"font_{f.name}", type=NT_FONT, name=f.name, id=f.id)
        if hasattr(self.game, "sequences"):
            for s in self.game.sequences.values():
                self.G.add_node(f"seq_{s.name}", type=NT_SEQUENCE, name=s.name, id=s.name)
        if hasattr(self.game, "backgrounds"):
            for b in self.game.backgrounds.values():
                self.G.add_node(f"bg_{b.name}", type=NT_BACKGROUND, name=b.name, id=b.name)

    def _add_room_instances(self) -> None:
        """Room → instance → object edges."""
        for room_id, instances in self.resolver.room_instances.items():
            room_node = _nid("room", room_id)
            for inst in instances:
                inst_node = _nid("inst", inst.instance_id)
                self.G.add_node(inst_node, type=NT_INSTANCE, id=inst.instance_id,
                                x=inst.x, y=inst.y)
                self.G.add_edge(room_node, inst_node, relation=CONTAINS)
                obj_node = _nid("obj", inst.object_id)
                if self.G.has_node(obj_node):
                    self.G.add_edge(inst_node, obj_node, relation=IS_INSTANCE_OF)
                if inst.creation_code_id >= 0:
                    cc_node = _nid("code", inst.creation_code_id)
                    if self.G.has_node(cc_node):
                        self.G.add_edge(inst_node, cc_node, relation=HAS_CREATION_CODE)
                        self.G.add_edge(cc_node, obj_node, relation=CREATES)
        for room_id, code in self.resolver.room_creation_code.items():
            room_node = _nid("room", room_id)
            cc_node = _nid("code", code.id)
            if self.G.has_node(cc_node):
                self.G.add_edge(room_node, cc_node, relation=HAS_CREATION_CODE)

    def _add_object_relationships(self) -> None:
        """Object → parent, object → sprite, object → mask edges."""
        for obj_id, parent in self.resolver.object_parent.items():
            child_node = _nid("obj", obj_id)
            parent_node = _nid("obj", parent.id)
            self.G.add_edge(child_node, parent_node, relation=INHERITS)
        for obj_id, sprite in self.resolver.object_sprite.items():
            obj_node = _nid("obj", obj_id)
            spr_node = _nid("spr", sprite.id)
            self.G.add_edge(obj_node, spr_node, relation=USES_SPRITE)
        # Collision events
        for obj_id, obj in self.game.objects.items():
            obj_node = _nid("obj", obj_id)
            for ev in obj.events:
                if ev.event_type == 4 and ev.subtype in self.game.objects:
                    other_node = _nid("obj", ev.subtype)
                    self.G.add_edge(obj_node, other_node, relation=COLLISION_REF)

    def _add_code_relationships(self) -> None:
        """Code entry ownership edges: owner → code.

        Every CODE entry should have at least one incoming edge.
        Handles all owner types: object events, rooms, scripts,
        global scripts, sequences, timelines, and unknown.
        """
        owned_count = 0
        for code_id in self.game.code_entries:
            code_node = _nid("code", code_id)
            owner = self.resolver.owner_of(code_id)
            owner_type = self.resolver.owner_type.get(code_id, -1)
            owner_id = self.resolver.owner_id.get(code_id, -1)

            # OWNER_OBJECT_EVENT (1): connect owning object → code
            if owner_type == 1 and owner_id >= 0:
                obj_node = _nid("obj", owner_id)
                if self.G.has_node(obj_node):
                    self.G.add_edge(obj_node, code_node, relation=HAS_EVENT)
                    owned_count += 1

            # OWNER_ROOM (2): connect room → code
            elif owner_type == 2 and owner_id >= 0:
                room_node = _nid("room", owner_id)
                if self.G.has_node(room_node):
                    self.G.add_edge(room_node, code_node, relation=HAS_CREATION_CODE)
                    owned_count += 1

            # OWNER_SCRIPT (0): connect script → code
            elif owner_type == 0:
                if owner and "::" in owner:
                    script_name = owner.split("::", 1)[1]
                    script_node = f"script_{script_name}"
                    if self.G.has_node(script_node):
                        self.G.add_edge(script_node, code_node, relation=OWNS)
                        owned_count += 1

            # OWNER_GLOBAL_SCRIPT (3): connect as a root node
            elif owner_type == 3:
                if owner and "::" in owner:
                    gs_name = owner.split("::", 1)[1]
                    gs_node = f"global_{gs_name}"
                    self.G.add_node(gs_node, type="global_script", name=gs_name)
                    self.G.add_edge(gs_node, code_node, relation=OWNS)
                    owned_count += 1

            # OWNER_SEQUENCE (4) / OWNER_TIMELINE (5): connect to a timeline/sequence node
            elif owner_type in (4, 5):
                prefix = "seq" if owner_type == 4 else "timeline"
                if owner and "::" in owner:
                    sub_name = owner.split("::", 1)[1]
                    sub_node = f"{prefix}_{sub_name}"
                    self.G.add_node(sub_node, type=prefix, name=sub_name)
                    self.G.add_edge(sub_node, code_node, relation=OWNS)
                    owned_count += 1

            # OWNER_UNKNOWN (-1) or anything else: still record the code exists
            else:
                pass  # CODE node is already in the graph, just isolated

        # Map FUNC → CODE entry points
        for func_id, code_id in self.resolver.func_to_code.items():
            func_node = _nid("func", func_id)
            code_node = _nid("code", code_id)
            if self.G.has_node(code_node):
                self.G.add_edge(func_node, code_node, relation=ENTRY_POINT)

    def _add_call_edges(self) -> None:
        """CODE → CODE call edges and CODE → FUNCTION builtin edges."""
        for caller_id, callees in self.resolver.callees.items():
            caller_node = _nid("code", caller_id)
            for callee_id in callees:
                callee_node = _nid("code", callee_id)
                if self.G.has_node(callee_node):
                    self.G.add_edge(caller_node, callee_node, relation=CALLS)
        for caller_id, builtins in self.resolver.builtin_calls.items():
            caller_node = _nid("code", caller_id)
            for func_id, arg_count in builtins:
                func_node = _nid("func", func_id)
                if self.G.has_node(func_node):
                    self.G.add_edge(caller_node, func_node, relation=CALLS_FUNCTION)

    def _add_flag_edges(self) -> None:
        """CODE → FLAG read/write edges."""
        for flag_id, readers in self.resolver.flag_reads.items():
            flag_node = _nid("flag", flag_id)
            self.G.add_node(flag_node, type=NT_FLAG, id=flag_id, name=f"flag[{flag_id}]")
            for code_id in readers:
                code_node = _nid("code", code_id)
                self.G.add_edge(code_node, flag_node, relation=READS_FLAG)
        for flag_id, writers in self.resolver.flag_writes.items():
            flag_node = _nid("flag", flag_id)
            self.G.add_node(flag_node, type=NT_FLAG, id=flag_id, name=f"flag[{flag_id}]")
            for code_id in writers:
                code_node = _nid("code", code_id)
                self.G.add_edge(code_node, flag_node, relation=WRITES_FLAG)
        # Add flag nodes even for -1 unknown flag
        if -1 in self.resolver.flag_reads or -1 in self.resolver.flag_writes:
            self.G.add_node(_nid("flag", -1), type=NT_FLAG, id=-1, name="flag[?]")

    def _add_room_transitions(self) -> None:
        """Room → room edges from resolver transitions + fallback."""
        # Build room nodes if not already present
        for room in self.game.rooms.values():
            node = _nid("room", room.id)
            if not self.G.has_node(node):
                self.G.add_node(node, type=NT_ROOM, name=room.name, id=room.id)

        if self.resolver.room_transitions:
            for code_id, trans_type, target_room_id in self.resolver.room_transitions:
                if target_room_id is not None and target_room_id in self.game.rooms:
                    # Find first room as source, or use any existing room
                    first_room_id = min(self.game.rooms.keys())
                    source = _nid("room", first_room_id)
                    target = _nid("room", target_room_id)
                    self.G.add_edge(source, target, relation=CONNECTED_TO)
                    code_node = _nid("code", code_id)
                    if self.G.has_node(code_node):
                        self.G.add_edge(code_node, target, relation=CONNECTED_TO)
        else:
            # Fallback: connect rooms sharing object instances
            obj_to_rooms: dict[int, set[int]] = defaultdict(set)
            for room_id, room in self.game.rooms.items():
                for inst in room.instances:
                    if inst.object_id >= 0:
                        obj_to_rooms[inst.object_id].add(room_id)
            for obj_id, room_ids in obj_to_rooms.items():
                rid_list = sorted(room_ids)
                for i in range(1, len(rid_list)):
                    source = _nid("room", rid_list[0])
                    target = _nid("room", rid_list[i])
                    self.G.add_edge(source, target, relation=CONNECTED_TO)

    def _add_bytecode_edges(self) -> None:
        """Bytecode analysis: INSTANTIATE, WITH, creation funcs, refs, strings, sounds.

        This is the ONE place where we scan bytecode for relationships.
        After build(), no other module ever needs to scan instructions again.
        """
        creation_func_ids = set()
        execute_func_ids = set()
        asset_func_ids = set()
        sound_func_ids = set()
        for func_id, fname in enumerate(self.game.func_names):
            if not fname:
                continue
            low = fname.lower()
            for pat in CREATION_FUNC_PATTERNS:
                if pat in low:
                    creation_func_ids.add(func_id)
                    break
            for pat in EXECUTE_FUNC_PATTERNS:
                if pat in low:
                    execute_func_ids.add(func_id)
                    break
            for pat in ASSET_FUNC_PATTERNS:
                if pat in low:
                    asset_func_ids.add(func_id)
                    break
            for pat in SOUND_FUNC_PATTERNS:
                if pat in low:
                    sound_func_ids.add(func_id)
                    break

        obj_ids = set(self.game.objects.keys())
        obj_names = {o.name: o.id for o in self.game.objects.values()}
        room_names = {r.name: _nid("room", r.id) for r in self.game.rooms.values()}
        sound_names = {s.name: _nid("snd", s.id) for s in self.game.sounds.values()}

        for code_id, entry in self.game.code_entries.items():
            code_node = _nid("code", code_id)
            instrs = entry.instructions
            for i, instr in enumerate(instrs):
                # INSTANTIATE opcode
                if instr.opcode == Opcode.INSTANTIATE:
                    oid = instr.value_int
                    if oid in obj_ids:
                        obj_node = _nid("obj", oid)
                        self.G.add_edge(code_node, obj_node, relation=CREATES)
                        continue

                # CALL instructions
                if is_call(instr.opcode):
                    func_id = instr.value_func_id

                    # Creation function calls
                    if func_id in creation_func_ids or func_id in execute_func_ids:
                        target_obj = self._find_obj_arg(instrs, i, obj_ids, obj_names)
                        if target_obj is not None:
                            self.G.add_edge(code_node, _nid("obj", target_obj), relation=CREATES)

                    # asset_get_index / object_get_name
                    if func_id in asset_func_ids:
                        target_obj = self._find_str_arg(instrs, i, obj_names)
                        if target_obj is not None:
                            self.G.add_edge(code_node, _nid("obj", target_obj), relation=ASSET_GET_REF)

                    # Sound play functions
                    if func_id in sound_func_ids:
                        target_snd = self._find_str_arg(instrs, i, sound_names)
                        if target_snd is not None:
                            self.G.add_edge(code_node, target_snd, relation=REFERENCES_SOUND)

                    # Room transition detection (redundant with resolver, but catches more)
                    if func_id not in creation_func_ids and func_id not in execute_func_ids:
                        target_room = self._find_str_arg(instrs, i, room_names)
                        if target_room is not None:
                            self.G.add_edge(code_node, target_room, relation=CONNECTED_TO)

                    continue

                # WITH opcode
                if instr.opcode == Opcode.WITH:
                    target_obj = self._find_obj_arg(instrs, i, obj_ids)
                    if target_obj is not None:
                        self.G.add_edge(code_node, _nid("obj", target_obj), relation=WITH_REF)

                # PUSHI with object ID (generic bytecode reference)
                if instr.opcode == Opcode.PUSHI and instr.value_int in obj_ids:
                    self.G.add_edge(code_node, _nid("obj", instr.value_int), relation=REFERENCES_OBJ)

                # PUSHSTR with object/sound/room name
                if instr.opcode == Opcode.PUSHSTR and instr.value_str_id >= 0:
                    val = self.game.string(instr.value_str_id)
                    if val in obj_names:
                        self.G.add_edge(code_node, _nid("obj", obj_names[val]), relation=REFERENCES)
                    elif val in sound_names:
                        self.G.add_edge(code_node, sound_names[val], relation=REFERENCES_SOUND)
                    elif val in room_names:
                        self.G.add_edge(code_node, room_names[val], relation=REFERENCES)

                # String references
                if instr.opcode in (Opcode.PUSHSTR,):
                    if instr.value_str_id >= 0:
                        str_node = _nid("str", instr.value_str_id)
                        if self.G.has_node(str_node):
                            self.G.add_edge(code_node, str_node, relation=REFERENCES)

    def _find_obj_arg(self, instrs, call_idx: int, obj_ids: set[int],
                      obj_names: Optional[dict[str, int]] = None) -> Optional[int]:
        """Find an object ID in the instructions preceding a call."""
        for j in range(call_idx - 1, max(call_idx - 8, -1), -1):
            prev = instrs[j]
            if prev.opcode == Opcode.PUSHI and prev.value_int in obj_ids:
                return prev.value_int
            if prev.opcode == Opcode.PUSHSTR and obj_names is not None:
                val = prev.value_str
                if val in obj_names:
                    return obj_names[val]
            if prev.opcode in (Opcode.PUSHENV, Opcode.POPENV, Opcode.PUSHBLTN):
                continue
            break
        return None

    def _find_str_arg(self, instrs, call_idx: int,
                      name_map: dict[str, str]) -> Optional[str]:
        """Find a named resource in instructions preceding a call."""
        for j in range(call_idx - 1, max(call_idx - 8, -1), -1):
            prev = instrs[j]
            if prev.opcode == Opcode.PUSHSTR:
                val = prev.value_str
                if val in name_map:
                    return name_map[val]
            if prev.opcode in (Opcode.PUSHENV, Opcode.POPENV, Opcode.PUSHBLTN):
                continue
            break
        return None

    # ── CORE QUERY API ───────────────────────────────────────────────

    def incoming(self, node: str, relation: Optional[str] = None) -> list[dict]:
        """Return all incoming edges as [{source, relation, source_type, source_name}, ...]."""
        if not self.G.has_node(node):
            return []
        results = []
        for src, _, data in self.G.in_edges(node, data=True):
            if relation and data.get("relation") != relation:
                continue
            src_type = self.G.nodes[src].get("type", "?")
            src_name = self.G.nodes[src].get("name", src)
            results.append({
                "source": src, "relation": data.get("relation", "?"),
                "type": src_type, "name": src_name,
                "node": node,
            })
        return results

    def outgoing(self, node: str, relation: Optional[str] = None) -> list[dict]:
        """Return all outgoing edges as [{target, relation, target_type, target_name}, ...]."""
        if not self.G.has_node(node):
            return []
        results = []
        for _, tgt, data in self.G.out_edges(node, data=True):
            if relation and data.get("relation") != relation:
                continue
            tgt_type = self.G.nodes[tgt].get("type", "?")
            tgt_name = self.G.nodes[tgt].get("name", tgt)
            results.append({
                "target": tgt, "relation": data.get("relation", "?"),
                "type": tgt_type, "name": tgt_name,
                "node": node,
            })
        return results

    def neighbors(self, node: str) -> list[str]:
        if not self.G.has_node(node):
            return []
        return list(set(self.G.predecessors(node)) | set(self.G.successors(node)))

    def shortest_path(self, source: str, target: str) -> list[str]:
        try:
            return nx.shortest_path(self.G, source, target)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    def find(self, type: str, name_pattern: Optional[str] = None) -> list[dict]:
        results = []
        for nid, data in self.G.nodes(data=True):
            if data.get("type") != type:
                continue
            if name_pattern and name_pattern.lower() not in data.get("name", "").lower():
                continue
            results.append({
                "node": nid, "type": type,
                "name": data.get("name", nid),
                "id": data.get("id"),
            })
        return results

    def find_edges(self, relation: str) -> list[dict]:
        results = []
        for src, tgt, data in self.G.edges(data=True):
            if data.get("relation") == relation:
                src_data = self.G.nodes[src]
                tgt_data = self.G.nodes[tgt]
                results.append({
                    "source": src, "target": tgt,
                    "src_name": src_data.get("name", src),
                    "tgt_name": tgt_data.get("name", tgt),
                    "src_type": src_data.get("type", "?"),
                    "tgt_type": tgt_data.get("type", "?"),
                })
        return results

    def roots(self) -> list[dict]:
        return [
            {"node": n, "name": self.G.nodes[n].get("name", n),
             "type": self.G.nodes[n].get("type", "?")}
            for n in self.G.nodes() if self.G.in_degree(n) == 0
        ]

    def leaves(self) -> list[dict]:
        return [
            {"node": n, "name": self.G.nodes[n].get("name", n),
             "type": self.G.nodes[n].get("type", "?")}
            for n in self.G.nodes() if self.G.out_degree(n) == 0
        ]

    def reachable_from(self, source: str) -> set[str]:
        if not self.G.has_node(source):
            return set()
        try:
            return set(nx.dfs_preorder_nodes(self.G, source))
        except (nx.NetworkXError, nx.NodeNotFound):
            return {source}

    def node_info(self, node: str) -> Optional[dict]:
        if not self.G.has_node(node):
            return None
        data = self.G.nodes[node]
        return {
            "node": node,
            "type": data.get("type", "?"),
            "name": data.get("name", node),
            "id": data.get("id"),
            "in_degree": self.G.in_degree(node),
            "out_degree": self.G.out_degree(node),
        }

    # ── SUBGRAPH VIEWS (backward compat) ────────────────────────────

    @property
    def room(self) -> nx.DiGraph:
        """Room transition subgraph (backward compat)."""
        sg = nx.DiGraph()
        for src, tgt, data in self.G.edges(data=True):
            if data.get("relation") == CONNECTED_TO:
                src_data = self.G.nodes[src]
                tgt_data = self.G.nodes[tgt]
                sg.add_node(src, name=src_data.get("name", src))
                sg.add_node(tgt, name=tgt_data.get("name", tgt))
                sg.add_edge(src, tgt, **data)
        return sg

    @property
    def call(self) -> nx.DiGraph:
        """Call graph subgraph — CODE → CODE edges only (backward compat).

        This matches resolver.callees which only tracks CODE→CODE calls.
        CODE → FUNCTION (built-in) edges are excluded from this view.
        """
        sg = nx.DiGraph()
        for src, tgt, data in self.G.edges(data=True):
            if data.get("relation") not in (CALLS,):
                continue
            src_data = self.G.nodes[src]
            tgt_data = self.G.nodes[tgt]
            if src_data.get("type") != NT_CODE or tgt_data.get("type") != NT_CODE:
                continue
            sg.add_node(src, name=src_data.get("name", src))
            sg.add_node(tgt, name=tgt_data.get("name", tgt))
            sg.add_edge(src, tgt, **data)
        return sg

    @property
    def object(self) -> nx.DiGraph:
        """Object relationship subgraph (backward compat)."""
        sg = nx.DiGraph()
        rels = {CONTAINS, IS_INSTANCE_OF, USES_SPRITE, INHERITS, PLACED_IN}
        for src, tgt, data in self.G.edges(data=True):
            if data.get("relation") in rels:
                src_data = self.G.nodes[src]
                tgt_data = self.G.nodes[tgt]
                sg.add_node(src, name=src_data.get("name", src), type=src_data.get("type"))
                sg.add_node(tgt, name=tgt_data.get("name", tgt), type=tgt_data.get("type"))
                sg.add_edge(src, tgt, **data)
        return sg

    @property
    def flag(self) -> nx.DiGraph:
        """Flag dependency subgraph (backward compat)."""
        sg = nx.DiGraph()
        for src, tgt, data in self.G.edges(data=True):
            if data.get("relation") in (READS_FLAG, WRITES_FLAG):
                src_data = self.G.nodes[src]
                tgt_data = self.G.nodes[tgt]
                sg.add_node(src, name=src_data.get("name", src))
                sg.add_node(tgt, name=tgt_data.get("name", tgt))
                sg.add_edge(src, tgt, **data)
        return sg

    def unreachable_rooms(self) -> set[int]:
        """Backward compat: room IDs not reachable from any source room."""
        rg = self.room
        if not rg.nodes():
            return {r.id for r in self.game.rooms.values()}
        sources = [n for n in rg.nodes() if rg.in_degree(n) == 0]
        if not sources:
            return set()
        reachable = set()
        for s in sources:
            reachable.update(nx.dfs_preorder_nodes(rg, s))
        return {r.id for r in self.game.rooms.values()
                if _nid("room", r.id) not in reachable}

    def room_graph_summary(self) -> dict:
        rg = self.room
        return {
            "nodes": rg.number_of_nodes(),
            "edges": rg.number_of_edges(),
            "components": nx.number_weakly_connected_components(rg) if rg.number_of_nodes() > 0 else 0,
            "unreachable": sorted(self.unreachable_rooms()),
        }

    def call_graph_summary(self) -> dict:
        cg = self.call
        return {
            "nodes": cg.number_of_nodes(),
            "edges": cg.number_of_edges(),
        }

    # ── DOMAIN-SPECIFIC ANALYSES ─────────────────────────────────────

    def trace(self, pattern: str) -> list[TraceNode]:
        """Semantic trace: walk the graph showing the relationship chain.

        Strategy:
          1. Try exact match on node name or node ID first.
          2. If only one exact match, trace just that node (not every fuzzy hit).
          3. Fall back to substring matching only when no exact match exists.

        For each matched node, shows both incoming and outgoing edges.
        """
        results: list[TraceNode] = []
        lower = pattern.lower()

        # Phase 1: exact match on name or node ID
        exact: list[str] = []
        for nid, data in self.G.nodes(data=True):
            name = data.get("name", "")
            if name == pattern or nid == pattern:
                exact.append(nid)

        # Phase 2: only fall back to fuzzy if no exact match
        matched: list[str] = []
        if exact:
            matched = exact
        else:
            for nid, data in self.G.nodes(data=True):
                name = data.get("name", "")
                if lower in name.lower() or lower in nid.lower():
                    matched.append(nid)

        for nid in matched:
            data = self.G.nodes[nid]
            node_type = data.get("type", "?")
            node_name = data.get("name", nid)
            tn = TraceNode(node_id=nid, type=node_type, name=node_name)

            for _, tgt, edata in self.G.out_edges(nid, data=True):
                rel = edata.get("relation", "?")
                tgt_data = self.G.nodes[tgt]
                tn.edges.append((rel, tgt, tgt_data.get("name", tgt)))

            for src, _, edata in self.G.in_edges(nid, data=True):
                rel = edata.get("relation", "?")
                src_data = self.G.nodes[src]
                tn.edges.append((f"<--{rel}", src, src_data.get("name", src)))

            results.append(tn)

        return results

    def who_uses(self, resource_name: str) -> dict[str, list[str]]:
        """Inverse graph query: find all incoming edges grouped by source type.

        For a resource name, finds the node(s) and returns every resource
        that has an edge TO it, grouped by type. Searches by:
          - exact node name match
          - node ID pattern match (e.g. "obj_42")
          - resource object match via game model

        Every known graph relationship is included.
        """
        result: dict[str, list[str]] = {
            "objects": [], "code": [], "rooms": [], "sprites": [],
            "scripts": [], "functions": [], "strings": [],
            "flags": [], "events": [], "creation_code": [],
            "bytecode": [], "sounds": [],
        }

        targets: list[str] = []

        # 1. Exact match on node name
        for nid, data in self.G.nodes(data=True):
            if data.get("name") == resource_name:
                targets.append(nid)

        # 2. Node ID match
        node_id = resource_name
        if self.G.has_node(node_id):
            targets.append(node_id)

        # 3. Try to resolve via game model
        obj = next((o for o in self.game.objects.values() if o.name == resource_name), None)
        if obj is not None:
            nid = _nid("obj", obj.id)
            if nid not in targets:
                targets.append(nid)

        room = next((r for r in self.game.rooms.values() if r.name == resource_name), None)
        if room is not None:
            nid = _nid("room", room.id)
            if nid not in targets:
                targets.append(nid)

        sprite = next((s for s in self.game.sprites.values() if s.name == resource_name), None)
        if sprite is not None:
            nid = _nid("spr", sprite.id)
            if nid not in targets:
                targets.append(nid)

        sound = next((s for s in self.game.sounds.values() if s.name == resource_name), None)
        if sound is not None:
            nid = _nid("snd", sound.id)
            if nid not in targets:
                targets.append(nid)

        # Deduplicate
        seen_targets = set()
        unique_targets = []
        for t in targets:
            if t not in seen_targets:
                seen_targets.add(t)
                unique_targets.append(t)

        for target in unique_targets:
            for src, _, edata in self.G.in_edges(target, data=True):
                rel = edata.get("relation", "?")
                src_data = self.G.nodes[src]
                src_type = src_data.get("type", "?")
                src_name = src_data.get("name", src)
                entry = f"{src_name} ({rel})"

                if src_type == NT_OBJECT:
                    result["objects"].append(entry)
                elif src_type == NT_CODE:
                    result["bytecode"].append(entry)
                elif src_type == NT_ROOM:
                    result["rooms"].append(entry)
                elif src_type == NT_SPRITE:
                    result["sprites"].append(entry)
                elif src_type in (NT_SCRIPT,):
                    result["scripts"].append(entry)
                elif src_type == NT_FUNCTION:
                    result["functions"].append(entry)
                elif src_type == NT_STRING:
                    result["strings"].append(entry)
                elif src_type == NT_FLAG:
                    result["flags"].append(entry)
                elif src_type == NT_INSTANCE:
                    result["creation_code"].append(entry)
                else:
                    result["bytecode"].append(entry)

            # Also walk outward from target to find usage relationships
            for _, tgt, edata in self.G.out_edges(target, data=True):
                rel = edata.get("relation", "?")
                tgt_data = self.G.nodes[tgt]
                tgt_type = tgt_data.get("type", "?")
                tgt_name = tgt_data.get("name", tgt)
                entry = f"{tgt_name} ({rel})"
                if tgt_type == NT_SPRITE:
                    result["sprites"].append(entry)
                elif tgt_type == NT_SOUND:
                    result["sounds"].append(entry)
                elif tgt_type == NT_CODE:
                    result["bytecode"].append(entry)

        for key in result:
            result[key] = list(set(result[key]))[:30]

        return result

    def suspicious_resources(self) -> list[SuspiciousItem]:
        """Find suspicious/disconnected resources by inspecting graph properties.

        Does NOT perform independent searches. Only inspects the graph.
        An object is NEVER suspicious if it has clear graph evidence of use:
          - has any event code
          - placed in a room
          - inherited or parent of others
          - collision referenced
          - WITH referenced
          - bytecode referenced
          - dynamically created
        """
        items: list[SuspiciousItem] = []

        # Object nodes: check isolation, naming, etc.
        for nid, data in self.G.nodes(data=True):
            if data.get("type") != NT_OBJECT:
                continue
            name: str = data.get("name", "")
            evidence_for: list[str] = []
            evidence_against: list[str] = []

            in_deg = self.G.in_degree(nid)
            out_deg = self.G.out_degree(nid)

            # Gather evidence of actual use
            in_room = any(
                True
                for src, _, edata in self.G.in_edges(nid, data=True)
                if edata.get("relation") == IS_INSTANCE_OF
                and self.G.nodes[src].get("type") == NT_INSTANCE
            )
            has_any_event = any(
                edata.get("relation") == HAS_EVENT
                for _, _, edata in self.G.out_edges(nid, data=True)
            )
            has_dynamic_creation = any(
                edata.get("relation") == CREATES
                for _, _, edata in self.G.in_edges(nid, data=True)
            )
            has_inheritance_as_child = any(
                edata.get("relation") == INHERITS
                for _, _, edata in self.G.out_edges(nid, data=True)
            )
            has_inheritance_as_parent = any(
                edata.get("relation") == INHERITS
                for _, _, edata in self.G.in_edges(nid, data=True)
            )
            has_collision_ref = any(
                edata.get("relation") == COLLISION_REF
                for _, _, edata in self.G.out_edges(nid, data=True)
            )
            has_with_ref = any(
                edata.get("relation") == WITH_REF
                for _, _, edata in self.G.in_edges(nid, data=True)
            )
            has_bytecode_ref = any(
                edata.get("relation") in (REFERENCES_OBJ, REFERENCES, ASSET_GET_REF)
                for _, _, edata in self.G.in_edges(nid, data=True)
            )

            # If any strong evidence of use exists, skip entirely
            if any([in_room, has_any_event, has_dynamic_creation,
                    has_inheritance_as_child, has_inheritance_as_parent,
                    has_collision_ref, has_with_ref, has_bytecode_ref]):
                continue

            low = name.lower()

            # Check naming for suspicious patterns
            has_suspicious_name = False
            for pat in SUSPICIOUS_NAMES:
                if pat in low:
                    evidence_for.append(f"suspicious name pattern: '{pat}'")
                    has_suspicious_name = True
                    break

            # Controller pattern is counter-evidence (likely intentional)
            if "controller" in low or "ctrl" in low:
                evidence_against.append("controller naming (likely intentional)")
                has_suspicious_name = False

            # No suspicious name AND no evidence = truly dead, report at medium confidence
            if not has_suspicious_name and not evidence_against:
                if in_deg == 0 and out_deg == 0:
                    evidence_for.append("completely isolated (no edges)")
                elif in_deg == 0:
                    evidence_for.append("no incoming references from graph")
                if out_deg == 0:
                    evidence_for.append("no outgoing relationships")
                # Only report if there's real reason to suspect
                if not evidence_for:
                    continue

            conf = self._confidence(evidence_for, evidence_against)
            if conf < 20:
                continue

            items.append(SuspiciousItem(
                name=name, resource_type="OBJECT", confidence=conf,
                reasons=evidence_for[:3],
                evidence_for=evidence_for[:5],
                evidence_against=evidence_against[:5],
                details=f"in_deg={in_deg} out_deg={out_deg}",
            ))

        # Room nodes: check unreachability
        unreachable = self.unreachable_rooms()
        for rid in unreachable:
            room = self.game.room_by_id(rid)
            if not room:
                continue
            node = _nid("room", rid)
            in_deg = self.G.in_degree(node)
            evidence_for = ["no incoming room transitions"]
            evidence_against = []
            if room.creation_code_id >= 0:
                evidence_against.append("has creation code")
            if room.instances:
                evidence_against.append(f"has {len(room.instances)} instances")
            conf = self._confidence(evidence_for, evidence_against)
            if conf < 20:
                continue
            items.append(SuspiciousItem(
                name=room.name, resource_type="ROOM", confidence=conf,
                reasons=evidence_for[:3],
                evidence_for=evidence_for[:5],
                evidence_against=evidence_against[:5],
                details=f"in_deg={in_deg} instances={len(room.instances)}",
            ))

        # Sprite nodes: only report if unused AND has a suspicious name
        for nid, data in self.G.nodes(data=True):
            if data.get("type") != NT_SPRITE:
                continue
            name = data.get("name", "")
            in_deg = self.G.in_degree(nid)
            if in_deg > 0:
                continue
            low = name.lower()
            suspicious_name = next((pat for pat in SUSPICIOUS_NAMES if pat in low), None)
            if not suspicious_name:
                continue
            evidence_for = ["no object uses this sprite", f"suspicious name: '{suspicious_name}'"]
            conf = self._confidence(evidence_for, [])
            if conf < 20:
                continue
            items.append(SuspiciousItem(
                name=name, resource_type="SPRITE", confidence=conf,
                reasons=evidence_for[:3],
                evidence_for=evidence_for[:5],
                evidence_against=[],
            ))

        # Sound nodes: only report if never played AND has a suspicious name
        for nid, data in self.G.nodes(data=True):
            if data.get("type") != NT_SOUND:
                continue
            name = data.get("name", "")
            has_play = any(
                edata.get("relation") == REFERENCES_SOUND
                for _, _, edata in self.G.in_edges(nid, data=True)
            )
            if has_play:
                continue
            low = name.lower()
            suspicious_name = next((pat for pat in SUSPICIOUS_NAMES if pat in low), None)
            if not suspicious_name:
                continue
            evidence_for = ["sound never played", f"suspicious name: '{suspicious_name}'"]
            conf = self._confidence(evidence_for, [])
            if conf < 20:
                continue
            items.append(SuspiciousItem(
                name=name, resource_type="SOUND", confidence=conf,
                reasons=evidence_for[:3],
                evidence_for=evidence_for[:5],
                evidence_against=[],
            ))

        # Script nodes: no CODE entry point (never called)
        for nid, data in self.G.nodes(data=True):
            if data.get("type") != NT_SCRIPT:
                continue
            name = data.get("name", "")
            has_entry = any(
                edata.get("relation") == OWNS
                for _, _, edata in self.G.out_edges(nid, data=True)
            )
            if not has_entry:
                continue
            # Check if script's code is called
            script_code_called = False
            for _, tgt, edata in self.G.out_edges(nid, data=True):
                if edata.get("relation") == OWNS:
                    code_callees = [
                        t for _, t, ed2 in self.G.in_edges(tgt, data=True)
                        if ed2.get("relation") == CALLS
                    ]
                    if code_callees:
                        script_code_called = True
                        break
            if script_code_called:
                continue
            evidence_for = ["script never called"]
            low = name.lower()
            for pat in SUSPICIOUS_NAMES:
                if pat in low:
                    evidence_for.append(f"suspicious name: '{pat}'")
                    break
            conf = self._confidence(evidence_for, [])
            if conf < 20:
                continue
            items.append(SuspiciousItem(
                name=name, resource_type="SCRIPT", confidence=conf,
                reasons=evidence_for[:3],
                evidence_for=evidence_for[:5],
                evidence_against=[],
            ))

        items.sort()
        return items

    def _confidence(self, evidence_for: list[str], evidence_against: list[str]) -> int:
        score = 0
        score += min(len(evidence_for) * 15, 70)
        score -= min(len(evidence_against) * 20, 60)
        score = max(0, min(100, score))
        if not evidence_against and evidence_for:
            score = max(score, 35)
        return score

    def flag_analysis(self) -> dict:
        """Analyze flag usage from the graph.

        Returns counts of reads, writes, and dead flags.
        """
        flag_nodes = [n for n, d in self.G.nodes(data=True) if d.get("type") == NT_FLAG]
        analysis: dict[int, dict] = {}
        for fn in flag_nodes:
            fid = _parse_nid(fn)[1]
            if fid < 0:
                continue
            reads = sum(1 for _, _, d in self.G.in_edges(fn, data=True)
                        if d.get("relation") == READS_FLAG)
            writes = sum(1 for _, _, d in self.G.in_edges(fn, data=True)
                         if d.get("relation") == WRITES_FLAG)
            analysis[fid] = {"reads": reads, "writes": writes, "total": reads + writes}

        dead = [fid for fid, a in analysis.items() if a["reads"] == 0 and a["writes"] == 0]
        read_only = [fid for fid, a in analysis.items() if a["reads"] > 0 and a["writes"] == 0]
        write_only = [fid for fid, a in analysis.items() if a["reads"] == 0 and a["writes"] > 0]
        return {
            "total": len(analysis),
            "dead": len(dead), "dead_flags": dead[:50],
            "read_only": len(read_only), "read_only_flags": read_only[:50],
            "write_only": len(write_only), "write_only_flags": write_only[:50],
            "reads": sum(a["reads"] for a in analysis.values()),
            "writes": sum(a["writes"] for a in analysis.values()),
            "by_flag": analysis,
        }

    def dead_resources(self) -> dict[str, list[str]]:
        """Find resources with no path from any runtime root.

        A resource is considered dead if it has no incoming edges and
        no path from any entry point (scripts, objects with events, rooms).
        """
        # Define runtime roots
        roots = set()
        for nid, data in self.G.nodes(data=True):
            if data.get("type") == NT_OBJECT:
                # Object with events or room placement is a root
                has_events = any(
                    edata.get("relation") == HAS_EVENT
                    for _, _, edata in self.G.out_edges(nid, data=True)
                )
                in_room = any(
                    self.G.nodes[src].get("type") == NT_INSTANCE
                    for src, _, edata in self.G.in_edges(nid, data=True)
                    if edata.get("relation") == IS_INSTANCE_OF
                )
                has_incoming = self.G.in_degree(nid) > 0
                if has_events or in_room or has_incoming:
                    roots.add(nid)
            if data.get("type") == NT_ROOM:
                roots.add(nid)
            if data.get("type") == NT_SCRIPT:
                roots.add(nid)

        # Compute reachable set from all roots
        reachable: set[str] = set()
        for r in roots:
            reachable.update(self.reachable_from(r))

        dead: dict[str, list[str]] = {}
        for nid, data in self.G.nodes(data=True):
            nt = data.get("type")
            if nt not in (NT_OBJECT, NT_ROOM, NT_SPRITE, NT_SOUND, NT_SCRIPT):
                continue
            if nid in reachable:
                continue
            name = data.get("name", nid)
            dead.setdefault(nt, []).append(name)

        for key in dead:
            dead[key].sort()

        return dead
