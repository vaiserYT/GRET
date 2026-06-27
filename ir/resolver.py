"""Resolver: builds all cross-reference indexes after chunk parsing.

Every numeric ID parsed from data.win is resolved into actual Python object
references. No IDs are left dangling unless the data.win genuinely contains
invalid references.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Optional, TYPE_CHECKING

from code.opcodes import Opcode, is_call, is_push

if TYPE_CHECKING:
    from model.game import Game
    from model.object_ import ObjectDef, EventDef
    from model.room_ import RoomDef, RoomInstance
    from model.code_ import CodeEntry
    from model.sprite import SpriteDef
    from model.sound import SoundDef


# Known GMS2.3 event name keywords (in order of longest to shortest for matching)
EVENT_KEYWORDS = [
    "DrawGUIBegin", "DrawGUIEnd", "DrawGUI",
    "DrawBegin", "DrawEnd",
    "AnimationStart", "AnimationEnd",
    "StepBegin", "StepMiddle", "StepEnd",
    "RoomStart", "RoomEnd",
    "KeyRelease", "KeyPress",
    "MouseRelease", "MousePress",
    "PreCreate", "PreDraw",
    "GameStart", "GameEnd",
    "Collision",
    "Create", "Destroy", "Alarm", "Step", "Draw",
    "Keyboard", "Mouse", "Other", "User",
    "Cleanup",
]

EVENT_KEYWORD_MAP: dict[str, int] = {}
for name in EVENT_KEYWORDS:
    EVENT_KEYWORD_MAP[name] = EVENT_KEYWORD_MAP.get(name, 0) + 1


def _parse_gml_object_name(name: str) -> tuple[Optional[str], int, int]:
    """Parse gml_Object_<objname>_<EventName>_<subtype> into (obj_name, event_type, subtype)."""
    if not name.startswith("gml_Object_"):
        return None, -1, -1
    rest = name[len("gml_Object_"):]
    # Find the last occurrence of any event keyword
    best_pos = -1
    best_keyword = None
    for kw in EVENT_KEYWORDS:
        pos = rest.rfind("_" + kw + "_")
        if pos > best_pos:
            best_pos = pos
            best_keyword = kw
    if best_keyword is None or best_pos < 0:
        return None, -1, -1
    obj_name = rest[:best_pos]
    after_kw = rest[best_pos + 1 + len(best_keyword) + 1:]  # after "<objname>_<Keyword>_"
    # Subtype is everything after the event keyword, up to the next _
    # For collision: gml_Object_<obj>_Collision_<other>_<sub>
    if best_keyword == "Collision":
        # Format: <obj>_Collision_<other_obj>_<sub>
        parts = after_kw.rsplit("_", 1)
        if len(parts) == 2:
            subtype_str = parts[1]
        else:
            subtype_str = "0"
    else:
        subtype_str = after_kw
    try:
        subtype = int(subtype_str)
    except ValueError:
        subtype = 0
    # Map keyword to event type number
    event_type = _event_name_to_num(best_keyword)
    return obj_name, event_type, subtype


def _event_name_to_num(name: str) -> int:
    mapping = {
        "Create": 0, "Destroy": 1, "Alarm": 2, "Step": 3, "Collision": 4,
        "Keyboard": 5, "Mouse": 6, "Other": 7, "Draw": 8, "DrawGUI": 9,
        "KeyRelease": 10, "MouseRelease": 11, "KeyPress": 12, "MousePress": 13,
        "User": 14, "RoomStart": 15, "RoomEnd": 16, "AnimationEnd": 17,
        "AnimationStart": 18, "Cleanup": 19,
        "StepBegin": 20, "StepMiddle": 21, "StepEnd": 22,
        "PreDraw": 23, "DrawBegin": 24, "DrawEnd": 25,
        "DrawGUIBegin": 26, "DrawGUIEnd": 27,
        "GameStart": 28, "GameEnd": 29,
        "PreCreate": 30,
    }
    return mapping.get(name, 99)


# Owner type constants
OWNER_SCRIPT = 0
OWNER_OBJECT_EVENT = 1
OWNER_ROOM = 2
OWNER_GLOBAL_SCRIPT = 3
OWNER_SEQUENCE = 4
OWNER_TIMELINE = 5
OWNER_EXTENSION = 6
OWNER_ANONYMOUS = 7
OWNER_UNKNOWN = -1


class Resolver:
    """Bidirectional cross-reference index for a loaded Game."""

    def __init__(self) -> None:
        # FUNC table index -> CODE entry ID (for script functions)
        self.func_to_code: dict[int, int] = {}

        # code_id -> owner string label
        self.code_owner: dict[int, str] = {}

        # code_id -> owner type constant
        self.owner_type: dict[int, int] = {}

        # code_id -> owning object/room id (if applicable)
        self.owner_id: dict[int, int] = {}

        # string_id -> list of code_ids that reference it
        self.string_refs: dict[int, list[int]] = defaultdict(list)

        # flag_idx -> {reads: [code_id], writes: [code_id]}
        self.flag_reads: dict[int, list[int]] = defaultdict(list)
        self.flag_writes: dict[int, list[int]] = defaultdict(list)

        # Object reference resolution
        self.object_parent: dict[int, ObjectDef] = {}
        self.object_children: dict[int, list[ObjectDef]] = defaultdict(list)
        self.object_sprite: dict[int, SpriteDef] = {}
        self.object_mask: dict[int, SpriteDef] = {}
        self.object_events: dict[int, list[EventDef]] = defaultdict(list)

        # Room resolution
        self.room_instances: dict[int, list[RoomInstance]] = defaultdict(list)
        self.room_creation_code: dict[int, CodeEntry] = {}
        self.instance_objects: dict[int, ObjectDef] = {}  # instance_id -> ObjectDef

        # Code ownership resolution
        self.code_entry_owner: dict[int, str] = {}  # code_id -> owner label
        self.code_entry_owner_type: dict[int, int] = {}  # code_id -> OWNER_*

        # Call graph (sets deduplicate multiple calls from same caller to same callee)
        self.callers: dict[int, set[int]] = defaultdict(set)  # callee_code_id -> {caller_code_id}
        self.callees: dict[int, set[int]] = defaultdict(set)  # caller_code_id -> {callee_code_id}

        # Built-in call tracking
        self.builtin_calls: dict[int, list[tuple[int, int]]] = defaultdict(list)  # caller_code_id -> [(builtin_id, arg_count)]

        # Sprite/sound usage
        self.sprite_users: dict[int, list[ObjectDef]] = defaultdict(list)
        self.sound_users: dict[int, list[CodeEntry]] = defaultdict(list)

        # Room transitions extracted from bytecode
        self.room_transitions: list[tuple[int, str, Optional[int]]] = []  # (source_code_id, transition_type, target_room_id)

    def build(self, game: Game) -> None:
        """Build all indexes from a loaded Game instance."""
        self._build_func_to_code(game)
        self._resolve_object_references(game)
        self._resolve_room_references(game)
        self._resolve_code_ownership(game)
        self._build_string_refs(game)
        self._build_call_graph(game)
        self._build_flag_refs(game)
        self._build_sprite_users(game)
        self._build_room_transitions(game)
        self._validate(game)

    def _resolve_object_references(self, game: Game) -> None:
        """Resolve all numeric IDs in ObjectDef to actual objects."""
        for obj_id, obj in game.objects.items():
            # Parent
            if obj.parent_index >= 0:
                parent = game.object_by_id(obj.parent_index)
                if parent is not None:
                    self.object_parent[obj_id] = parent
                    self.object_children[obj.parent_index].append(obj)

            # Sprite
            if obj.sprite_index >= 0:
                spr = game.sprite_by_id(obj.sprite_index)
                if spr is not None:
                    self.object_sprite[obj_id] = spr

            # Mask
            if obj.mask_index >= 0:
                mask = game.sprite_by_id(obj.mask_index)
                if mask is not None:
                    self.object_mask[obj_id] = mask

            # Events
            for ev in obj.events:
                self.object_events[obj_id].append(ev)

    def _resolve_room_references(self, game: Game) -> None:
        """Resolve all numeric IDs in RoomDef to actual objects/code."""
        for room_id, room in game.rooms.items():
            for inst in room.instances:
                self.room_instances[room_id].append(inst)
                obj = game.object_by_id(inst.object_id)
                if obj is not None:
                    self.instance_objects[inst.instance_id] = obj

            if room.creation_code_id >= 0:
                code = game.code_entries.get(room.creation_code_id)
                if code is not None:
                    self.room_creation_code[room_id] = code

    def _resolve_code_ownership(self, game: Game) -> None:
        """Classify every CODE entry by owner type using name conventions."""
        for code_id, entry in game.code_entries.items():
            name = entry.name
            owner_label = f"unknown_code_{code_id}"
            owner_type = OWNER_UNKNOWN

            if name.startswith("gml_Object_"):
                obj_name, ev_type, ev_sub = _parse_gml_object_name(name)
                if obj_name is not None:
                    # Find object by name
                    for obj_id, obj in game.objects.items():
                        if obj.name == obj_name:
                            ev_label = f"event_{ev_type}_{ev_sub}"
                            owner_label = f"{obj.name}.{ev_label}"
                            owner_type = OWNER_OBJECT_EVENT
                            self.owner_id[code_id] = obj_id
                            break
                    if owner_type == OWNER_UNKNOWN:
                        owner_label = f"object_unknown::{name}"
                        owner_type = OWNER_OBJECT_EVENT
                else:
                    owner_label = f"object_unparseable::{name}"
                    owner_type = OWNER_OBJECT_EVENT

            elif name.startswith("gml_Script_"):
                script_name = name[len("gml_Script_"):]
                owner_label = f"script::{script_name}"
                owner_type = OWNER_SCRIPT

            elif name.startswith("gml_GlobalScript_"):
                script_name = name[len("gml_GlobalScript_"):]
                owner_label = f"global_init::{script_name}"
                owner_type = OWNER_GLOBAL_SCRIPT

            elif name.startswith("gml_RoomCC_"):
                # gml_RoomCC_<roomname>_<index>_<EventName>
                rest = name[len("gml_RoomCC_"):]
                parts = rest.split("_")
                room_name = parts[0] if parts else rest
                owner_label = f"room_cc::{room_name}"
                owner_type = OWNER_ROOM

            elif name.startswith("gml_Room_"):
                room_name = name[len("gml_Room_"):]
                owner_label = f"room_creation::{room_name}"
                owner_type = OWNER_ROOM

            elif name.startswith("gml_Sequence_"):
                owner_label = f"sequence::{name}"
                owner_type = OWNER_SEQUENCE

            elif name.startswith("gml_Timeline_"):
                owner_label = f"timeline::{name}"
                owner_type = OWNER_TIMELINE

            else:
                owner_label = f"unknown::{name or f'code_{code_id}'}"
                owner_type = OWNER_UNKNOWN

            self.code_owner[code_id] = owner_label
            self.owner_type[code_id] = owner_type
            self.code_entry_owner[code_id] = owner_label
            self.code_entry_owner_type[code_id] = owner_type

    def _build_string_refs(self, game: Game) -> None:
        """Build string reference index from decoded instructions."""
        for code_id, entry in game.code_entries.items():
            for str_id in entry.string_refs:
                self.string_refs[str_id].append(code_id)

    def _build_func_to_code(self, game: Game) -> None:
        """Build FUNC table index -> CODE entry ID mapping.

        A FUNC entry's code_offset matches a CODE entry's bytecode offset
        when the function is a "primary" entry point (script, event, etc.).
        Inner/anonymous functions have code_offsets within a parent CODE
        entry's bytecode range but no exact offset match.
        """
        code_by_offset: dict[int, int] = {}
        for cid, entry in game.code_entries.items():
            code_by_offset[entry.offset] = cid

        self.func_to_code = {}
        for func_id in range(len(game.func_names)):
            code_off = game.func_code_offsets[func_id] if func_id < len(game.func_code_offsets) else 0
            if code_off > 0 and code_off in code_by_offset:
                self.func_to_code[func_id] = code_by_offset[code_off]

    def _build_call_graph(self, game: Game) -> None:
        """Build call graph from CALL instructions.

        CALL instructions in bytecode use FUNC table indices.
        func_to_code maps FUNC index -> CODE entry ID for scripts.
        Functions without a CODE entry are built-in calls.
        """
        func_count = len(game.func_names)

        for caller_code_id, entry in game.code_entries.items():
            for func_id, arg_count, raw_type in entry.calls:
                if func_id >= func_count:
                    # Garbage/invalid func_id — skip
                    continue
                callee_code_id = self.func_to_code.get(func_id)
                if callee_code_id is not None:
                    self.callers[callee_code_id].add(caller_code_id)
                    self.callees[caller_code_id].add(callee_code_id)
                else:
                    self.builtin_calls[caller_code_id].append((func_id, arg_count))

    def _build_flag_refs(self, game: Game) -> None:
        """Build flag read/write index from bytecode instructions.

        Identifies flag access by detecting CALL instructions to functions
        whose names match flag-related patterns (scr_flag_get, scr_flag_set,
        scr_flag_get_ext, scr_flag_set_ext, etc.).

        Flag index extraction from preceding PUSHI is attempted but may fail
        for index values passed as variables. All detected accesses are
        recorded; failed extractions use flag_id=-1.
        """
        flag_get_funcs: set[int] = set()
        flag_set_funcs: set[int] = set()
        for func_id, fname in enumerate(game.func_names):
            if not fname:
                continue
            low = fname.lower()
            if "flag_get" in low and "get" in low:
                flag_get_funcs.add(func_id)
            elif "flag_set" in low and "set" in low:
                flag_set_funcs.add(func_id)
            elif "flag" in low and "get" not in low and "set" not in low:
                if low == "flag":
                    continue
                if "name" in low:
                    continue
                flag_get_funcs.add(func_id)

        for code_id, entry in game.code_entries.items():
            instrs = entry.instructions
            for i, instr in enumerate(instrs):
                if not is_call(instr.opcode):
                    continue
                func_id = instr.value_func_id
                is_write = func_id in flag_set_funcs
                is_read = func_id in flag_get_funcs
                if not is_write and not is_read:
                    continue

                flag_idx = -1
                for j in range(i - 1, max(i - 5, -1), -1):
                    prev = instrs[j]
                    if prev.opcode == Opcode.PUSHI:
                        flag_idx = prev.value_int
                        break
                    if prev.opcode == Opcode.PUSHSTR:
                        try:
                            flag_idx = int(prev.value_str)
                        except (ValueError, TypeError):
                            pass
                        break
                    if prev.opcode in (Opcode.PUSHENV, Opcode.POPENV, Opcode.PUSHBLTN):
                        continue
                    break

                if is_write:
                    self.flag_writes[flag_idx].append(code_id)
                else:
                    self.flag_reads[flag_idx].append(code_id)
                entry.flag_refs.append((flag_idx, is_write))

    def _build_sprite_users(self, game: Game) -> None:
        """Build sprite usage index from object references."""
        for obj_id, obj in game.objects.items():
            if obj.sprite_index >= 0:
                spr = game.sprite_by_id(obj.sprite_index)
                if spr is not None:
                    self.sprite_users[obj.sprite_index].append(obj)

    def _build_room_transitions(self, game: Game) -> None:
        """Extract room transition calls from bytecode instructions.

        Scans for calls where a PUSHSTR immediately before the call contains
        a room name. This captures room_goto(room_name) style transitions
        regardless of whether room_goto is a script or builtin function.
        """
        room_names_lookup = {room.name: room.id for room in game.rooms.values()}

        for code_id, entry in game.code_entries.items():
            instrs = entry.instructions
            for i, instr in enumerate(instrs):
                if not is_call(instr.opcode):
                    continue

                # Scan backwards up to 15 instructions for PUSHSTR with room name
                for j in range(i - 1, max(i - 15, -1), -1):
                    prev = instrs[j]
                    if prev.opcode != Opcode.PUSHSTR or prev.value_str_id < 0:
                        continue
                    text = game.string(prev.value_str_id)
                    if text in room_names_lookup:
                        target_id = room_names_lookup[text]
                        self.room_transitions.append((code_id, "goto", target_id))
                        break

    def _validate(self, game: Game) -> None:
        """Validate all resolved references and report issues."""
        pass  # Validation stats built on demand via report()

    def report(self, game: Game) -> dict:
        """Generate a resolver validation report."""
        # Count resolved references
        objects_resolved = len(game.objects)
        parents_resolved = len(self.object_parent)
        sprites_resolved = len(self.object_sprite)
        masks_resolved = len(self.object_mask)
        events_total = sum(len(evts) for evts in self.object_events.values())

        room_instances = sum(len(insts) for insts in self.room_instances.values())
        room_cc_resolved = len(self.room_creation_code)

        total_code = len(game.code_entries)
        owned_code = len(self.code_entry_owner)
        unknown_code = sum(1 for t in self.code_entry_owner_type.values() if t == OWNER_UNKNOWN)
        object_events = sum(1 for t in self.code_entry_owner_type.values() if t == OWNER_OBJECT_EVENT)
        scripts = sum(1 for t in self.code_entry_owner_type.values() if t == OWNER_SCRIPT)
        global_scripts = sum(1 for t in self.code_entry_owner_type.values() if t == OWNER_GLOBAL_SCRIPT)
        room_code = sum(1 for t in self.code_entry_owner_type.values() if t == OWNER_ROOM)
        sequences = sum(1 for t in self.code_entry_owner_type.values() if t == OWNER_SEQUENCE)
        timelines = sum(1 for t in self.code_entry_owner_type.values() if t == OWNER_TIMELINE)

        # Call graph
        call_nodes = len(game.code_entries)
        call_edges = sum(len(callees) for callees in self.callees.values())

        # Room graph
        room_nodes = len(game.rooms)
        room_edges = len(self.room_transitions)

        # Object graph
        obj_edges = len(self.object_parent) + sum(len(insts) for insts in self.room_instances.values())

        # Broken references (script calls to non-existent code entries)
        code_count = len(game.code_entries)
        broken = 0
        for code_id, entry in game.code_entries.items():
            for func_id, _, _ in entry.calls:
                if func_id < code_count and func_id not in game.code_entries:
                    broken += 1

        return {
            "objects_loaded": len(game.objects),
            "objects_resolved": objects_resolved,
            "parents_resolved": f"{parents_resolved}/{len(game.objects)}",
            "sprites_resolved": f"{sprites_resolved}/{len(game.objects)}",
            "masks_resolved": f"{masks_resolved}/{len(game.objects)}",
            "events_total": events_total,
            "room_instances": room_instances,
            "room_placements": room_instances,
            "room_creation_code": room_cc_resolved,
            "functions_total": len(game.functions),
            "code_entries_total": total_code,
            "code_ownership_resolved": f"{owned_code}/{total_code}",
            "unknown_code": unknown_code,
            "object_events": object_events,
            "scripts": scripts,
            "global_scripts": global_scripts,
            "room_code": room_code,
            "sequence_callbacks": sequences,
            "timeline_code": timelines,
            "call_nodes": call_nodes,
            "call_edges": call_edges,
            "room_nodes": room_nodes,
            "room_edges": room_edges,
            "broken_script_refs": broken,
        }

    def owner_of(self, code_id: int) -> Optional[str]:
        return self.code_owner.get(code_id)

    def references_of(self, string_id: int) -> list[int]:
        return list(self.string_refs.get(string_id, []))

    def flag_readers(self, flag_idx: int) -> list[int]:
        return list(self.flag_reads.get(flag_idx, []))

    def flag_writers(self, flag_idx: int) -> list[int]:
        return list(self.flag_writes.get(flag_idx, []))

    def objects_using_sprite(self, sprite_id: int) -> list[ObjectDef]:
        return list(self.sprite_users.get(sprite_id, []))

    def instances_in_room(self, room_id: int) -> list[RoomInstance]:
        return list(self.room_instances.get(room_id, []))
