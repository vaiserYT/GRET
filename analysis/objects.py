"""RuntimeUsageAnalyzer: determines which objects can actually exist at runtime.

Uses multiple detection strategies:
  1. Room placement (instances in rooms)
  2. INSTANTIATE opcode
  3. CALL to instance_create*/instance_change* functions
  4. CALL to layer_instance_create
  5. WITH opcode (with target references)
  6. asset_get_index / object_get_name with object name strings
  7. event_execute_object calls
  8. Object ID literal references in bytecode
  9. Object name strings referenced near creation calls
  10. Collision event references
  11. Parent/child inheritance chains
"""
from __future__ import annotations

from collections import defaultdict
from enum import Flag, auto
from typing import Any, Optional

from code.opcodes import Opcode, is_call


class ObjectState(Flag):
    ROOM_PLACED = auto()
    CREATED_DYNAMICALLY = auto()
    INSTANTIATE_CREATED = auto()
    FUNCTION_CREATED = auto()
    WITH_REFERENCED = auto()
    ASSET_GET_REFERENCED = auto()
    EVENT_EXECUTE_REFERENCED = auto()
    BYTECODE_REFERENCED = auto()
    STRING_REFERENCED = auto()
    CREATION_CODE_REFERENCED = auto()
    COLLISION_REFERENCED = auto()
    INHERITED = auto()
    PARENT_OF = auto()
    HAS_SPRITE = auto()
    HAS_EVENTS = auto()
    UNUSED = auto()
    UNKNOWN = auto()
    LIKELY_UNUSED = auto()


STATE_LABELS: dict[ObjectState, str] = {
    ObjectState.ROOM_PLACED: "placed in room",
    ObjectState.CREATED_DYNAMICALLY: "created dynamically",
    ObjectState.INSTANTIATE_CREATED: "instantiate opcode",
    ObjectState.FUNCTION_CREATED: "creation function call",
    ObjectState.WITH_REFERENCED: "with() reference",
    ObjectState.ASSET_GET_REFERENCED: "asset_get_index",
    ObjectState.EVENT_EXECUTE_REFERENCED: "event_execute_object",
    ObjectState.BYTECODE_REFERENCED: "bytecode reference",
    ObjectState.STRING_REFERENCED: "string reference",
    ObjectState.CREATION_CODE_REFERENCED: "creation code",
    ObjectState.COLLISION_REFERENCED: "collision event",
    ObjectState.INHERITED: "inherited from parent",
    ObjectState.PARENT_OF: "is a parent",
    ObjectState.HAS_SPRITE: "has sprite",
    ObjectState.HAS_EVENTS: "has events",
    ObjectState.UNUSED: "unused",
    ObjectState.UNKNOWN: "unknown",
    ObjectState.LIKELY_UNUSED: "likely unused",
}

CREATION_FUNC_PATTERNS = [
    "instance_create", "instance_change", "layer_instance_create",
    "instance_create_region", "instance_copy",
]
EXECUTE_FUNC_PATTERNS = [
    "event_execute_object", "event_user",
]
ASSET_FUNC_PATTERNS = [
    "asset_get_index", "object_get_name",
]


class RuntimeUsageAnalyzer:
    def __init__(self, game) -> None:
        self.game = game
        self.resolver = game.resolver
        self._states: dict[int, ObjectState] = {}
        self._creation_func_ids: set[int] = set()
        self._execute_func_ids: set[int] = set()
        self._asset_func_ids: set[int] = set()
        self._bytecode_refs: dict[int, list[int]] = defaultdict(list)
        self._string_refs: dict[int, list[int]] = defaultdict(list)
        self._created_by: dict[int, set[str]] = defaultdict(set)
        self._ref_sources: dict[int, set[str]] = defaultdict(set)

    def analyze(self, progress_callback=None) -> None:
        steps = [
            ("Identifying functions", 1), ("Scanning room placement", 1),
            ("Scanning INSTANTIATE opcode", 1), ("Scanning function calls", 1),
            ("Scanning WITH opcode", 1), ("Scanning bytecode references", 1),
            ("Scanning string references", 1), ("Scanning inheritance", 1),
            ("Scanning collision events", 1), ("Scanning creation code refs", 1),
            ("Computing final states", 1),
        ]
        total_weight = sum(w for _, w in steps)
        completed = 0

        def _report(msg):
            nonlocal completed
            if progress_callback:
                completed += 1
                progress_callback(completed, total_weight, msg)

        self._identify_functions()
        _report(steps[0][0])
        self._scan_room_placement()
        _report(steps[1][0])
        self._scan_instantiate_opcode()
        _report(steps[2][0])
        self._scan_function_calls()
        _report(steps[3][0])
        self._scan_with_opcode()
        _report(steps[4][0])
        self._scan_bytecode_references()
        _report(steps[5][0])
        self._scan_string_references()
        _report(steps[6][0])
        self._scan_inheritance()
        _report(steps[7][0])
        self._scan_collision_events()
        _report(steps[8][0])
        self._scan_creation_code_refs()
        _report(steps[9][0])
        self._compute_final_states()
        _report(steps[10][0])

    def _identify_functions(self) -> None:
        for func_id, fname in enumerate(self.game.func_names):
            if not fname:
                continue
            low = fname.lower()
            for pat in CREATION_FUNC_PATTERNS:
                if pat in low:
                    self._creation_func_ids.add(func_id)
                    break
            for pat in EXECUTE_FUNC_PATTERNS:
                if pat in low:
                    self._execute_func_ids.add(func_id)
                    break
            for pat in ASSET_FUNC_PATTERNS:
                if pat in low:
                    self._asset_func_ids.add(func_id)
                    break

    def _scan_room_placement(self) -> None:
        for room_id, instances in self.resolver.room_instances.items():
            for inst in instances:
                oid = inst.object_id
                self._add_state(oid, ObjectState.ROOM_PLACED)
                room = self.game.room_by_id(room_id)
                if room:
                    self._ref_sources[oid].add(f"room:{room.name}")

    def _scan_instantiate_opcode(self) -> None:
        for code_id, entry in self.game.code_entries.items():
            for instr in entry.instructions:
                if instr.opcode == Opcode.INSTANTIATE:
                    oid = instr.value_int
                    if oid in self.game.objects:
                        self._add_state(oid, ObjectState.INSTANTIATE_CREATED)
                        self._add_state(oid, ObjectState.CREATED_DYNAMICALLY)
                        owner = self.resolver.owner_of(code_id)
                        if owner:
                            self._created_by[oid].add(f"INSTANTIATE in {owner}")
                            self._ref_sources[oid].add(f"bytecode:{owner}")
                        else:
                            self._created_by[oid].add(f"INSTANTIATE in CODE[{code_id}]")
                            self._ref_sources[oid].add(f"bytecode:CODE[{code_id}]")

    def _scan_function_calls(self) -> None:
        for code_id, entry in self.game.code_entries.items():
            instrs = entry.instructions
            for i, instr in enumerate(instrs):
                if not is_call(instr.opcode):
                    continue
                func_id = instr.value_func_id

                if func_id in self._creation_func_ids or func_id in self._execute_func_ids:
                    self._detect_creation_args(code_id, instrs, i, func_id)

                if func_id in self._asset_func_ids:
                    self._detect_asset_get(code_id, instrs, i)

    def _detect_creation_args(self, code_id: int, instrs, call_idx: int, func_id: int) -> None:
        for j in range(call_idx - 1, max(call_idx - 8, -1), -1):
            prev = instrs[j]
            if prev.opcode == Opcode.PUSHI and prev.value_int in self.game.objects:
                oid = prev.value_int
                self._add_state(oid, ObjectState.FUNCTION_CREATED)
                self._add_state(oid, ObjectState.CREATED_DYNAMICALLY)
                owner = self.resolver.owner_of(code_id)
                fname = self.game.func_names[func_id] if func_id < len(self.game.func_names) else "?"
                if owner:
                    self._created_by[oid].add(f"call:{fname} in {owner}")
                    self._ref_sources[oid].add(f"bytecode:{owner}")
                break
            if prev.opcode == Opcode.PUSHSTR:
                val = prev.value_str
                if val.startswith("obj_") or val.startswith("_"):
                    for oid, obj in self.game.objects.items():
                        if obj.name == val:
                            self._add_state(oid, ObjectState.FUNCTION_CREATED)
                            self._add_state(oid, ObjectState.CREATED_DYNAMICALLY)
                            owner = self.resolver.owner_of(code_id)
                            fname = self.game.func_names[func_id] if func_id < len(self.game.func_names) else "?"
                            if owner:
                                self._created_by[oid].add(f"call:{fname}(str) in {owner}")
                                self._ref_sources[oid].add(f"bytecode:{owner}")
                            break
                break
            if prev.opcode in (Opcode.PUSHENV, Opcode.POPENV, Opcode.PUSHBLTN):
                continue
            break

    def _detect_asset_get(self, code_id: int, instrs, call_idx: int) -> None:
        for j in range(call_idx - 1, max(call_idx - 5, -1), -1):
            prev = instrs[j]
            if prev.opcode == Opcode.PUSHSTR:
                val = prev.value_str
                if val.startswith("obj_") or val.startswith("_"):
                    for oid, obj in self.game.objects.items():
                        if obj.name == val:
                            self._add_state(oid, ObjectState.ASSET_GET_REFERENCED)
                            owner = self.resolver.owner_of(code_id)
                            if owner:
                                self._ref_sources[oid].add(f"bytecode:{owner}")
                            break
                break
            if prev.opcode in (Opcode.PUSHENV, Opcode.POPENV, Opcode.PUSHBLTN):
                continue
            break

    def _scan_with_opcode(self) -> None:
        for code_id, entry in self.game.code_entries.items():
            instrs = entry.instructions
            for i, instr in enumerate(instrs):
                if instr.opcode != Opcode.WITH:
                    continue
                for j in range(i - 1, max(i - 5, -1), -1):
                    prev = instrs[j]
                    if prev.opcode == Opcode.PUSHI and prev.value_int in self.game.objects:
                        oid = prev.value_int
                        self._add_state(oid, ObjectState.WITH_REFERENCED)
                        owner = self.resolver.owner_of(code_id)
                        if owner:
                            self._ref_sources[oid].add(f"bytecode:with() in {owner}")
                        break
                    if prev.opcode in (Opcode.PUSHENV, Opcode.POPENV, Opcode.PUSHBLTN):
                        continue
                    break

    def _scan_bytecode_references(self) -> None:
        obj_ids = set(self.game.objects.keys())
        for code_id, entry in self.game.code_entries.items():
            for instr in entry.instructions:
                if instr.opcode == Opcode.PUSHI and instr.value_int in obj_ids:
                    oid = instr.value_int
                    self._add_state(oid, ObjectState.BYTECODE_REFERENCED)
                    self._bytecode_refs[oid].append(code_id)
                    owner = self.resolver.owner_of(code_id)
                    if owner:
                        self._ref_sources[oid].add(f"bytecode:{owner}")

    def _scan_string_references(self) -> None:
        obj_names = {o.name for o in self.game.objects.values()}
        for code_id, entry in self.game.code_entries.items():
            for instr in entry.instructions:
                if instr.opcode == Opcode.PUSHSTR and instr.value_str_id >= 0:
                    val = instr.value_str
                    if val in obj_names:
                        oid = next(o.id for o in self.game.objects.values() if o.name == val)
                        self._add_state(oid, ObjectState.STRING_REFERENCED)
                        owner = self.resolver.owner_of(code_id)
                        if owner:
                            self._ref_sources[oid].add(f"str:{val} in {owner}")
                            self._string_refs[oid].append(code_id)

    def _scan_inheritance(self) -> None:
        for child_id, parent in self.resolver.object_parent.items():
            self._add_state(child_id, ObjectState.INHERITED)
            self._add_state(parent.id, ObjectState.PARENT_OF)
            child = self.game.object_by_id(child_id)
            if child:
                self._ref_sources[parent.id].add(f"parent of {child.name}")

    def _scan_collision_events(self) -> None:
        for obj_id, obj in self.game.objects.items():
            for ev in obj.events:
                if ev.event_type == 4:
                    other_id = ev.subtype
                    if other_id in self.game.objects:
                        self._add_state(other_id, ObjectState.COLLISION_REFERENCED)
                        self._ref_sources[other_id].add(f"collision event in {obj.name}")

    def _scan_creation_code_refs(self) -> None:
        for room_id, room in self.game.rooms.items():
            if room.creation_code_id >= 0:
                code = self.game.code_entries.get(room.creation_code_id)
                if code:
                    for instr in code.instructions:
                        self._check_creation_ref(instr, f"room_cc:{room.name}")

            for inst in room.instances:
                if inst.creation_code_id >= 0:
                    code = self.game.code_entries.get(inst.creation_code_id)
                    if code:
                        for instr in code.instructions:
                            self._check_creation_ref(instr, f"inst_cc:room={room.name}")

    def _check_creation_ref(self, instr, source: str) -> None:
        if instr.opcode == Opcode.PUSHI and instr.value_int in self.game.objects:
            oid = instr.value_int
            self._add_state(oid, ObjectState.CREATION_CODE_REFERENCED)
            self._ref_sources[oid].add(source)

    def _compute_final_states(self) -> None:
        for oid, obj in self.game.objects.items():
            if obj.sprite_index >= 0:
                self._add_state(oid, ObjectState.HAS_SPRITE)
            if obj.has_any_event:
                self._add_state(oid, ObjectState.HAS_EVENTS)

            states = self._states.get(oid, ObjectState(0))
            alive = (
                ObjectState.ROOM_PLACED
                | ObjectState.CREATED_DYNAMICALLY
                | ObjectState.INHERITED
                | ObjectState.PARENT_OF
                | ObjectState.COLLISION_REFERENCED
                | ObjectState.WITH_REFERENCED
                | ObjectState.BYTECODE_REFERENCED
                | ObjectState.STRING_REFERENCED
                | ObjectState.CREATION_CODE_REFERENCED
                | ObjectState.ASSET_GET_REFERENCED
            )
            if states & alive:
                pass
            elif states & (ObjectState.HAS_EVENTS | ObjectState.HAS_SPRITE):
                self._add_state(oid, ObjectState.LIKELY_UNUSED)
            else:
                self._add_state(oid, ObjectState.UNUSED)

    def _add_state(self, oid: int, state: ObjectState) -> None:
        if oid not in self._states:
            self._states[oid] = state
        else:
            self._states[oid] |= state

    def states(self, obj_name: str) -> ObjectState:
        obj = next((o for o in self.game.objects.values() if o.name == obj_name), None)
        if obj is None:
            return ObjectState.UNKNOWN
        return self._states.get(obj.id, ObjectState.UNKNOWN)

    def state_labels(self, obj_name: str) -> list[str]:
        s = self.states(obj_name)
        return [STATE_LABELS[flag] for flag in ObjectState if flag in s and flag.name not in ("UNKNOWN",)]

    def is_alive(self, obj_name: str) -> bool:
        s = self.states(obj_name)
        dead = ObjectState(0)
        alive = (
            ObjectState.ROOM_PLACED
            | ObjectState.CREATED_DYNAMICALLY
            | ObjectState.INHERITED
            | ObjectState.PARENT_OF
            | ObjectState.COLLISION_REFERENCED
            | ObjectState.WITH_REFERENCED
            | ObjectState.BYTECODE_REFERENCED
            | ObjectState.STRING_REFERENCED
            | ObjectState.CREATION_CODE_REFERENCED
            | ObjectState.ASSET_GET_REFERENCED
        )
        return bool(s & alive)

    def alive_objects(self) -> set[str]:
        return {o.name for o in self.game.objects.values() if self.is_alive(o.name)}

    def dead_objects(self) -> set[str]:
        return {o.name for o in self.game.objects.values() if not self.is_alive(o.name)}

    def classified_objects(self) -> list[dict[str, Any]]:
        result = []
        for oid, obj in self.game.objects.items():
            s = self._states.get(oid, ObjectState.UNKNOWN)
            alive = self.is_alive(obj.name)
            result.append({
                "id": oid,
                "name": obj.name,
                "states": [STATE_LABELS[flag] for flag in ObjectState if flag in s],
                "alive": alive,
                "created_by": list(self._created_by.get(oid, set())),
                "ref_sources": list(self._ref_sources.get(oid, set())),
            })
        return result

    def object_analysis(self, obj_name: str) -> dict[str, Any]:
        obj = next((o for o in self.game.objects.values() if o.name == obj_name), None)
        if not obj:
            return {"error": f"Object '{obj_name}' not found"}
        s = self._states.get(obj.id, ObjectState.UNKNOWN)
        return {
            "name": obj.name,
            "id": obj.id,
            "states": [STATE_LABELS[flag] for flag in ObjectState if flag in s],
            "alive": self.is_alive(obj_name),
            "created_by": list(self._created_by.get(obj.id, set())),
            "ref_sources": list(self._ref_sources.get(obj.id, set())),
            "sprite": (
                self.game.sprite_by_id(obj.sprite_index).name
                if obj.sprite_index >= 0 and self.game.sprite_by_id(obj.sprite_index)
                else None
            ),
            "parent": (
                self.resolver.object_parent.get(obj.id).name
                if obj.id in self.resolver.object_parent
                else None
            ),
            "children": [
                c.name for c in self.resolver.object_children.get(obj.id, [])
            ],
            "events": [(e.event_type, e.subtype) for e in obj.events],
            "bytecode_ref_count": len(self._bytecode_refs.get(obj.id, [])),
        }

    def who_creates(self, obj_name: str) -> list[str]:
        obj = next((o for o in self.game.objects.values() if o.name == obj_name), None)
        if not obj:
            return []
        return list(self._created_by.get(obj.id, set()))
