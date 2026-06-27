"""QueryEngine: high-level query interface over resolver + ResourceGraph."""
from __future__ import annotations

from typing import Any, Optional

from analysis.objects import ObjectAnalyzer
from analysis.dialogue import DialogueAnalyzer
from analysis.secret import SecretFinder, SuspiciousItem
from code.opcodes import Opcode


class QueryEngine:
    def __init__(self, game, graph) -> None:
        self.game = game
        self.graph = graph
        self.resolver = game.resolver
        self.secret_finder = SecretFinder(game, graph)
        self.object_analyzer = ObjectAnalyzer(game)
        self.dialogue_analyzer = DialogueAnalyzer(game)

    def why_object(self, name: str) -> dict[str, Any]:
        obj = next((o for o in self.game.objects.values() if o.name == name), None)
        if not obj:
            return {"error": f"Object '{name}' not found"}

        placed_in: list[str] = []
        for room_id, instances in self.resolver.room_instances.items():
            for inst in instances:
                if inst.object_id == obj.id:
                    room = self.game.room_by_id(room_id)
                    if room:
                        placed_in.append(f"{room.name} ({inst.x}, {inst.y})")

        created_in: list[str] = []
        for code_id, entry in self.game.code_entries.items():
            for instr in entry.instructions:
                if instr.opcode == Opcode.INSTANTIATE and instr.value_int == obj.id:
                    owner = self.resolver.owner_of(code_id)
                    if owner:
                        created_in.append(owner)

        sprite = self.resolver.object_sprite.get(obj.id)
        parent = self.resolver.object_parent.get(obj.id)

        incoming = set()
        obj_node = f"obj_{obj.id}"
        if self.graph.object.has_node(obj_node):
            for pred in self.graph.object.predecessors(obj_node):
                incoming.add(str(pred))
        outgoing = set()
        for succ in self.graph.object.successors(obj_node):
            outgoing.add(str(succ))

        return {
            "name": obj.name,
            "id": obj.id,
            "sprite": sprite.name if sprite else None,
            "parent": parent.name if parent else None,
            "depth": obj.depth,
            "persistent": obj.persistent,
            "visible": obj.visible,
            "events": [(e.event_type, e.subtype) for e in obj.events],
            "placed_in_rooms": placed_in,
            "created_dynamically_by": created_in,
            "incoming_refs": list(incoming)[:20],
            "outgoing_refs": list(outgoing)[:20],
        }

    def trace(self, pattern: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        lower = pattern.lower()

        for obj_id, obj in self.game.objects.items():
            if lower in obj.name.lower():
                results.append({
                    "type": "OBJECT", "name": obj.name,
                    "summary": obj.event_summary() if obj.has_any_event else "No events",
                })

        for room_id, room in self.game.rooms.items():
            if lower in room.name.lower():
                results.append({
                    "type": "ROOM", "name": room.name,
                    "summary": f"{room.width}x{room.height}, {room.object_count} instances",
                })

        for sprite in self.game.sprites.values():
            if lower in sprite.name.lower():
                results.append({"type": "SPRITE", "name": sprite.name})

        for sound in self.game.sounds.values():
            if lower in sound.name.lower():
                results.append({"type": "SOUND", "name": sound.name})

        for name in self.game.scripts:
            if lower in name.lower():
                results.append({"type": "SCRIPT", "name": name})

        for str_id, s in enumerate(self.game.strings):
            if lower in s.lower():
                results.append({"type": "STRING", "id": str_id, "name": s[:100]})

        return results[:100]

    def who_uses(self, resource_name: str) -> list[str]:
        users: list[str] = []

        # Check sprite usage via resolver
        if any(s.name == resource_name for s in self.game.sprites.values()):
            for obj_id, sprite in self.resolver.object_sprite.items():
                if sprite.name == resource_name:
                    obj = self.game.object_by_id(obj_id)
                    if obj:
                        users.append(obj.name)

        # Check sound references via resolver
        if any(s.name == resource_name for s in self.game.sounds.values()):
            for code_id, entry in self.game.code_entries.items():
                for instr in entry.instructions:
                    if instr.opcode == Opcode.PUSHSTR and instr.value_str_id >= 0:
                        s = self.game.strings[instr.value_str_id]
                        if s == resource_name:
                            # Check if this code entry calls audio_play
                            for func_id, _, _ in entry.calls:
                                for fname, func in self.game.functions.items():
                                    if func.id == func_id and "audio_play" in fname:
                                        owner = self.resolver.owner_of(code_id)
                                        if owner:
                                            users.append(owner)
                                        break

        # Check room name references
        if any(r.name == resource_name for r in self.game.rooms.values()):
            for code_id, entry in self.game.code_entries.items():
                for instr in entry.instructions:
                    if instr.opcode == Opcode.PUSHSTR and instr.value_str_id >= 0:
                        if self.game.strings[instr.value_str_id] == resource_name:
                            owner = self.resolver.owner_of(code_id)
                            if owner:
                                users.append(owner)

        return list(set(users))[:30]

    def who_writes_flag(self, flag_idx: int) -> list[str]:
        writers = self.resolver.flag_writes.get(flag_idx, [])
        return [self.resolver.owner_of(cid) or f"code_{cid}" for cid in writers]

    def show_room(self, name: str) -> dict[str, Any]:
        room = next((r for r in self.game.rooms.values() if r.name == name), None)
        if not room:
            return {"error": f"Room '{name}' not found"}

        instances_info: list[dict] = []
        for inst in room.instances:
            obj = self.game.object_by_id(inst.object_id)
            instances_info.append({
                "object": obj.name if obj else f"<obj_{inst.object_id}>",
                "x": inst.x, "y": inst.y,
                "instance_id": inst.instance_id,
                "has_creation_code": inst.creation_code_id >= 0,
            })

        incoming = []
        if self.graph.room.has_node(room.id):
            incoming = [str(self.game.room_by_id(p).name if self.game.room_by_id(p) else p)
                        for p in self.graph.room.predecessors(room.id)]
        outgoing = []
        if self.graph.room.has_node(room.id):
            outgoing = [str(self.game.room_by_id(s).name if self.game.room_by_id(s) else s)
                        for s in self.graph.room.successors(room.id)]

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
            "incoming_transitions": incoming[:20],
            "outgoing_transitions": outgoing[:20],
        }

    def unreachable_rooms(self) -> list[str]:
        return sorted(self.game.room_by_id(rid).name
                      for rid in self.graph.unreachable_rooms()
                      if self.game.room_by_id(rid))

    def unreachable_dialogue(self) -> list[tuple[str, str]]:
        self.dialogue_analyzer.analyze()
        return [(f"str[{sid}]", text[:80])
                for sid, text in self.dialogue_analyzer.unused_dialogue()[:200]]

    def dead_objects(self) -> list[str]:
        self.object_analyzer.analyze()
        return sorted(self.object_analyzer.dead_objects)

    def hidden_resources(self) -> list[SuspiciousItem]:
        return self.secret_finder.find_all()

    def search(self, pattern: str) -> list[dict[str, Any]]:
        return self.trace(pattern)
