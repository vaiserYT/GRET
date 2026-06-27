"""ObjectAnalyzer: object relationship analysis using the resolver."""
from __future__ import annotations

from code.opcodes import Opcode


class ObjectAnalyzer:
    def __init__(self, game) -> None:
        self.game = game
        self.resolver = game.resolver
        self._created_objects: set[int] = set()

    def analyze(self) -> None:
        for code_entry in self.game.code_entries.values():
            for instr in code_entry.instructions:
                if instr.opcode == Opcode.INSTANTIATE:
                    self._created_objects.add(instr.value_int)

    @property
    def dead_objects(self) -> set[str]:
        instantiated: set[int] = set()
        for instances in self.resolver.room_instances.values():
            for inst in instances:
                instantiated.add(inst.object_id)
        instantiated |= self._created_objects
        all_ids = set(self.game.objects.keys())
        dead_ids = all_ids - instantiated
        return {self.game.objects[oid].name for oid in dead_ids}

    @property
    def orphan_objects(self) -> set[str]:
        parent_ids = set(self.resolver.object_parent.keys())
        child_of = set()
        for child_id, parent in self.resolver.object_parent.items():
            child_of.add(parent.id)
        instantiated: set[int] = set()
        for instances in self.resolver.room_instances.values():
            for inst in instances:
                instantiated.add(inst.object_id)
        instantiated |= self._created_objects
        instantiated |= parent_ids
        instantiated |= child_of
        all_ids = set(self.game.objects.keys())
        orphan_ids = all_ids - instantiated
        return {self.game.objects[oid].name for oid in orphan_ids}

    @property
    def controller_objects(self) -> set[str]:
        instantiated: set[int] = set()
        for instances in self.resolver.room_instances.values():
            for inst in instances:
                instantiated.add(inst.object_id)
        instantiated |= self._created_objects
        controllers: set[str] = set()
        for obj in self.game.objects.values():
            if ("controller" in obj.name.lower() or "ctrl" in obj.name.lower()):
                if obj.id not in instantiated:
                    controllers.add(obj.name)
        return controllers

    def object_summary(self, obj_name: str) -> dict:
        obj = next((o for o in self.game.objects.values() if o.name == obj_name), None)
        if not obj:
            return {}
        sprite = self.resolver.object_sprite.get(obj.id)
        parent = self.resolver.object_parent.get(obj.id)
        placed_rooms = []
        for room_id, instances in self.resolver.room_instances.items():
            if any(inst.object_id == obj.id for inst in instances):
                room = self.game.room_by_id(room_id)
                if room:
                    placed_rooms.append(room.name)
        return {
            "name": obj.name,
            "id": obj.id,
            "sprite": sprite.name if sprite else None,
            "parent": parent.name if parent else None,
            "persistent": obj.persistent,
            "depth": obj.depth,
            "event_count": obj.event_count,
            "events": [(e.event_type, e.subtype) for e in obj.events],
            "placed_in_rooms": placed_rooms,
            "created_dynamically": obj.id in self._created_objects,
        }
