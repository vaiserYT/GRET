"""SecretFinder: detect suspicious/hidden resources using resolver + graph."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from analysis.objects import ObjectAnalyzer
from analysis.dialogue import DialogueAnalyzer
from code.opcodes import Opcode


@dataclass
class SuspiciousItem:
    name: str
    resource_type: str
    score: int
    reasons: list[str] = field(default_factory=list)
    details: str = ""

    def __lt__(self, other: SuspiciousItem) -> bool:
        return self.score > other.score


class SecretFinder:
    def __init__(self, game, graph) -> None:
        self.game = game
        self.graph = graph
        self.resolver = game.resolver
        self.items: list[SuspiciousItem] = []

    def find_all(self) -> list[SuspiciousItem]:
        self.items.clear()
        self._find_dead_objects()
        self._find_dead_rooms()
        self._find_dead_scripts()
        self._find_unused_sprites()
        self._find_unused_sounds()
        self._find_unused_dialogue()
        self._find_empty_objects()
        self._find_orphan_resources()
        self.items.sort()
        return self.items

    def _find_dead_objects(self) -> None:
        obj_analyzer = ObjectAnalyzer(self.game)
        obj_analyzer.analyze()
        dead = obj_analyzer.dead_objects
        orphan = obj_analyzer.orphan_objects

        for obj_name in dead:
            obj = next((o for o in self.game.objects.values() if o.name == obj_name), None)
            if not obj:
                continue
            score = 40
            reasons = []
            if obj.has_step:
                score += 15
                reasons.append("Has Step event but never instantiated")
            if obj.has_draw:
                score += 10
                reasons.append("Has Draw event but never instantiated")
            if obj.has_create:
                score += 5
                reasons.append("Has Create event but never instantiated")
            if obj.has_alarm:
                score += 10
                reasons.append("Has Alarm event but never instantiated")
            if obj.sprite_index >= 0:
                score += 5
                sprite = self.game.sprite_by_id(obj.sprite_index)
                reasons.append(f"References sprite '{sprite.name if sprite else '?'}' but never used")
            if obj.event_count > 3:
                score += 10
                reasons.append(f"Has {obj.event_count} events but never instantiated (complex dead object)")
            if obj_name in orphan:
                score += 15
                reasons.append("Not placed, not created dynamically, not inherited")
            details = obj.event_summary() if obj.has_any_event else "Empty object"
            self.items.append(SuspiciousItem(
                name=obj_name, resource_type="OBJECT", score=score,
                reasons=reasons[:5], details=details,
            ))

    def _find_dead_rooms(self) -> None:
        unreachable_ids = self.graph.unreachable_rooms()
        for room_id in sorted(unreachable_ids):
            room = self.game.room_by_id(room_id)
            if not room:
                continue
            score = 50
            reasons = ["No incoming room transitions (potentially unreachable)"]
            if not room.instances:
                score += 15
                reasons.append("Empty room (no instances placed)")
            obj_count = room.object_count
            if obj_count > 20:
                score += 10
                reasons.append(f"Has {obj_count} instances but no incoming path")
            self.items.append(SuspiciousItem(
                name=room.name, resource_type="ROOM", score=score,
                reasons=reasons,
                details=f"Room has {obj_count} instances, {len(room.views)} views",
            ))

    def _find_dead_scripts(self) -> None:
        called_funcs: set[str] = set()
        for caller_id, callees in self.resolver.callees.items():
            for callee_id in callees:
                entry = self.game.code_entries.get(callee_id)
                if entry and entry.name.startswith("gml_Script_"):
                    script_name = entry.name[len("gml_Script_"):]
                    called_funcs.add(script_name)

        dead_scripts: set[str] = set()
        for name, script in self.game.scripts.items():
            func_name = f"gml_Script_{script.name}"
            if func_name not in called_funcs and script.name not in called_funcs:
                dead_scripts.add(script.name)

        for script_name in sorted(dead_scripts):
            score = 35
            reasons = ["Script never called from any code path"]
            self.items.append(SuspiciousItem(
                name=script_name, resource_type="SCRIPT", score=score, reasons=reasons,
            ))

    def _find_unused_sprites(self) -> None:
        used_sprites: set[str] = set()
        for obj in self.game.objects.values():
            if obj.sprite_index >= 0:
                sprite = self.game.sprite_by_id(obj.sprite_index)
                if sprite:
                    used_sprites.add(sprite.name)

        all_sprites = {s.name for s in self.game.sprites.values()}
        unused = all_sprites - used_sprites
        for sprite_name in sorted(unused)[:200]:
            self.items.append(SuspiciousItem(
                name=sprite_name, resource_type="SPRITE", score=10,
                reasons=["Sprite not assigned to any object"],
            ))

    def _find_unused_sounds(self) -> None:
        audio_func_ids: set[int] = set()
        for name, func in self.game.functions.items():
            if "audio_play" in name:
                audio_func_ids.add(func.id)

        played_sounds: set[str] = set()
        for code_id, entry in self.game.code_entries.items():
            for func_id, _, _ in entry.calls:
                if func_id in audio_func_ids:
                    for instr in entry.instructions:
                        if instr.opcode == Opcode.PUSHSTR and instr.value_str_id >= 0:
                            s = self.game.string(instr.value_str_id)
                            sound = next((sd for sd in self.game.sounds.values() if sd.name == s), None)
                            if sound:
                                played_sounds.add(s)

        all_sounds = {s.name for s in self.game.sounds.values()}
        unused = all_sounds - played_sounds
        for sound_name in sorted(unused)[:200]:
            self.items.append(SuspiciousItem(
                name=sound_name, resource_type="SOUND", score=10,
                reasons=["Sound never played via audio_play_sound"],
            ))

    def _find_unused_dialogue(self) -> None:
        dia = DialogueAnalyzer(self.game)
        dia.analyze()
        for str_id, text in dia.unused_dialogue():
            if len(text) < 5:
                continue
            preview = text[:80] + "..." if len(text) > 80 else text
            score = 20 + min(len(text), 20)
            self.items.append(SuspiciousItem(
                name=f"str[{str_id}]", resource_type="STRING", score=score,
                reasons=["Dialogue string never referenced by any dialogue function"],
                details=f'"{preview}"',
            ))

    def _find_empty_objects(self) -> None:
        for obj_id, obj in self.game.objects.items():
            if not obj.has_any_event:
                self.items.append(SuspiciousItem(
                    name=obj.name, resource_type="OBJECT", score=5,
                    reasons=["Object has no events"],
                ))

    def _find_orphan_resources(self) -> None:
        resource_refs: dict[str, set[str]] = defaultdict(set)
        for room_id, instances in self.resolver.room_instances.items():
            room = self.game.room_by_id(room_id)
            for inst in instances:
                obj = self.game.object_by_id(inst.object_id)
                if obj and room:
                    resource_refs[obj.name].add(room.name)
        for child_id, parent in self.resolver.object_parent.items():
            child = self.game.object_by_id(child_id)
            if child:
                resource_refs[parent.name].add(child.name)
        for obj_id, sprite in self.resolver.object_sprite.items():
            obj = self.game.object_by_id(obj_id)
            if obj:
                resource_refs[sprite.name].add(obj.name)

        all_resources: dict[str, str] = {}
        for obj in self.game.objects.values():
            all_resources[obj.name] = "OBJECT"
        for room in self.game.rooms.values():
            all_resources[room.name] = "ROOM"
        for sprite in self.game.sprites.values():
            all_resources[sprite.name] = "SPRITE"
        for sound in self.game.sounds.values():
            all_resources[sound.name] = "SOUND"
        for name in self.game.scripts:
            all_resources[name] = "SCRIPT"

        for name, rtype in all_resources.items():
            if name not in resource_refs:
                score = 15 if rtype in ("OBJECT", "ROOM") else 8
                self.items.append(SuspiciousItem(
                    name=name, resource_type=rtype, score=score,
                    reasons=[f"{rtype} has zero incoming references (orphan)"],
                ))

    def top_suspicious(self, limit: int = 100) -> list[SuspiciousItem]:
        return self.items[:limit]
