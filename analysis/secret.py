"""SecretFinder: confidence-based suspicious resource detection.

Uses multiple independent heuristics and aggregates them into a 0-100
confidence score. Never classifies something as "secret" solely because
it is absent from rooms.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional

from analysis.objects import RuntimeUsageAnalyzer, ObjectState
from analysis.dialogue import DialogueAnalyzer
from code.opcodes import Opcode, is_call


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


class SecretFinder:
    def __init__(self, game, graph) -> None:
        self.game = game
        self.graph = graph
        self.resolver = game.resolver
        self.items: list[SuspiciousItem] = []
        self._obj_analyzer: Optional[RuntimeUsageAnalyzer] = None

    def analyze_objects(self, progress_callback=None) -> RuntimeUsageAnalyzer:
        if self._obj_analyzer is None:
            a = RuntimeUsageAnalyzer(self.game)
            a.analyze(progress_callback=progress_callback)
            self._obj_analyzer = a
        return self._obj_analyzer

    def find_all(self, progress_callback=None) -> list[SuspiciousItem]:
        self.items.clear()
        phases = [
            ("objects", self._find_suspicious_objects),
            ("rooms", self._find_suspicious_rooms),
            ("scripts", self._find_suspicious_scripts),
            ("sprites", self._find_suspicious_sprites),
            ("sounds", self._find_suspicious_sounds),
            ("dialogue", self._find_suspicious_dialogue),
            ("empty objects", self._find_empty_objects),
            ("orphan resources", self._find_orphan_resources),
        ]
        total = len(phases)
        for i, (name, method) in enumerate(phases):
            if progress_callback:
                progress_callback(i, total, f"Analyzing {name}")
            method()
        if progress_callback:
            progress_callback(total, total, "Sorting results")
        self.items.sort()
        return self.items

    def _confidence(self, evidence_for: list[str], evidence_against: list[str]) -> int:
        score = 0
        score += min(len(evidence_for) * 15, 70)
        score -= min(len(evidence_against) * 20, 60)
        score = max(0, min(100, score))
        if not evidence_against and evidence_for:
            score = max(score, 40)
        return score

    def _find_suspicious_objects(self) -> None:
        obj_an = self.analyze_objects()
        for obj_info in obj_an.classified_objects():
            name = obj_info["name"]
            states = obj_info["states"]

            evidence_for: list[str] = []
            evidence_against: list[str] = []

            if "unused" in states or "likely unused" in states:
                evidence_for.append("never instantiated")

            if ObjectState.BYTECODE_REFERENCED.name.lower() in str(states).lower():
                evidence_against.append("referenced in bytecode")
            if ObjectState.ROOM_PLACED.name.lower() in str(states).lower():
                evidence_against.append("placed in room")
            if ObjectState.CREATED_DYNAMICALLY.name.lower() in str(states).lower():
                evidence_against.append("dynamically created")
            if ObjectState.INHERITED.name.lower() in str(states).lower():
                evidence_against.append("inherits from parent")
            if ObjectState.PARENT_OF.name.lower() in str(states).lower():
                evidence_against.append("is a parent object")
            if ObjectState.STRING_REFERENCED.name.lower() in str(states).lower():
                evidence_against.append("referenced by strings")
            if ObjectState.COLLISION_REFERENCED.name.lower() in str(states).lower():
                evidence_against.append("in collision events")
            if ObjectState.CREATION_CODE_REFERENCED.name.lower() in str(states).lower():
                evidence_against.append("in creation code")
            if ObjectState.WITH_REFERENCED.name.lower() in str(states).lower():
                evidence_against.append("with() reference")
            if ObjectState.ASSET_GET_REFERENCED.name.lower() in str(states).lower():
                evidence_against.append("asset_get_index reference")
            if ObjectState.FUNCTION_CREATED.name.lower() in str(states).lower():
                evidence_against.append("creation function call")

            obj = next((o for o in self.game.objects.values() if o.name == name), None)
            if obj:
                if obj.event_count > 5:
                    evidence_for.append(f"complex object ({obj.event_count} events)")
                if "controller" in name.lower() or "ctrl" in name.lower():
                    evidence_for.append("controller naming pattern")

            low = name.lower()
            for pat in SUSPICIOUS_NAMES:
                if pat in low:
                    evidence_for.append(f"suspicious name pattern: '{pat}'")
                    break

            if obj and obj.sprite_index >= 0:
                sprite = self.game.sprite_by_id(obj.sprite_index)
                if sprite and not any(
                    o.sprite_index == obj.sprite_index
                    for o in self.game.objects.values()
                    if o.id != obj.id and o.name != name
                ):
                    evidence_for.append("unique sprite (not shared)")

            if not evidence_for and not evidence_against:
                continue

            if not evidence_against and evidence_for:
                evidence_for.append("no evidence of runtime use")

            conf = self._confidence(evidence_for, evidence_against)
            if conf < 20:
                continue

            self.items.append(SuspiciousItem(
                name=name, resource_type="OBJECT", confidence=conf,
                reasons=evidence_for[:5],
                evidence_for=evidence_for[:5],
                evidence_against=evidence_against[:5],
                details=f"States: {', '.join(states[:5])}",
            ))

    def _find_suspicious_rooms(self) -> None:
        unreachable_ids = self.graph.unreachable_rooms()
        for room_id in sorted(unreachable_ids):
            room = self.game.room_by_id(room_id)
            if not room:
                continue
            evidence_for: list[str] = []
            evidence_against: list[str] = []

            evidence_for.append("no incoming room transitions")

            if not room.instances:
                evidence_for.append("empty room (zero instances)")

            obj_count = len(room.instances)
            if obj_count > 10:
                evidence_for.append(f"has {obj_count} instances but unreachable")

            low = room.name.lower()
            for pat in SUSPICIOUS_NAMES:
                if pat in low:
                    evidence_for.append(f"suspicious name: '{pat}'")
                    break

            has_outgoing = any(
                self.graph.room.has_edge(room_id, t)
                for t in range(300)
            )
            if has_outgoing:
                evidence_against.append("has outgoing transitions")

            conf = self._confidence(evidence_for, evidence_against)
            if conf < 25:
                continue

            self.items.append(SuspiciousItem(
                name=room.name, resource_type="ROOM", confidence=conf,
                reasons=evidence_for[:5],
                evidence_for=evidence_for[:5],
                evidence_against=evidence_against[:5],
                details=f"Room has {obj_count} instances, {len(room.views)} views",
            ))

    def _find_suspicious_scripts(self) -> None:
        obj_an = self.analyze_objects()
        alive_objects = obj_an.alive_objects()
        used_funcs: set[str] = set()

        for cid, callees in self.resolver.callees.items():
            for callee_id in callees:
                entry = self.game.code_entries.get(callee_id)
                if entry and entry.name:
                    used_funcs.add(entry.name)

        for name, script in self.game.scripts.items():
            func_name = f"gml_Script_{script.name}"
            if func_name in used_funcs:
                continue

            evidence_for: list[str] = []
            evidence_against: list[str] = []
            evidence_for.append("script never called")

            low = script.name.lower()
            for pat in SUSPICIOUS_NAMES:
                if pat in low:
                    evidence_for.append(f"suspicious name: '{pat}'")
                    break

            conf = self._confidence(evidence_for, evidence_against)
            if conf < 25:
                continue
            self.items.append(SuspiciousItem(
                name=script.name, resource_type="SCRIPT", confidence=conf,
                reasons=evidence_for[:5], evidence_for=evidence_for[:5],
                evidence_against=evidence_against[:5],
            ))

    def _find_suspicious_sprites(self) -> None:
        used_sprites: set[int] = set()
        for obj in self.game.objects.values():
            if obj.sprite_index >= 0:
                used_sprites.add(obj.sprite_index)

        for sprite in self.game.sprites.values():
            if sprite.id in used_sprites:
                continue
            evidence_for: list[str] = []
            evidence_against: list[str] = []

            evidence_for.append("sprite not assigned to any object")

            low = sprite.name.lower()
            for pat in SUSPICIOUS_NAMES:
                if pat in low:
                    evidence_for.append(f"suspicious name: '{pat}'")
                    break

            conf = self._confidence(evidence_for, evidence_against)
            if conf < 10:
                continue
            self.items.append(SuspiciousItem(
                name=sprite.name, resource_type="SPRITE", confidence=conf,
                reasons=evidence_for[:5],
                evidence_for=evidence_for[:5],
                evidence_against=evidence_against[:5],
            ))

    def _find_suspicious_sounds(self) -> None:
        audio_func_ids: set[int] = set()
        for func_id, fname in enumerate(self.game.func_names):
            if fname and "audio_play" in fname.lower():
                audio_func_ids.add(func_id)

        played_sounds: set[str] = set()
        for code_id, entry in self.game.code_entries.items():
            for func_id, _, _ in entry.calls:
                if func_id in audio_func_ids:
                    for instr in entry.instructions:
                        if instr.opcode == Opcode.PUSHSTR and instr.value_str_id >= 0:
                            s = self.game.string(instr.value_str_id)
                            sound = next(
                                (sd for sd in self.game.sounds.values() if sd.name == s),
                                None,
                            )
                            if sound:
                                played_sounds.add(s)

        all_sounds = {s.name for s in self.game.sounds.values()}
        unused = all_sounds - played_sounds
        for sound_name in sorted(unused)[:300]:
            evidence_for: list[str] = []
            evidence_against: list[str] = []
            evidence_for.append("sound never played via audio_play_sound")
            low = sound_name.lower()
            for pat in SUSPICIOUS_NAMES:
                if pat in low:
                    evidence_for.append(f"suspicious name: '{pat}'")
                    break
            conf = self._confidence(evidence_for, evidence_against)
            if conf < 10:
                continue
            self.items.append(SuspiciousItem(
                name=sound_name, resource_type="SOUND", confidence=conf,
                reasons=evidence_for[:5],
                evidence_for=evidence_for[:5],
                evidence_against=evidence_against[:5],
            ))

    def _find_suspicious_dialogue(self) -> None:
        dia = DialogueAnalyzer(self.game)
        dia.analyze()
        for str_id, text in dia.unused_dialogue():
            if len(text) < 5:
                continue
            low = text.lower()
            evidence_for: list[str] = []
            evidence_against: list[str] = []
            evidence_for.append("dialogue string never referenced")
            score = 20 + min(len(text), 20)
            for pat in ["secret", "hidden", "easter egg", "bonus", "debug"]:
                if pat in low:
                    evidence_for.append(f"content hint: '{pat}'")
                    score += 15
                    break
            preview = text[:80] + "..." if len(text) > 80 else text
            conf = min(score, 70)
            if conf < 15:
                continue
            self.items.append(SuspiciousItem(
                name=f"str[{str_id}]", resource_type="STRING", confidence=conf,
                reasons=evidence_for[:5],
                evidence_for=evidence_for[:5],
                evidence_against=evidence_against[:5],
                details=f'"{preview}"',
            ))

    def _find_empty_objects(self) -> None:
        for obj_id, obj in self.game.objects.items():
            if obj.has_any_event:
                continue
            evidence_for: list[str] = ["object has no events"]
            obj_an = self.analyze_objects()
            if obj_an.is_alive(obj.name):
                continue
            self.items.append(SuspiciousItem(
                name=obj.name, resource_type="OBJECT", confidence=15,
                reasons=evidence_for[:5],
                evidence_for=evidence_for[:5],
                evidence_against=[],
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
                conf = 15 if rtype in ("OBJECT", "ROOM") else 8
                self.items.append(SuspiciousItem(
                    name=name, resource_type=rtype, confidence=conf,
                    reasons=[f"{rtype} has zero incoming references (orphan)"],
                    evidence_for=[f"orphan {rtype}"],
                    evidence_against=[],
                ))

    def top_suspicious(self, limit: int = 100) -> list[SuspiciousItem]:
        return self.items[:limit]
