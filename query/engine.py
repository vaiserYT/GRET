"""QueryEngine: high-level query interface over resolver + ResourceGraph."""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Callable, Optional

from analysis.objects import RuntimeUsageAnalyzer
from analysis.dialogue import DialogueAnalyzer
from analysis.secret import SecretFinder, SuspiciousItem
from code.opcodes import Opcode


ProgressCB = Optional[Callable[[int, int, str], None]]


class QueryEngine:
    def __init__(self, game, graph) -> None:
        self.game = game
        self.graph = graph
        self.resolver = game.resolver
        self.secret_finder = SecretFinder(game, graph)
        self.object_analyzer = RuntimeUsageAnalyzer(game)
        self.dialogue_analyzer = DialogueAnalyzer(game)

    def why_object(self, name: str, on_progress: ProgressCB = None) -> dict[str, Any]:
        obj = next((o for o in self.game.objects.values() if o.name == name), None)
        if not obj:
            return {"error": f"Object '{name}' not found"}

        if on_progress:
            on_progress(0, 1, "Analyzing runtime usage")
        self.object_analyzer.analyze(progress_callback=on_progress)
        info = self.object_analyzer.object_analysis(name)
        if "error" in info:
            return info

        if on_progress:
            on_progress(1, 1, "Gathering room refs")
        placed_in: list[str] = []
        for room_id, instances in self.resolver.room_instances.items():
            for inst in instances:
                if inst.object_id == obj.id:
                    room = self.game.room_by_id(room_id)
                    if room:
                        placed_in.append(f"{room.name} ({inst.x}, {inst.y})")

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
            "states": info.get("states", []),
            "alive": info.get("alive", False),
            "created_by": info.get("created_by", []),
            "ref_sources": info.get("ref_sources", []),
            "children": info.get("children", []),
            "incoming_refs": list(incoming)[:20],
            "outgoing_refs": list(outgoing)[:20],
        }

    def trace(self, pattern: str, on_progress: ProgressCB = None) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        lower = pattern.lower()

        self.object_analyzer.analyze()
        phases = [
            ("objects", len(self.game.objects)),
            ("rooms", len(self.game.rooms)),
            ("sprites", len(self.game.sprites)),
            ("sounds", len(self.game.sounds)),
            ("scripts", len(self.game.scripts)),
            ("strings", len(self.game.strings)),
        ]
        total_weight = sum(w for _, w in phases)
        completed = 0

        def _report(msg):
            nonlocal completed
            if on_progress:
                completed += 1
                on_progress(completed, total_weight, msg)

        matched_objs = 0
        for obj_id, obj in self.game.objects.items():
            if lower not in obj.name.lower():
                continue
            matched_objs += 1
            info = self.object_analyzer.object_analysis(obj.name)
            chain: list[str] = info.get("ref_sources", [])[:5]
            created_by = info.get("created_by", [])
            chain.extend(created_by[:3])
            summary = "; ".join(chain) if chain else obj.event_summary() if obj.has_any_event else "No events"
            results.append({
                "type": "OBJECT", "name": obj.name,
                "summary": summary,
                "alive": info.get("alive", False),
                "states": info.get("states", []),
                "sprite": info.get("sprite"),
                "parent": info.get("parent"),
                "children": info.get("children", [])[:5],
            })
        _report(f"{matched_objs} objects matched")

        matched_rooms = 0
        for room_id, room in self.game.rooms.items():
            if lower not in room.name.lower():
                continue
            matched_rooms += 1
            reachable = room.id not in self.graph.unreachable_rooms()
            summary = f"{room.width}x{room.height}, {len(room.instances)} instances"
            if not reachable:
                summary += " [UNREACHABLE]"
            results.append({
                "type": "ROOM", "name": room.name,
                "summary": summary,
                "reachable": reachable,
                "instance_count": len(room.instances),
            })
        _report(f"{matched_rooms} rooms matched")

        matched_sprites = 0
        for sprite in self.game.sprites.values():
            if lower not in sprite.name.lower():
                continue
            matched_sprites += 1
            users = [o.name for o in self.game.objects.values() if o.sprite_index == sprite.id]
            summary = f"Used by {len(users)} objects"
            if users:
                summary += f": {', '.join(users[:8])}"
            results.append({
                "type": "SPRITE", "name": sprite.name,
                "summary": summary,
                "users": users[:10],
            })
        _report(f"{matched_sprites} sprites matched")

        for sound in self.game.sounds.values():
            if lower in sound.name.lower():
                results.append({"type": "SOUND", "name": sound.name})
        _report("sounds done")

        matched_scripts = 0
        for name in self.game.scripts:
            if lower not in name.lower():
                continue
            matched_scripts += 1
            func_name = f"gml_Script_{name}"
            callers = []
            for cid, callees in self.resolver.callees.items():
                for callee_id in callees:
                    entry = self.game.code_entries.get(callee_id)
                    if entry and entry.name == func_name:
                        owner = self.resolver.owner_of(cid)
                        if owner:
                            callers.append(owner)
            summary = f"Called by {len(callers)} locations"
            if callers:
                summary += f": {', '.join(callers[:5])}"
            results.append({
                "type": "SCRIPT", "name": name,
                "summary": summary,
                "callers": callers[:10],
            })
        _report(f"{matched_scripts} scripts matched")

        matched_strs = 0
        for str_id, s in enumerate(self.game.strings):
            if lower not in s.lower():
                continue
            matched_strs += 1
            refs = self.resolver.string_refs.get(str_id, [])
            owners = set()
            for cid in refs:
                owner = self.resolver.owner_of(cid)
                if owner:
                    owners.add(owner)
            summary = f"Referenced by {len(refs)} code entries"
            if owners:
                summary += f": {', '.join(list(owners)[:5])}"
            results.append({
                "type": "STRING", "id": str_id,
                "name": s[:120],
                "summary": summary,
                "ref_count": len(refs),
            })
        _report(f"{matched_strs} strings matched")

        return results[:100]

    def who_uses(self, resource_name: str, on_progress: ProgressCB = None) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {
            "objects": [],
            "scripts": [],
            "rooms": [],
            "bytecode": [],
            "events": [],
            "creation_code": [],
            "dialogue": [],
        }

        if on_progress:
            on_progress(0, 4, "Finding resource by type")
        sprite = next((s for s in self.game.sprites.values() if s.name == resource_name), None)
        sound = next((s for s in self.game.sounds.values() if s.name == resource_name), None)
        room = next((r for r in self.game.rooms.values() if r.name == resource_name), None)
        obj = next((o for o in self.game.objects.values() if o.name == resource_name), None)

        if sprite:
            if on_progress:
                on_progress(1, 4, "Checking sprite references")
            for o in self.game.objects.values():
                if o.sprite_index == sprite.id:
                    result["objects"].append(o.name)

        if sound:
            if on_progress:
                on_progress(2, 4, "Scanning bytecode for sound refs")
            for code_id, entry in self.game.code_entries.items():
                for instr in entry.instructions:
                    if instr.opcode == Opcode.PUSHSTR and instr.value_str_id >= 0:
                        s = self.game.string(instr.value_str_id)
                        if s == resource_name:
                            for func_id, _, _ in entry.calls:
                                fname = self.game.func_names[func_id] if func_id < len(self.game.func_names) else ""
                                if "audio_play" in fname.lower():
                                    owner = self.resolver.owner_of(code_id)
                                    if owner:
                                        result["bytecode"].append(
                                            f"{owner} (audio_play_sound)"
                                        )
                                    break

        if room:
            if on_progress:
                on_progress(2, 4, "Scanning bytecode for room refs")
            for code_id, entry in self.game.code_entries.items():
                for instr in entry.instructions:
                    if instr.opcode == Opcode.PUSHSTR and instr.value_str_id >= 0:
                        if self.game.string(instr.value_str_id) == resource_name:
                            owner = self.resolver.owner_of(code_id)
                            if owner:
                                result["bytecode"].append(f"{owner} (room_goto)")

            if self.graph.room.has_node(room.id):
                for pred in self.graph.room.predecessors(room.id):
                    r = self.game.room_by_id(pred)
                    if r:
                        result["rooms"].append(r.name)

        if obj:
            if on_progress:
                on_progress(3, 4, "Analyzing object references")
            self.object_analyzer.analyze(progress_callback=on_progress)
            rs = self.object_analyzer.object_analysis(obj.name)
            for src in rs.get("ref_sources", []):
                if src.startswith("bytecode:"):
                    result["bytecode"].append(src)
                elif src.startswith("room:"):
                    result["rooms"].append(src.replace("room:", ""))
                elif src.startswith("collision event in "):
                    result["events"].append(src.replace("collision event in ", ""))
                elif src.startswith("inst_cc:") or src.startswith("room_cc:"):
                    result["creation_code"].append(src)
                else:
                    result["bytecode"].append(src)

            for c in rs.get("children", []):
                result["objects"].append(c)

            parent = rs.get("parent")
            if parent:
                result["objects"].append(f"PARENT({parent})")

        for key in result:
            result[key] = list(set(result[key]))[:30]

        if on_progress:
            on_progress(4, 4, "Done")
        return result

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

    def unreachable_dialogue(self, on_progress: ProgressCB = None) -> list[tuple[str, str]]:
        self.dialogue_analyzer.analyze(progress_callback=on_progress)
        return [(f"str[{sid}]", text[:80])
                for sid, text in self.dialogue_analyzer.unused_dialogue()[:200]]

    def dead_objects(self, on_progress: ProgressCB = None) -> list[str]:
        self.object_analyzer.analyze(progress_callback=on_progress)
        return sorted(self.object_analyzer.dead_objects())

    def hidden_resources(self, on_progress: ProgressCB = None) -> list[SuspiciousItem]:
        return self.secret_finder.find_all(progress_callback=on_progress)

    def search(self, pattern: str, on_progress: ProgressCB = None) -> list[dict[str, Any]]:
        return self.trace(pattern, on_progress=on_progress)
