from __future__ import annotations

from analyzers.base import BaseAnalyzer
from core.models import (
    AnalysisResult,
    ResourceType,
    SuspicionLevel,
    SuspiciousResource,
    suspicion_level_from_score,
)


class RoomAnalyzer(BaseAnalyzer):
    def analyze(self) -> None:
        all_rooms = set(self.index.rooms.keys())
        rooms_with_incoming: set[str] = set()
        rooms_with_outgoing: set[str] = set()
        rooms_with_instances: set[str] = set()
        rooms_referenced: set[str] = set()

        for transition in self.index.transitions:
            rooms_with_incoming.add(transition.target_room)
            rooms_with_outgoing.add(transition.source_room)

        for target, refs in self.index.call_targets.items():
            for ref in refs:
                if target in self.index.rooms:
                    rooms_referenced.add(target)

        for room_name, room in self.index.rooms.items():
            if room.instances:
                rooms_with_instances.add(room_name)
            for event_key, event in room.creation_code_events() if hasattr(room, 'creation_code_events') else []:
                pass
            if room.creation_code:
                import re
                for match in re.finditer(r"room_goto\s*\(\s*(\w+)", room.creation_code):
                    rooms_with_outgoing.add(room_name)
                for match in re.finditer(r"instance_create", room.creation_code):
                    rooms_with_instances.add(room_name)

        dead_rooms = all_rooms - rooms_with_incoming - rooms_referenced
        no_outgoing = all_rooms - rooms_with_outgoing
        no_instances = all_rooms - rooms_with_instances

        self.database.dead_rooms = dead_rooms

        for room_name in dead_rooms:
            room = self.index.rooms[room_name]
            score = 0
            reasons = []

            score += 50
            reasons.append("No incoming room transitions")

            if room_name not in rooms_referenced:
                score += 30
                reasons.append("Not referenced in any code")

            if room.instances:
                score -= 10
                reasons.append("Has instances placed (may be start room)")

            if room.creation_code:
                score -= 5
                reasons.append("Has creation code")

            self.database.add_suspicious(SuspiciousResource(
                name=room_name,
                resource_type=ResourceType.ROOM,
                score=score,
                level=suspicion_level_from_score(score),
                reasons=reasons,
                details=f"Room {room_name} has no incoming transitions",
            ))

        for room_name in no_outgoing - dead_rooms:
            room = self.index.rooms[room_name]
            score = 20
            reasons = ["No outgoing room transitions"]
            if not room.instances:
                score += 10
                reasons.append("No instances placed")
            self.database.add_suspicious(SuspiciousResource(
                name=room_name,
                resource_type=ResourceType.ROOM,
                score=score,
                level=suspicion_level_from_score(score),
                reasons=reasons,
            ))

        for room_name in self.index.rooms:
            result = AnalysisResult(
                resource_name=room_name,
                analyzer="rooms",
                findings=[],
            )
            if room_name in dead_rooms:
                result.findings.append("No incoming transitions (potentially unreachable)")
                result.score += 50
            if room_name in no_outgoing:
                result.findings.append("No outgoing transitions (dead end)")
                result.score += 20
            if room_name in no_instances:
                result.findings.append("No instances placed in room")
                result.score += 10
            self.database.add_result("rooms", result)

        self.log(f"Found {len(dead_rooms)} rooms with no incoming transitions")
        self.log(f"Found {len(no_outgoing)} rooms with no outgoing transitions")
        self.log(f"Found {len(no_instances)} empty rooms")

    def name(self) -> str:
        return "rooms"
