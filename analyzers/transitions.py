from __future__ import annotations

import re

from analyzers.base import BaseAnalyzer
from core.models import (
    AnalysisResult,
    Reference,
    ReferenceType,
    ResourceType,
    RoomTransition,
    SourceLocation,
    SuspicionLevel,
    SuspiciousResource,
    suspicion_level_from_score,
)


class TransitionAnalyzer(BaseAnalyzer):
    def analyze(self) -> None:
        all_transitions = list(self.index.transitions)
        transition_map: dict[str, list[RoomTransition]] = {}
        reverse_map: dict[str, list[RoomTransition]] = {}

        custom_transitions: list[tuple[str, str, SourceLocation]] = []

        for obj in self.index.objects.values():
            for event_key, event in obj.events.items():
                source = SourceLocation(
                    resource_name=obj.name,
                    resource_type=ResourceType.OBJECT,
                    file_path=obj.path or self.index.project_path,
                    context=f"Event: {event_key}",
                )
                self._find_transition_refs(event.code, source, all_transitions, transition_map, reverse_map, custom_transitions)

        for script in self.index.scripts.values():
            source = SourceLocation(
                resource_name=script.name,
                resource_type=ResourceType.SCRIPT,
                file_path=script.path or self.index.project_path,
            )
            self._find_transition_refs(script.code, source, all_transitions, transition_map, reverse_map, custom_transitions)

        for room in self.index.rooms.values():
            if room.creation_code:
                source = SourceLocation(
                    resource_name=room.name,
                    resource_type=ResourceType.ROOM,
                    file_path=room.path or self.index.project_path,
                )
                self._find_transition_refs(room.creation_code, source, all_transitions, transition_map, reverse_map, custom_transitions)

        self.index.transitions = all_transitions

        all_rooms = set(self.index.rooms.keys())
        rooms_with_incoming: set[str] = set()
        rooms_with_outgoing: set[str] = set()

        for room_name, trans_list in reverse_map.items():
            if room_name in all_rooms or room_name.startswith("room_"):
                rooms_with_incoming.add(room_name)

        for room_name, trans_list in transition_map.items():
            if room_name in all_rooms or room_name.startswith("room_"):
                rooms_with_outgoing.add(room_name)

        hidden_rooms = all_rooms - rooms_with_incoming
        terminal_rooms = all_rooms - rooms_with_outgoing

        for room_name in hidden_rooms:
            if room_name in all_rooms:
                score = 50
                reasons = ["Room has no incoming transitions"]
                self.database.add_suspicious(SuspiciousResource(
                    name=room_name,
                    resource_type=ResourceType.ROOM,
                    score=score,
                    level=suspicion_level_from_score(score),
                    reasons=reasons,
                ))

        for room_name in terminal_rooms:
            if room_name in all_rooms and room_name not in hidden_rooms:
                score = 20
                reasons = ["Room has no outgoing transitions"]
                self.database.add_suspicious(SuspiciousResource(
                    name=room_name,
                    resource_type=ResourceType.ROOM,
                    score=score,
                    level=suspicion_level_from_score(score),
                    reasons=reasons,
                ))

        for src, tgt, loc in custom_transitions:
            score = 25
            reasons = [f"Custom transition function used to go to '{tgt}' from '{src}'"]
            self.database.add_suspicious(SuspiciousResource(
                name=f"transition_{src}_to_{tgt}",
                resource_type=ResourceType.UNKNOWN,
                score=score,
                level=suspicion_level_from_score(score),
                reasons=reasons,
                details=f"Non-standard room transition: {loc.context}",
            ))

        all_room_names = set(self.index.rooms.keys())
        for room_name in all_room_names:
            result = AnalysisResult(
                resource_name=room_name,
                analyzer="transitions",
                findings=[],
            )
            if room_name in hidden_rooms:
                result.findings.append("No incoming transitions")
                result.score += 50
            if room_name in terminal_rooms:
                result.findings.append("No outgoing transitions")
                result.score += 20
            outgoing = transition_map.get(room_name, [])
            incoming = reverse_map.get(room_name, [])
            result.findings.append(f"{len(outgoing)} outgoing, {len(incoming)} incoming transitions")
            self.database.add_result("transitions", result)

        self.log(f"Found {len(all_transitions)} room transitions")
        self.log(f"Found {len(hidden_rooms)} rooms with no incoming transitions")
        self.log(f"Found {len(terminal_rooms)} rooms with no outgoing transitions")
        self.log(f"Found {len(custom_transitions)} custom transition patterns")

    def _find_transition_refs(
        self,
        code: str,
        source: SourceLocation,
        all_transitions: list[RoomTransition],
        transition_map: dict[str, list[RoomTransition]],
        reverse_map: dict[str, list[RoomTransition]],
        custom_transitions: list[tuple[str, str, SourceLocation]],
    ) -> None:
        for match in re.finditer(r"room_goto\s*\(\s*(\w+)", code):
            target = match.group(1)
            if target and target != "room":
                trans = RoomTransition(
                    source_room=source.resource_name,
                    target_room=target,
                    source_location=source,
                    transition_type="room_goto",
                )
                all_transitions.append(trans)
                transition_map.setdefault(source.resource_name, []).append(trans)
                reverse_map.setdefault(target, []).append(trans)

        if re.search(r"room_goto_next\s*\(\s*\)", code):
            trans = RoomTransition(
                source_room=source.resource_name,
                target_room="__next__",
                source_location=source,
                transition_type="room_goto_next",
            )
            all_transitions.append(trans)
            transition_map.setdefault(source.resource_name, []).append(trans)

        if re.search(r"room_goto_previous\s*\(\s*\)", code):
            trans = RoomTransition(
                source_room=source.resource_name,
                target_room="__previous__",
                source_location=source,
                transition_type="room_goto_previous",
            )
            all_transitions.append(trans)
            transition_map.setdefault(source.resource_name, []).append(trans)

        if re.search(r"room_restart\s*\(\s*\)", code):
            trans = RoomTransition(
                source_room=source.resource_name,
                target_room="__current__",
                source_location=source,
                transition_type="room_restart",
            )
            all_transitions.append(trans)
            transition_map.setdefault(source.resource_name, []).append(trans)

        for match in re.finditer(r"(\w+)\s*\(\s*\)", code):
            func_name = match.group(1)
            if func_name.startswith("goto_") or func_name.startswith("trans_"):
                custom_transitions.append((source.resource_name, func_name, source))

    def name(self) -> str:
        return "transitions"
