from __future__ import annotations

import re
from collections import defaultdict

from analyzers.base import BaseAnalyzer
from core.models import (
    AnalysisResult,
    Reference,
    ReferenceType,
    ResourceType,
    SourceLocation,
    SuspicionLevel,
    SuspiciousResource,
    suspicion_level_from_score,
)


class CallGraphAnalyzer(BaseAnalyzer):
    def analyze(self) -> None:
        call_targets: dict[str, list[Reference]] = defaultdict(list)

        for obj in self.index.objects.values():
            for event_key, event in obj.events.items():
                source = SourceLocation(
                    resource_name=obj.name,
                    resource_type=ResourceType.OBJECT,
                    file_path=obj.path or self.index.project_path,
                    context=f"Event: {event_key}",
                )
                self._extract_calls(event.code, source, call_targets)

        for script in self.index.scripts.values():
            source = SourceLocation(
                resource_name=script.name,
                resource_type=ResourceType.SCRIPT,
                file_path=script.path or self.index.project_path,
            )
            self._extract_calls(script.code, source, call_targets)

        for room in self.index.rooms.values():
            if room.creation_code:
                source = SourceLocation(
                    resource_name=room.name,
                    resource_type=ResourceType.ROOM,
                    file_path=room.path or self.index.project_path,
                )
                self._extract_calls(room.creation_code, source, call_targets)

        self.index.call_targets = dict(call_targets)

        callers: dict[str, set[str]] = defaultdict(set)
        callees: dict[str, set[str]] = defaultdict(set)
        for target, refs in call_targets.items():
            for ref in refs:
                caller = ref.source.resource_name
                callees[caller].add(target)
                callers[target].add(caller)

        recursive_chains: list[tuple[str, str]] = []
        for caller, targets in callees.items():
            for target in targets:
                if target in callees and caller in callees[target]:
                    recursive_chains.append((caller, target))

        leaf_nodes: list[str] = []
        for caller in callees:
            if caller not in callers and not any(
                obj.name == caller for obj in self.index.objects.values()
            ):
                leaf_nodes.append(caller)

        high_freq_callees = sorted(
            [(t, len(refs)) for t, refs in call_targets.items()],
            key=lambda x: x[1],
            reverse=True,
        )[:20]

        for caller, target in recursive_chains:
            score = 30
            reasons = [f"Mutual recursion between {caller} and {target}"]
            self.database.add_suspicious(SuspiciousResource(
                name=f"recursion_{caller}_{target}",
                resource_type=ResourceType.UNKNOWN,
                score=score,
                level=suspicion_level_from_score(score),
                reasons=reasons,
            ))

        for target, refs in call_targets.items():
            if target.startswith("scr_") and target not in self.index.scripts:
                score = 40
                reasons = [f"'{target}' is called but does not exist as a script resource"]
                self.database.add_suspicious(SuspiciousResource(
                    name=target,
                    resource_type=ResourceType.SCRIPT,
                    score=score,
                    level=suspicion_level_from_score(score),
                    reasons=reasons,
                ))

        for target, refs in call_targets.items():
            if target.startswith("obj_") and target not in self.index.objects:
                score = 25
                reasons = [f"'{target}' is referenced but does not exist as an object resource"]
                self.database.add_suspicious(SuspiciousResource(
                    name=target,
                    resource_type=ResourceType.OBJECT,
                    score=score,
                    level=suspicion_level_from_score(score),
                    reasons=reasons,
                ))

        for caller_node in leaf_nodes:
            score = 10
            reasons = [f"'{caller_node}' has no callers (orphan caller)"]
            self.database.add_suspicious(SuspiciousResource(
                name=caller_node,
                resource_type=ResourceType.UNKNOWN,
                score=score,
                level=suspicion_level_from_score(score),
                reasons=reasons,
            ))

        self.log(f"Built call graph with {len(call_targets)} targets")
        self.log(f"Found {len(recursive_chains)} recursive call pairs")
        self.log(f"Top called: {high_freq_callees[:5]}")

    def _extract_calls(self, code: str, source: SourceLocation, call_targets: dict[str, list[Reference]]) -> None:
        for match in re.finditer(r"(scr_\w+)\s*\(", code):
            target = match.group(1)
            ref = Reference(source=source, target=target, ref_type=ReferenceType.CALL)
            call_targets[target].append(ref)

        for match in re.finditer(r"script_execute\s*\(\s*(\w+)", code):
            target = match.group(1)
            ref = Reference(source=source, target=target, ref_type=ReferenceType.CALL)
            call_targets[target].append(ref)

        for match in re.finditer(r"method\s*\(\s*(\w+)", code):
            target = match.group(1)
            ref = Reference(source=source, target=target, ref_type=ReferenceType.CALL)
            call_targets[target].append(ref)

        for match in re.finditer(r"instance_create[_\w]*\s*\([^,]+,[^,]+,\s*(\w+)\s*\)", code):
            target = match.group(1)
            if target and not target[0].isdigit():
                ref = Reference(source=source, target=target, ref_type=ReferenceType.DYNAMIC)
                call_targets[target].append(ref)

        for match in re.finditer(r"with\s*\(\s*(\w+)", code):
            target = match.group(1)
            if target and target not in ("self", "other", "all", "noone"):
                ref = Reference(source=source, target=target, ref_type=ReferenceType.DYNAMIC)
                call_targets[target].append(ref)

        for match in re.finditer(r"room_goto\s*\(\s*(\w+)", code):
            target = match.group(1)
            if target:
                ref = Reference(source=source, target=target, ref_type=ReferenceType.TRANSITION)
                call_targets[target].append(ref)

        for match in re.finditer(r"audio_play_sound\s*\(\s*(\w+)", code):
            target = match.group(1)
            ref = Reference(source=source, target=target, ref_type=ReferenceType.REFERENCE)
            call_targets[target].append(ref)

        for match in re.finditer(r"(\w+)\.object_index\b", code):
            target = match.group(1)
            if target not in ("self", "other", "all", "noone", "instance"):
                ref = Reference(source=source, target=target, ref_type=ReferenceType.REFERENCE)
                call_targets[target].append(ref)

    def name(self) -> str:
        return "callgraph"
