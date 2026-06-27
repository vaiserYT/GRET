from __future__ import annotations

from typing import Set

from analyzers.base import BaseAnalyzer
from core.models import (
    AnalysisResult,
    ObjectInfo,
    Reference,
    ReferenceType,
    ResourceType,
    SourceLocation,
    SuspicionLevel,
    SuspiciousResource,
    suspicion_level_from_score,
)


class ObjectAnalyzer(BaseAnalyzer):
    def analyze(self) -> None:
        placed_objects: set[str] = set()
        created_objects: set[str] = set()
        referenced_objects: set[str] = set()
        parent_objects: set[str] = set()
        all_objects = set(self.index.objects.keys())

        for room in self.index.rooms.values():
            for inst in room.instances:
                placed_objects.add(inst.object_name)

        for obj in self.index.objects.values():
            if obj.parent and obj.parent in self.index.objects:
                parent_objects.add(obj.parent)

            for event_key, event in obj.events.items():
                if "instance_create" in event.code or "instance_create_layer" in event.code:
                    import re
                    for match in re.findall(r"instance_create[_\w]*\s*\([^,]+,[^,]+,\s*(\w+)\s*\)", event.code):
                        created_objects.add(match)
                    for match in re.findall(r"instance_create_layer\s*\([^,]+,[^,]+,[^,]+,\s*(\w+)\s*\)", event.code):
                        created_objects.add(match)

        for target, refs in self.index.call_targets.items():
            for ref in refs:
                if ref.source.resource_type == ResourceType.OBJECT and ref.ref_type in (
                    ReferenceType.DYNAMIC, ReferenceType.REFERENCE
                ):
                    referenced_objects.add(target)

        for script in self.index.scripts.values():
            import re
            for match in re.findall(r"instance_create[_\w]*\s*\([^,]+,[^,]+,\s*(\w+)\s*\)", script.code):
                created_objects.add(match)

        never_instantiated = all_objects - placed_objects - created_objects - parent_objects
        never_referenced = all_objects - placed_objects - created_objects - referenced_objects - parent_objects
        placed_but_never_created = placed_objects - created_objects

        self.database.dead_objects = never_instantiated

        for obj_name in never_instantiated:
            obj = self.index.objects[obj_name]
            score = 0
            reasons = []

            if obj.events:
                score += 40
                reasons.append("Has events but never instantiated")

            if any("step" in k.lower() for k in obj.events):
                score += 20
                reasons.append("Has Step event but never instantiated")

            if any("draw" in k.lower() for k in obj.events):
                score += 15
                reasons.append("Has Draw event but never instantiated")

            if any("alarm" in k.lower() for k in obj.events):
                score += 10
                reasons.append("Has Alarm event but never instantiated")

            if obj.sprite:
                score += 10
                reasons.append(f"Has sprite ({obj.sprite}) but never instantiated")

            if obj_name not in referenced_objects and obj_name not in placed_objects:
                score += 20
                reasons.append("Not placed in any room, not created dynamically, not referenced")

            self.database.add_suspicious(SuspiciousResource(
                name=obj_name,
                resource_type=ResourceType.OBJECT,
                score=score,
                level=suspicion_level_from_score(score),
                reasons=reasons,
                details=f"Object {obj_name} exists in resources but is never instantiated",
            ))

        for obj_name in never_referenced - never_instantiated:
            score = 15
            reasons = ["Object placed but never dynamically created or otherwise referenced"]
            self.database.add_suspicious(SuspiciousResource(
                name=obj_name,
                resource_type=ResourceType.OBJECT,
                score=score,
                level=suspicion_level_from_score(score),
                reasons=reasons,
            ))

        for obj_name, obj in self.index.objects.items():
            if not obj.events and obj_name not in placed_objects:
                score = 5
                self.database.add_suspicious(SuspiciousResource(
                    name=obj_name,
                    resource_type=ResourceType.OBJECT,
                    score=score,
                    level=suspicion_level_from_score(score),
                    reasons=["Object has no events and is not placed in any room"],
                ))

        for obj_name in self.index.objects:
            result = AnalysisResult(
                resource_name=obj_name,
                analyzer="objects",
                findings=[],
            )
            if obj_name in never_instantiated:
                result.findings.append("Never instantiated")
                result.score += 50
            if obj_name in never_referenced:
                result.findings.append("Never referenced")
                result.score += 30
            if obj_name in placed_but_never_created:
                result.findings.append("Placed in room but never dynamically created")
                result.score += 10
            self.database.add_result("objects", result)

        self.log(f"Found {len(never_instantiated)} never-instantiated objects")
        self.log(f"Found {len(never_referenced)} never-referenced objects")

    def name(self) -> str:
        return "objects"
