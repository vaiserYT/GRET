from __future__ import annotations

import re

from analyzers.base import BaseAnalyzer
from core.models import (
    AnalysisResult,
    DialogueEntry,
    Reference,
    ReferenceType,
    ResourceType,
    SourceLocation,
    SuspicionLevel,
    SuspiciousResource,
    suspicion_level_from_score,
)


class DialogueAnalyzer(BaseAnalyzer):
    def analyze(self) -> None:
        all_text_ids = set(self.index.dialogues.keys())
        referenced_text_ids: set[str] = set()

        for obj in self.index.objects.values():
            for event_key, event in obj.events.items():
                source = SourceLocation(
                    resource_name=obj.name,
                    resource_type=ResourceType.OBJECT,
                    file_path=obj.path or self.index.project_path,
                    context=f"Event: {event_key}",
                )
                found = self._find_dialogue_refs(event.code, source)
                referenced_text_ids.update(found)

        for script in self.index.scripts.values():
            source = SourceLocation(
                resource_name=script.name,
                resource_type=ResourceType.SCRIPT,
                file_path=script.path or self.index.project_path,
            )
            found = self._find_dialogue_refs(script.code, source)
            referenced_text_ids.update(found)

        for room in self.index.rooms.values():
            if room.creation_code:
                source = SourceLocation(
                    resource_name=room.name,
                    resource_type=ResourceType.ROOM,
                    file_path=room.path or self.index.project_path,
                )
                found = self._find_dialogue_refs(room.creation_code, source)
                referenced_text_ids.update(found)

        unused_text = all_text_ids - referenced_text_ids

        self.database.dead_dialogues = unused_text

        for text_id in unused_text:
            entry = self.index.dialogues[text_id]
            text_preview = entry.text[:80] + "..." if len(entry.text) > 80 else entry.text
            score = 35
            reasons = [f"Dialogue '{text_id}' has zero references in code"]

            self.database.add_suspicious(SuspiciousResource(
                name=text_id,
                resource_type=ResourceType.UNKNOWN,
                score=score,
                level=suspicion_level_from_score(score),
                reasons=reasons,
                details=f"Unused dialogue: \"{text_preview}\"",
            ))

        for text_id in referenced_text_ids:
            if text_id in self.index.dialogues:
                entry = self.index.dialogues[text_id]
                entry.references = [
                    Reference(
                        source=SourceLocation(
                            resource_name="multiple",
                            resource_type=ResourceType.UNKNOWN,
                            file_path=self.index.project_path,
                        ),
                        target=text_id,
                        ref_type=ReferenceType.REFERENCE,
                    )
                ]

        for text_id in all_text_ids:
            result = AnalysisResult(
                resource_name=text_id,
                analyzer="dialogues",
                findings=[],
            )
            if text_id in unused_text:
                entry = self.index.dialogues[text_id]
                text_preview = entry.text[:60]
                result.findings.append(f"Unused dialogue: \"{text_preview}\"")
                result.score += 35
            self.database.add_result("dialogues", result)

        self.log(f"Found {len(unused_text)} unused dialogue entries out of {len(all_text_ids)} total")

    def _find_dialogue_refs(self, code: str, source: SourceLocation) -> set[str]:
        found: set[str] = set()

        for match in re.finditer(r'scr_Dialogue(?:_String|_Name)?\s*\(\s*"((?:[^"\\]|\\.)*)"', code):
            found.add(match.group(1))

        for match in re.finditer(r'scr_Dialogue\s*\(\s*(\w+)', code):
            text_id = match.group(1)
            if text_id in self.index.dialogues or text_id.startswith(("msg_", "str_", "txt_", "#")):
                found.add(text_id)

        for match in re.finditer(r'"((?:msg_|str_|txt_|#)\w+)"', code):
            found.add(match.group(1))

        for match in re.finditer(r'show_message\s*\(\s*"((?:[^"\\]|\\.)*)"', code):
            text_id = match.group(1)
            hashed = f"msg_{hash(text_id) & 0xFFFFFFFF:08x}"
            found.add(hashed)

        return found

    def name(self) -> str:
        return "dialogues"
