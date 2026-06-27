from __future__ import annotations

import re

from analyzers.base import BaseAnalyzer
from core.models import (
    AnalysisResult,
    ResourceType,
    SuspicionLevel,
    SuspiciousResource,
    suspicion_level_from_score,
)


class SoundAnalyzer(BaseAnalyzer):
    def analyze(self) -> None:
        all_sounds = set(self.index.sounds.keys())
        played_sounds: set[str] = set()

        for obj in self.index.objects.values():
            for event_key, event in obj.events.items():
                for match in re.finditer(r"audio_play_sound\s*\(\s*(\w+)", event.code):
                    played_sounds.add(match.group(1))
                for match in re.finditer(r"audio_play_sound_at\s*\(\s*(\w+)", event.code):
                    played_sounds.add(match.group(1))
                for match in re.finditer(r"sound_play\s*\(\s*(\w+)", event.code):
                    played_sounds.add(match.group(1))

        for script in self.index.scripts.values():
            for match in re.finditer(r"audio_play_sound\s*\(\s*(\w+)", script.code):
                played_sounds.add(match.group(1))
            for match in re.finditer(r"audio_play_sound_at\s*\(\s*(\w+)", script.code):
                played_sounds.add(match.group(1))
            for match in re.finditer(r"sound_play\s*\(\s*(\w+)", script.code):
                played_sounds.add(match.group(1))

        dead_sounds = all_sounds - played_sounds

        self.database.dead_sounds = dead_sounds

        for sound_name in dead_sounds:
            score = 15
            reasons = [f"Sound '{sound_name}' is never played via audio_play_sound or sound_play"]
            self.database.add_suspicious(SuspiciousResource(
                name=sound_name,
                resource_type=ResourceType.SOUND,
                score=score,
                level=suspicion_level_from_score(score),
                reasons=reasons,
            ))

        for sound_name in all_sounds:
            result = AnalysisResult(
                resource_name=sound_name,
                analyzer="sounds",
                findings=[],
            )
            if sound_name in dead_sounds:
                result.findings.append("Never played")
                result.score += 15
            self.database.add_result("sounds", result)

        self.log(f"Found {len(dead_sounds)} unused sounds out of {len(all_sounds)} total")

    def name(self) -> str:
        return "sounds"
