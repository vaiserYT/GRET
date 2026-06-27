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


class SpriteAnalyzer(BaseAnalyzer):
    def analyze(self) -> None:
        all_sprites = set(self.index.sprites.keys())
        used_sprites: set[str] = set()

        for obj in self.index.objects.values():
            if obj.sprite and obj.sprite in all_sprites:
                used_sprites.add(obj.sprite)
            for event_key, event in obj.events.items():
                for match in re.finditer(r"sprite_index\s*=\s*(\w+)", event.code):
                    used_sprites.add(match.group(1))
                for match in re.finditer(r"mask_index\s*=\s*(\w+)", event.code):
                    used_sprites.add(match.group(1))
                for match in re.finditer(r"draw_sprite\s*\(\s*(\w+)", event.code):
                    used_sprites.add(match.group(1))
                for match in re.finditer(r"draw_self\s*\(\)", event.code):
                    if obj.sprite:
                        used_sprites.add(obj.sprite)

        for script in self.index.scripts.values():
            for match in re.finditer(r"sprite_index\s*=\s*(\w+)", script.code):
                used_sprites.add(match.group(1))
            for match in re.finditer(r"draw_sprite\s*\(\s*(\w+)", script.code):
                used_sprites.add(match.group(1))

        dead_sprites = all_sprites - used_sprites

        self.database.dead_sprites = dead_sprites

        for sprite_name in dead_sprites:
            score = 15
            reasons = [f"Sprite '{sprite_name}' is never used by any object or draw call"]
            self.database.add_suspicious(SuspiciousResource(
                name=sprite_name,
                resource_type=ResourceType.SPRITE,
                score=score,
                level=suspicion_level_from_score(score),
                reasons=reasons,
            ))

        for sprite_name in all_sprites:
            result = AnalysisResult(
                resource_name=sprite_name,
                analyzer="sprites",
                findings=[],
            )
            if sprite_name in dead_sprites:
                result.findings.append("Never used by any object or draw call")
                result.score += 15
            self.database.add_result("sprites", result)

        self.log(f"Found {len(dead_sprites)} unused sprites out of {len(all_sprites)} total")

    def name(self) -> str:
        return "sprites"
