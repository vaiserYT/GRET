from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any, Optional

from core.models import (
    AnalysisResult,
    DialogueEntry,
    FlagInfo,
    FontInfo,
    ObjectInfo,
    PlotBranch,
    ProjectIndex,
    Reference,
    ResourceType,
    RoomInfo,
    RoomTransition,
    ScriptInfo,
    SoundInfo,
    SpriteInfo,
    SuspiciousResource,
)


class AnalysisDatabase:
    def __init__(self) -> None:
        self.index: Optional[ProjectIndex] = None
        self.suspicious: list[SuspiciousResource] = []
        self.analysis_results: dict[str, list[AnalysisResult]] = defaultdict(list)
        self._dead_objects: set[str] = set()
        self._dead_rooms: set[str] = set()
        self._dead_scripts: set[str] = set()
        self._dead_sprites: set[str] = set()
        self._dead_sounds: set[str] = set()
        self._dead_dialogues: set[str] = set()
        self._hidden_flags: dict[int, FlagInfo] = {}
        self._plot_branches: dict[int, PlotBranch] = {}
        self._orphan_resources: dict[str, ResourceType] = {}
        self._findings: list[str] = []

    def set_index(self, index: ProjectIndex) -> None:
        self.index = index

    def add_suspicious(self, resource: SuspiciousResource) -> None:
        self.suspicious.append(resource)

    def add_suspicious_list(self, resources: list[SuspiciousResource]) -> None:
        self.suspicious.extend(resources)

    def add_result(self, analyzer: str, result: AnalysisResult) -> None:
        self.analysis_results[analyzer].append(result)

    def add_finding(self, finding: str) -> None:
        self._findings.append(finding)

    @property
    def findings(self) -> list[str]:
        return self._findings

    @property
    def dead_objects(self) -> set[str]:
        return self._dead_objects

    @dead_objects.setter
    def dead_objects(self, value: set[str]) -> None:
        self._dead_objects = value

    @property
    def dead_rooms(self) -> set[str]:
        return self._dead_rooms

    @dead_rooms.setter
    def dead_rooms(self, value: set[str]) -> None:
        self._dead_rooms = value

    @property
    def dead_scripts(self) -> set[str]:
        return self._dead_scripts

    @dead_scripts.setter
    def dead_scripts(self, value: set[str]) -> None:
        self._dead_scripts = value

    @property
    def dead_sprites(self) -> set[str]:
        return self._dead_sprites

    @dead_sprites.setter
    def dead_sprites(self, value: set[str]) -> None:
        self._dead_sprites = value

    @property
    def dead_sounds(self) -> set[str]:
        return self._dead_sounds

    @dead_sounds.setter
    def dead_sounds(self, value: set[str]) -> None:
        self._dead_sounds = value

    @property
    def dead_dialogues(self) -> set[str]:
        return self._dead_dialogues

    @dead_dialogues.setter
    def dead_dialogues(self, value: set[str]) -> None:
        self._dead_dialogues = value

    @property
    def hidden_flags(self) -> dict[int, FlagInfo]:
        return self._hidden_flags

    @hidden_flags.setter
    def hidden_flags(self, value: dict[int, FlagInfo]) -> None:
        self._hidden_flags = value

    @property
    def plot_branches(self) -> dict[int, PlotBranch]:
        return self._plot_branches

    @plot_branches.setter
    def plot_branches(self, value: dict[int, PlotBranch]) -> None:
        self._plot_branches = value

    @property
    def orphan_resources(self) -> dict[str, ResourceType]:
        return self._orphan_resources

    @orphan_resources.setter
    def orphan_resources(self, value: dict[str, ResourceType]) -> None:
        self._orphan_resources = value

    def flag_summary(self) -> dict[str, Any]:
        if not self.index:
            return {}
        never_set = [f for f in self.index.flags.values() if f.never_set]
        never_read = [f for f in self.index.flags.values() if f.never_read]
        read_before_write_flags = [f for f in self.index.flags.values() if f.read_before_write]
        write_without_read_flags = [f for f in self.index.flags.values() if f.write_without_read]

        return {
            "total_flags": len(self.index.flags),
            "never_set": len(never_set),
            "never_read": len(never_read),
            "read_before_write": len(read_before_write_flags),
            "write_without_read": len(write_without_read_flags),
            "never_set_detail": [f.index for f in never_set[:100]],
            "never_read_detail": [f.index for f in never_read[:100]],
            "write_without_read_detail": [f.index for f in write_without_read_flags[:100]],
        }

    def top_suspicious(self, limit: int = 100) -> list[SuspiciousResource]:
        sorted_list = sorted(self.suspicious, key=lambda r: r.score, reverse=True)
        return sorted_list[:limit]

    def summary(self) -> dict[str, Any]:
        return {
            "total_objects": len(self.index.objects) if self.index else 0,
            "total_rooms": len(self.index.rooms) if self.index else 0,
            "total_scripts": len(self.index.scripts) if self.index else 0,
            "total_sprites": len(self.index.sprites) if self.index else 0,
            "total_sounds": len(self.index.sounds) if self.index else 0,
            "total_dialogues": len(self.index.dialogues) if self.index else 0,
            "total_flags": len(self.index.flags) if self.index else 0,
            "dead_objects": len(self._dead_objects),
            "dead_rooms": len(self._dead_rooms),
            "dead_scripts": len(self._dead_scripts),
            "dead_sprites": len(self._dead_sprites),
            "dead_sounds": len(self._dead_sounds),
            "dead_dialogues": len(self._dead_dialogues),
            "suspicious_total": len(self.suspicious),
            "findings_total": len(self._findings),
            "plot_branches": len(self._plot_branches),
            "orphan_resources": len(self._orphan_resources),
        }

    def get_dead_summary(self) -> dict[str, list[str]]:
        return {
            "objects": sorted(self._dead_objects),
            "rooms": sorted(self._dead_rooms),
            "scripts": sorted(self._dead_scripts),
            "sprites": sorted(self._dead_sprites),
            "sounds": sorted(self._dead_sounds),
            "dialogues": sorted(self._dead_dialogues),
        }
