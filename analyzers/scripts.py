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


class ScriptAnalyzer(BaseAnalyzer):
    def analyze(self) -> None:
        all_scripts = set(self.index.scripts.keys())
        called_scripts: set[str] = set()
        referenced_scripts: set[str] = set()
        anonymous_scripts: set[str] = set()

        for script_name, script in self.index.scripts.items():
            if script.is_anonymous:
                anonymous_scripts.add(script_name)

            for match in re.finditer(r"(\w+)\s*\(", script.code):
                func_name = match.group(1)
                if func_name.startswith("scr_") and func_name in self.index.scripts:
                    called_scripts.add(func_name)

        for target, refs in self.index.call_targets.items():
            for ref in refs:
                if ref.ref_type.name in ("CALL", "REFERENCE") and target in self.index.scripts:
                    called_scripts.add(target)
                    referenced_scripts.add(target)

        for obj in self.index.objects.values():
            for event_key, event in obj.events.items():
                for match in re.finditer(r"(scr_\w+)\s*\(", event.code):
                    called_scripts.add(match.group(1))
                for match in re.finditer(r"script_execute\s*\(\s*(\w+)", event.code):
                    called_scripts.add(match.group(1))
                for match in re.finditer(r"method\s*\(\s*(\w+)", event.code):
                    called_scripts.add(match.group(1))

        for room in self.index.rooms.values():
            if room.creation_code:
                for match in re.finditer(r"(scr_\w+)\s*\(", room.creation_code):
                    called_scripts.add(match.group(1))

        called_scripts.discard("")

        dead_scripts = all_scripts - called_scripts - anonymous_scripts

        self.database.dead_scripts = dead_scripts

        for script_name in dead_scripts:
            script = self.index.scripts[script_name]
            score = 45
            reasons = ["Script never called from any code path"]

            if script_name in referenced_scripts:
                score -= 10
                reasons.append("Referenced but not called")
            else:
                score += 15
                reasons.append("Not referenced anywhere")

            self.database.add_suspicious(SuspiciousResource(
                name=script_name,
                resource_type=ResourceType.SCRIPT,
                score=score,
                level=suspicion_level_from_score(score),
                reasons=reasons,
                details=f"Script {script_name} exists but is never executed",
            ))

        for script_name in self.index.scripts:
            result = AnalysisResult(
                resource_name=script_name,
                analyzer="scripts",
                findings=[],
            )
            if script_name in dead_scripts:
                result.findings.append("Never called")
                result.score += 45
            self.database.add_result("scripts", result)

        self.log(f"Found {len(dead_scripts)} dead scripts out of {len(all_scripts)} total")
        self.log(f"Found {len(anonymous_scripts)} anonymous scripts")

    def name(self) -> str:
        return "scripts"
