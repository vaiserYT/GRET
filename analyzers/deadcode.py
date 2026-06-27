from __future__ import annotations

import re

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


class DeadCodeAnalyzer(BaseAnalyzer):
    AFTER_GOTO_PATTERNS = [
        re.compile(r"exit\s*\(\s*\)"),
        re.compile(r"return\b(?!\s*\()"),
        re.compile(r"room_goto\s*\("),
        re.compile(r"room_restart\s*\(\s*\)"),
        re.compile(r"game_end\s*\(\s*\)"),
        re.compile(r"game_restart\s*\(\s*\)"),
        re.compile(r"show_debug_message\s*\("),
        re.compile(r"show_error\s*\("),
    ]

    UNUSED_VARIABLE_PATTERN = re.compile(r"var\s+(\w+)\s*=")
    UNUSED_GLOBAL_PATTERN = re.compile(r"globalvar\s+(\w+)")

    def analyze(self) -> None:
        for obj in self.index.objects.values():
            for event_key, event in obj.events.items():
                source = SourceLocation(
                    resource_name=obj.name,
                    resource_type=ResourceType.OBJECT,
                    file_path=obj.path or self.index.project_path,
                    context=f"Event: {event_key}",
                )
                self._analyze_code_for_dead(event.code, source)

        for script in self.index.scripts.values():
            source = SourceLocation(
                resource_name=script.name,
                resource_type=ResourceType.SCRIPT,
                file_path=script.path or self.index.project_path,
            )
            self._analyze_code_for_dead(script.code, source)

        for room in self.index.rooms.values():
            if room.creation_code:
                source = SourceLocation(
                    resource_name=room.name,
                    resource_type=ResourceType.ROOM,
                    file_path=room.path or self.index.project_path,
                )
                self._analyze_code_for_dead(room.creation_code, source)

        unused_builtins: list[str] = []
        for script_name in self.index.scripts:
            if script_name.startswith("gml_") and script_name not in self.index.call_targets:
                unused_builtins.append(script_name)

        for name in unused_builtins[:50]:
            score = 20
            reasons = [f"Anonymous/builtin script '{name}' has no callers"]
            self.database.add_suspicious(SuspiciousResource(
                name=name,
                resource_type=ResourceType.SCRIPT,
                score=score,
                level=suspicion_level_from_score(score),
                reasons=reasons,
            ))

        self.log("Completed dead code analysis")

    def _analyze_code_for_dead(self, code: str, source: SourceLocation) -> None:
        lines = code.split("\n")
        dead_after_goto: list[int] = []

        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                continue

            for pattern in self.AFTER_GOTO_PATTERNS:
                if pattern.search(stripped):
                    next_line = i + 1
                    while next_line < len(lines):
                        next_stripped = lines[next_line].strip()
                        if next_stripped and not next_stripped.startswith("//"):
                            if next_stripped != "}":
                                dead_after_goto.append(next_line + 1)
                            break
                        next_line += 1
                    break

        if len(dead_after_goto) > 0:
            score = len(dead_after_goto) * 5
            reasons = [
                f"Found {len(dead_after_goto)} lines of dead code after return/goto at {source.resource_name}"
            ]
            self.database.add_suspicious(SuspiciousResource(
                name=f"deadcode_{source.resource_name}_{source.context[:20]}",
                resource_type=ResourceType.UNKNOWN,
                score=score,
                level=suspicion_level_from_score(score),
                reasons=reasons,
                details=f"Lines: {dead_after_goto[:10]}",
            ))

        unreachable_blocks = self._find_unreachable_blocks(code)
        if unreachable_blocks:
            for block_type, block_line in unreachable_blocks:
                score = 30
                reasons = [f"Unreachable {block_type} block at line ~{block_line}"]
                self.database.add_suspicious(SuspiciousResource(
                    name=f"unreachable_{source.resource_name}_{block_type}",
                    resource_type=ResourceType.UNKNOWN,
                    score=score,
                    level=suspicion_level_from_score(score),
                    reasons=reasons,
                ))

        never_true_conditions = self._find_never_true_conditions(code)
        if never_true_conditions:
            for cond, cond_line in never_true_conditions[:5]:
                score = 35
                reasons = [f"Condition likely never true: '{cond}' at line ~{cond_line}"]
                self.database.add_suspicious(SuspiciousResource(
                    name=f"never_true_{source.resource_name}",
                    resource_type=ResourceType.UNKNOWN,
                    score=score,
                    level=suspicion_level_from_score(score),
                    reasons=reasons,
                ))

    def _find_unreachable_blocks(self, code: str) -> list[tuple[str, int]]:
        blocks: list[tuple[str, int]] = []
        lines = code.split("\n")
        i = 0
        while i < len(lines):
            line = lines[i]
            has_return = bool(re.search(r"\breturn\b", line)) and not re.search(r'return\s*"', line)
            has_goto = "room_goto" in line or "room_restart" in line or "game_end" in line

            if has_return or has_goto:
                j = i + 1
                while j < len(lines):
                    next_stripped = lines[j].strip()
                    if not next_stripped or next_stripped.startswith("//"):
                        j += 1
                        continue
                    if "if" in next_stripped or "switch" in next_stripped or "{" in next_stripped:
                        j += 1
                        continue
                    if next_stripped.startswith("}"):
                        break
                    blocks.append(("code after return/goto", j))
                    break
            i += 1
        return blocks

    def _find_never_true_conditions(self, code: str) -> list[tuple[str, int]]:
        conditions: list[tuple[str, int]] = []
        lines = code.split("\n")

        for i, line in enumerate(lines):
            stripped = line.strip()

            if_match = re.match(r"^\s*if\s*\(\s*(.+?)\s*\)", stripped)
            if if_match:
                cond = if_match.group(1)

                if re.match(r"^\d+\s*==\s*\d+$", cond) and not re.match(r"^\d+\s*!=\s*\d+$", cond):
                    nums = re.findall(r"\d+", cond)
                    if len(nums) == 2 and nums[0] != nums[1]:
                        conditions.append((f"if({cond})", i + 1))

                never_true_patterns = [
                    r"global\.flag\[\d+\]\s*==\s*-1",
                    r"global\.flag\[\d+\]\s*<\s*0",
                    r"global\.plot\s*==\s*-1",
                    r"false\s*(?:&&|\|\|)\s*true",
                    r"true\s*&&\s*false",
                ]
                for pat in never_true_patterns:
                    if re.search(pat, cond):
                        conditions.append((cond, i + 1))
                        break

        return conditions

    def name(self) -> str:
        return "deadcode"
