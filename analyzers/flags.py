from __future__ import annotations

import re
from typing import Optional

from analyzers.base import BaseAnalyzer
from core.models import (
    AnalysisResult,
    FlagInfo,
    Reference,
    ReferenceType,
    ResourceType,
    SourceLocation,
    SuspicionLevel,
    SuspiciousResource,
    suspicion_level_from_score,
)


class FlagAnalyzer(BaseAnalyzer):
    def analyze(self) -> None:
        all_flag_indices: set[int] = set()
        max_flag = 5000

        for obj in self.index.objects.values():
            for event_key, event in obj.events.items():
                source = SourceLocation(
                    resource_name=obj.name,
                    resource_type=ResourceType.OBJECT,
                    file_path=obj.path or self.index.project_path,
                    context=f"Event: {event_key}",
                )
                self._extract_flags_from_code(event.code, source, all_flag_indices)

        for script in self.index.scripts.values():
            source = SourceLocation(
                resource_name=script.name,
                resource_type=ResourceType.SCRIPT,
                file_path=script.path or self.index.project_path,
            )
            self._extract_flags_from_code(script.code, source, all_flag_indices)

        for room in self.index.rooms.values():
            if room.creation_code:
                source = SourceLocation(
                    resource_name=room.name,
                    resource_type=ResourceType.ROOM,
                    file_path=room.path or self.index.project_path,
                )
                self._extract_flags_from_code(room.creation_code, source, all_flag_indices)

        never_set: list[int] = []
        never_read: list[int] = []
        read_before_write_list: list[int] = []
        write_without_read_list: list[int] = []
        hidden_flags: dict[int, FlagInfo] = {}

        for idx in sorted(all_flag_indices):
            flag = self.index.flags.get(idx, FlagInfo(index=idx))
            self.index.flags[idx] = flag

            if flag.never_set:
                never_set.append(idx)
                hidden_flags[idx] = flag

                score = 50
                reasons = [f"Flag {idx} is never set"]
                if flag.never_read:
                    score += 20
                    reasons.append("Flag is also never read (completely dead)")
                self.database.add_suspicious(SuspiciousResource(
                    name=f"flag[{idx}]",
                    resource_type=ResourceType.UNKNOWN,
                    score=score,
                    level=suspicion_level_from_score(score),
                    reasons=reasons,
                    details=f"Global flag {idx} is referenced but never assigned a value",
                ))

            if flag.never_read:
                never_read.append(idx)
                if not flag.never_set:
                    score = 30
                    self.database.add_suspicious(SuspiciousResource(
                        name=f"flag[{idx}]",
                        resource_type=ResourceType.UNKNOWN,
                        score=score,
                        level=suspicion_level_from_score(score),
                        reasons=[f"Flag {idx} is set but never read"],
                    ))

            if flag.read_before_write:
                read_before_write_list.append(idx)
                score = 25
                self.database.add_suspicious(SuspiciousResource(
                    name=f"flag[{idx}]",
                    resource_type=ResourceType.UNKNOWN,
                    score=score,
                    level=suspicion_level_from_score(score),
                    reasons=[f"Flag {idx} is read before being written"],
                ))

            if flag.write_without_read:
                write_without_read_list.append(idx)

        self.database.hidden_flags = hidden_flags

        never_set_strs = set(f"flag[{i}]" for i in never_set)
        for idx in sorted(all_flag_indices):
            result = AnalysisResult(
                resource_name=f"flag[{idx}]",
                analyzer="flags",
                findings=[],
            )
            flag = self.index.flags[idx]
            if flag.never_set:
                result.findings.append("Never set")
                result.score += 50
            if flag.never_read:
                result.findings.append("Never read")
                result.score += 30
            if flag.read_before_write:
                result.findings.append("Read before write")
                result.score += 20
            self.database.add_result("flags", result)

        self.log(f"Found {len(all_flag_indices)} total flags referenced")
        self.log(f"Found {len(never_set)} flags never set")
        self.log(f"Found {len(never_read)} flags never read")
        self.log(f"Found {len(read_before_write_list)} flags read before write")

    def _extract_flags_from_code(self, code: str, source: SourceLocation, all_flags: set[int]) -> None:
        for match in re.finditer(r"global\.flag\s*\[\s*(\d+)\s*\]", code):
            idx = int(match.group(1))
            all_flags.add(idx)
            line_start = code.rfind("\n", 0, match.start()) + 1 if code.rfind("\n", 0, match.start()) >= 0 else 0
            line_end = code.find("\n", match.end())
            if line_end == -1:
                line_end = len(code)
            line_text = code[line_start:line_end].strip()

            is_set = False
            before_flag = code[max(0, match.start() - 20) : match.start()].strip()
            after_flag = code[match.end() : min(len(code), match.end() + 20)].strip()

            if after_flag.startswith("=") and not after_flag.startswith("=="):
                is_set = True
            elif after_flag.startswith("+=") or after_flag.startswith("-=") or after_flag.startswith("*=") or after_flag.startswith("/="):
                is_set = True
            elif after_flag.startswith("++"):
                is_set = True
            elif before_flag.endswith("=") and not before_flag.endswith("=="):
                is_set = True

            ref_type = ReferenceType.WRITE if is_set else ReferenceType.READ
            ref = Reference(source=source, target=str(idx), ref_type=ref_type)
            if idx not in self.index.flags:
                self.index.flags[idx] = FlagInfo(index=idx)
            if ref_type == ReferenceType.WRITE:
                self.index.flags[idx].sets.append(ref)
            else:
                self.index.flags[idx].gets.append(ref)

        for match in re.finditer(r"scr_flag_get\s*\(\s*(\d+)", code):
            idx = int(match.group(1))
            all_flags.add(idx)
            ref = Reference(source=source, target=str(idx), ref_type=ReferenceType.READ)
            if idx not in self.index.flags:
                self.index.flags[idx] = FlagInfo(index=idx)
            self.index.flags[idx].gets.append(ref)

        for match in re.finditer(r"scr_flag_set\s*\(\s*(\d+)\s*,", code):
            idx = int(match.group(1))
            all_flags.add(idx)
            ref = Reference(source=source, target=str(idx), ref_type=ReferenceType.WRITE)
            if idx not in self.index.flags:
                self.index.flags[idx] = FlagInfo(index=idx)
            self.index.flags[idx].sets.append(ref)

        in_switch = False
        for line in code.split("\n"):
            if re.search(r"switch\s*\(\s*global\.plot\s*\)", line):
                in_switch = True
                continue
            if in_switch:
                case_match = re.match(r"^\s*case\s+(\d+)\s*:", line)
                if case_match:
                    idx = int(case_match.group(1))
                    if idx not in self.index.flags:
                        self.index.flags[idx] = FlagInfo(index=idx)

    def name(self) -> str:
        return "flags"
