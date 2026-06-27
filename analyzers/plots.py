from __future__ import annotations

import re
from typing import Optional

from analyzers.base import BaseAnalyzer
from core.models import (
    AnalysisResult,
    PlotBranch,
    Reference,
    ReferenceType,
    ResourceType,
    SourceLocation,
    SuspicionLevel,
    SuspiciousResource,
    suspicion_level_from_score,
)


class PlotAnalyzer(BaseAnalyzer):
    def analyze(self) -> None:
        plot_references: dict[int, list[Reference]] = {}
        switch_statements: list[tuple[SourceLocation, list[int]]] = []
        global_plot_writes: list[Reference] = []
        global_plot_reads: list[Reference] = []

        for obj in self.index.objects.values():
            for event_key, event in obj.events.items():
                source = SourceLocation(
                    resource_name=obj.name,
                    resource_type=ResourceType.OBJECT,
                    file_path=obj.path or self.index.project_path,
                    context=f"Event: {event_key}",
                )
                self._analyze_plot_code(event.code, source, plot_references, switch_statements, global_plot_writes, global_plot_reads)

        for script in self.index.scripts.values():
            source = SourceLocation(
                resource_name=script.name,
                resource_type=ResourceType.SCRIPT,
                file_path=script.path or self.index.project_path,
            )
            self._analyze_plot_code(script.code, source, plot_references, switch_statements, global_plot_writes, global_plot_reads)

        for room in self.index.rooms.values():
            if room.creation_code:
                source = SourceLocation(
                    resource_name=room.name,
                    resource_type=ResourceType.ROOM,
                    file_path=room.path or self.index.project_path,
                )
                self._analyze_plot_code(room.creation_code, source, plot_references, switch_statements, global_plot_writes, global_plot_reads)

        all_plot_values: set[int] = set()
        for switch_source, cases in switch_statements:
            all_plot_values.update(cases)

        for idx in plot_references:
            all_plot_values.add(idx)

        for idx in global_plot_writes:
            pass

        written_states: set[int] = set()
        for ref in global_plot_writes:
            val = self._extract_assign_value(ref.source.context)
            if val is not None:
                written_states.add(val)

        branches: dict[int, PlotBranch] = {}
        for pv in sorted(all_plot_values):
            refs = plot_references.get(pv, [])
            in_switches = any(pv in cases for _, cases in switch_statements)
            is_written = pv in written_states
            branch = PlotBranch(
                plot_value=pv,
                description=f"Plot state {pv}",
                references=refs,
                reachable=in_switches or is_written or bool(refs),
                has_code=in_switches or is_written,
            )
            branches[pv] = branch

        for switch_source, cases in switch_statements:
            for i, case in enumerate(cases):
                if case in branches:
                    if i > 0:
                        branches[case].incoming_states.append(cases[i - 1])
                    if i < len(cases) - 1:
                        branches[case].outgoing_states.append(cases[i + 1])

        self.database.plot_branches = branches

        for pv, branch in branches.items():
            score = 0
            reasons = []

            if not branch.reachable:
                score += 60
                reasons.append(f"Plot state {pv} appears unreachable")
            if not branch.has_code:
                score += 40
                reasons.append(f"Plot state {pv} referenced but no code handles it")

            if branch.references:
                for ref in branch.references:
                    if ref.ref_type == ReferenceType.READ and not any(
                        r.ref_type == ReferenceType.WRITE for r in branch.references
                    ):
                        score += 20
                        reasons.append(f"Plot state {pv} read but never written")

            if score > 0:
                self.database.add_suspicious(SuspiciousResource(
                    name=f"plot_state_{pv}",
                    resource_type=ResourceType.UNKNOWN,
                    score=score,
                    level=suspicion_level_from_score(score),
                    reasons=reasons,
                    details=f"Plot branch global.plot == {pv}",
                ))

        for pv in sorted(all_plot_values):
            result = AnalysisResult(
                resource_name=f"plot_state_{pv}",
                analyzer="plots",
                findings=[],
            )
            branch = branches.get(pv)
            if branch:
                if not branch.reachable:
                    result.findings.append(f"Plot state {pv} appears unreachable")
                    result.score += 60
                if not branch.has_code:
                    result.findings.append(f"No code handles plot state {pv}")
                    result.score += 40
            self.database.add_result("plots", result)

        self.log(f"Found {len(all_plot_values)} plot states referenced")
        self.log(f"Found {len(switch_statements)} switch(global.plot) statements")
        dead_branches = [pv for pv, b in branches.items() if not b.reachable]
        self.log(f"Found {len(dead_branches)} potentially dead plot branches")

    def _analyze_plot_code(
        self,
        code: str,
        source: SourceLocation,
        plot_refs: dict[int, list[Reference]],
        switch_statements: list[tuple[SourceLocation, list[int]]],
        global_plot_writes: list[Reference],
        global_plot_reads: list[Reference],
    ) -> None:
        for match in re.finditer(r"global\.plot\s*=\s*(\d+)", code):
            val = int(match.group(1))
            ref = Reference(source=source, target=str(val), ref_type=ReferenceType.WRITE)
            global_plot_writes.append(ref)
            if val not in plot_refs:
                plot_refs[val] = []
            plot_refs[val].append(ref)

        for match in re.finditer(r"global\.plot\s*==\s*(\d+)", code):
            val = int(match.group(1))
            ref = Reference(source=source, target=str(val), ref_type=ReferenceType.READ)
            global_plot_reads.append(ref)
            if val not in plot_refs:
                plot_refs[val] = []
            plot_refs[val].append(ref)

        for match in re.finditer(r"switch\s*\(\s*global\.plot\s*\)", code):
            switch_start = match.start()
            switch_body = code[match.end():]
            brace_count = 0
            cases: list[int] = []
            in_body = False
            for line in switch_body.split("\n"):
                if "{" in line:
                    in_body = True
                if in_body:
                    case_match = re.match(r"^\s*case\s+(-?\d+)\s*:", line)
                    if case_match:
                        cases.append(int(case_match.group(1)))
                    if "}" in line and in_body:
                        break
            if cases:
                switch_statements.append((source, cases))
                for c in cases:
                    if c not in plot_refs:
                        plot_refs[c] = []
                    plot_refs[c].append(Reference(
                        source=source,
                        target=str(c),
                        ref_type=ReferenceType.READ,
                    ))

    def _extract_assign_value(self, context: str) -> Optional[int]:
        match = re.search(r"global\.plot\s*=\s*(\d+)", context)
        if match:
            return int(match.group(1))
        return None

    def name(self) -> str:
        return "plots"
