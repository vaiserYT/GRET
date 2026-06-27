from __future__ import annotations

from pathlib import Path

from core.database import AnalysisDatabase
from core.graph import DependencyGraph
from core.models import ProjectIndex


class MarkdownReportGenerator:
    def __init__(self, index: ProjectIndex, graph: DependencyGraph, database: AnalysisDatabase) -> None:
        self.index = index
        self.graph = graph
        self.database = database

    def generate(self, output_path: Path, top_limit: int = 100) -> Path:
        output_path = output_path.resolve()
        if output_path.suffix == "":
            output_path = output_path / "report.md"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        lines: list[str] = []
        lines.append(f"# GameMaker Static Analysis Report: {self.index.game_name}")
        lines.append("")
        lines.append(f"Generated from: `{self.index.project_path}`")
        lines.append("")

        summary = self.database.summary()
        flag_summary = self.database.flag_summary()
        dead = self.database.get_dead_summary()

        lines.append("## Summary")
        lines.append("")
        lines.append("| Resource | Count |")
        lines.append("|----------|-------|")
        lines.append(f"| Objects | {self.index.total_objects()} |")
        lines.append(f"| Rooms | {self.index.total_rooms()} |")
        lines.append(f"| Scripts | {self.index.total_scripts()} |")
        lines.append(f"| Sprites | {self.index.total_sprites()} |")
        lines.append(f"| Sounds | {self.index.total_sounds()} |")
        lines.append(f"| Dialogues | {len(self.index.dialogues)} |")
        lines.append(f"| Flags | {len(self.index.flags)} |")
        lines.append("")

        lines.append("### Dead Resources")
        lines.append("")
        for key, label in [
            ("objects", "Dead Objects"),
            ("rooms", "Dead Rooms"),
            ("scripts", "Dead Scripts"),
            ("sprites", "Dead Sprites"),
            ("sounds", "Dead Sounds"),
            ("dialogues", "Dead Dialogues"),
        ]:
            items = dead.get(key, [])
            lines.append(f"- **{label}**: {len(items)}")
        lines.append("")

        lines.append("### Flag Analysis")
        lines.append("")
        lines.append(f"- **Total flags referenced**: {flag_summary.get('total_flags', 0)}")
        lines.append(f"- **Flags never set**: {flag_summary.get('never_set', 0)}")
        lines.append(f"- **Flags never read**: {flag_summary.get('never_read', 0)}")
        lines.append(f"- **Flags read before write**: {flag_summary.get('read_before_write', 0)}")
        lines.append(f"- **Flags written but never read**: {flag_summary.get('write_without_read', 0)}")
        lines.append("")

        top_suspicious = self.database.top_suspicious(limit=top_limit)
        if top_suspicious:
            lines.append("## Top Suspicious Resources")
            lines.append("")
            lines.append("| Score | Level | Name | Type | Reasons |")
            lines.append("|-------|-------|------|------|---------|")
            for item in top_suspicious:
                reasons = "; ".join(item.reasons[:2])
                if len(item.reasons) > 2:
                    reasons += f" (+{len(item.reasons)-2} more)"
                lines.append(f"| {item.score} | {item.level.name} | `{item.name}` | {item.resource_type.name} | {reasons} |")
            lines.append("")

        if self.database.plot_branches:
            lines.append("## Plot Branches")
            lines.append("")
            lines.append("| Plot State | Reachable | Has Code | Incoming | Outgoing |")
            lines.append("|------------|-----------|----------|----------|----------|")
            for pv, branch in sorted(self.database.plot_branches.items(), key=lambda x: x[0]):
                reachable = "Yes" if branch.reachable else "**No**"
                has_code = "Yes" if branch.has_code else "**No**"
                lines.append(f"| `global.plot == {pv}` | {reachable} | {has_code} | {len(branch.incoming_states)} | {len(branch.outgoing_states)} |")
            lines.append("")

        dead_items = dead
        for key, label, header in [
            ("objects", "Dead Objects", "Objects that are never instantiated or placed in any room"),
            ("rooms", "Dead Rooms", "Rooms with no incoming transitions"),
            ("scripts", "Dead Scripts", "Scripts that are never called"),
            ("sprites", "Dead Sprites", "Sprites never used by any object or draw call"),
            ("sounds", "Dead Sounds", "Sounds never played"),
            ("dialogues", "Dead Dialogues", "Dialogue entries with zero references in code"),
        ]:
            items = dead_items.get(key, [])
            if items:
                lines.append(f"## {label}")
                lines.append("")
                lines.append(f"{header}")
                lines.append("")
                for item in sorted(items)[:100]:
                    lines.append(f"- `{item}`")
                if len(items) > 100:
                    lines.append(f"- *... and {len(items) - 100} more*")
                lines.append("")

        output_path.write_text("\n".join(lines), encoding="utf-8")
        return output_path
