from __future__ import annotations

from pathlib import Path

import orjson

from core.database import AnalysisDatabase
from core.graph import DependencyGraph
from core.models import ProjectIndex, SuspicionLevel


class JsonReportGenerator:
    def __init__(self, index: ProjectIndex, graph: DependencyGraph, database: AnalysisDatabase) -> None:
        self.index = index
        self.graph = graph
        self.database = database

    def generate(self, output_path: Path, top_limit: int = 100) -> Path:
        output_path = output_path.resolve()
        if output_path.suffix == "":
            output_path = output_path / "report.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        summary = self.database.summary()
        flag_summary = self.database.flag_summary()
        dead = self.database.get_dead_summary()

        report = {
            "meta": {
                "game_name": self.index.game_name,
                "project_path": str(self.index.project_path),
                "generated_by": "GameMaker Static Analyzer",
            },
            "summary": {
                "resources": {
                    "objects": self.index.total_objects(),
                    "rooms": self.index.total_rooms(),
                    "scripts": self.index.total_scripts(),
                    "sprites": self.index.total_sprites(),
                    "sounds": self.index.total_sounds(),
                    "dialogues": len(self.index.dialogues),
                    "flags": len(self.index.flags),
                    "total": self.index.total_resources(),
                },
                "dead": dead,
                "flags": {
                    "total": flag_summary.get("total_flags", 0),
                    "never_set": flag_summary.get("never_set", 0),
                    "never_read": flag_summary.get("never_read", 0),
                    "read_before_write": flag_summary.get("read_before_write", 0),
                    "write_without_read": flag_summary.get("write_without_read", 0),
                    "never_set_detail": flag_summary.get("never_set_detail", []),
                    "never_read_detail": flag_summary.get("never_read_detail", []),
                    "write_without_read_detail": flag_summary.get("write_without_read_detail", []),
                },
                "suspicious_total": summary["suspicious_total"],
                "findings_total": summary["findings_total"],
                "plot_branches": summary["plot_branches"],
            },
            "suspicious": [
                {
                    "name": item.name,
                    "type": item.resource_type.name,
                    "score": item.score,
                    "level": item.level.name,
                    "reasons": item.reasons,
                    "details": item.details,
                }
                for item in self.database.top_suspicious(limit=top_limit)
            ],
            "plot_branches": [
                {
                    "plot_value": pv,
                    "reachable": branch.reachable,
                    "has_code": branch.has_code,
                    "incoming_states": branch.incoming_states,
                    "outgoing_states": branch.outgoing_states,
                    "reference_count": len(branch.references),
                }
                for pv, branch in sorted(
                    self.database.plot_branches.items(), key=lambda x: x[0]
                )
            ],
            "graph": self.graph.to_dict(),
        }

        output_path.write_bytes(orjson.dumps(report, option=orjson.OPT_INDENT_2))
        return output_path
