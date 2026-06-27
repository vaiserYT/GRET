from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from core.database import AnalysisDatabase
from core.graph import DependencyGraph
from core.models import ProjectIndex, ResourceType


class HtmlReportGenerator:
    def __init__(self, index: ProjectIndex, graph: DependencyGraph, database: AnalysisDatabase) -> None:
        self.index = index
        self.graph = graph
        self.database = database
        template_dir = Path(__file__).parent.parent / "templates"
        self.env = Environment(loader=FileSystemLoader(str(template_dir)))

    def generate(self, output_path: Path, top_limit: int = 100) -> Path:
        template = self.env.get_template("report.html")
        suspicious_items = self.database.top_suspicious(limit=top_limit)
        summary = self.database.summary()
        flag_summary = self.database.flag_summary()
        dead = self.database.get_dead_summary()

        flag_never_set_details = flag_summary.get("never_set_detail", [])
        flag_never_read_details = flag_summary.get("never_read_detail", [])
        flag_write_without_read_details = flag_summary.get("write_without_read_detail", [])

        plot_branches = sorted(
            self.database.plot_branches.items(),
            key=lambda x: x[0],
        )

        explorer: list[tuple[str, list[str]]] = []
        for rt, label in [
            (ResourceType.OBJECT, "Objects"),
            (ResourceType.ROOM, "Rooms"),
            (ResourceType.SCRIPT, "Scripts"),
            (ResourceType.SPRITE, "Sprites"),
            (ResourceType.SOUND, "Sounds"),
        ]:
            resources = sorted(
                name for name, rtype in self.index.all_resources.items() if rtype == rt
            )
            if resources:
                explorer.append((label, resources))

        html = template.render(
            game_name=self.index.game_name,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            project_path=str(self.index.project_path),
            top_limit=top_limit,
            total_objects=self.index.total_objects(),
            total_rooms=self.index.total_rooms(),
            total_scripts=self.index.total_scripts(),
            total_sprites=self.index.total_sprites(),
            total_sounds=self.index.total_sounds(),
            total_dialogues=len(self.index.dialogues),
            total_flags=len(self.index.flags),
            total_resources=self.index.total_resources(),
            total_fonts=len(self.index.fonts),
            suspicious_total=summary["suspicious_total"],
            findings_total=summary["findings_total"],
            dead_objects=summary["dead_objects"],
            dead_rooms=summary["dead_rooms"],
            dead_scripts=summary["dead_scripts"],
            dead_sprites=summary["dead_sprites"],
            dead_sounds=summary["dead_sounds"],
            dead_dialogues=summary["dead_dialogues"],
            plot_branches_count=summary["plot_branches"],
            orphan_resources=summary["orphan_resources"],
            suspicious_items=suspicious_items,
            flag_never_set=flag_summary.get("never_set", 0),
            flag_never_read=flag_summary.get("never_read", 0),
            flag_read_before_write=flag_summary.get("read_before_write", 0),
            flag_write_without_read=flag_summary.get("write_without_read", 0),
            flag_never_set_details=flag_never_set_details,
            flag_never_read_details=flag_never_read_details,
            flag_write_without_read_details=flag_write_without_read_details,
            dead_objects_list=sorted(dead["objects"]),
            dead_rooms_list=sorted(dead["rooms"]),
            dead_scripts_list=sorted(dead["scripts"]),
            dead_sprites_list=sorted(dead["sprites"]),
            dead_sounds_list=sorted(dead["sounds"]),
            dead_dialogues_list=sorted(dead["dialogues"]),
            plot_branches=plot_branches,
            explorer=explorer,
        )

        output_path = output_path.resolve()
        if output_path.suffix != ".html":
            output_path = output_path / "report.html"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")

        return output_path
