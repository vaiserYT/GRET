from __future__ import annotations

from pathlib import Path
from typing import Optional

from core.graph import DependencyGraph
from core.models import ProjectIndex


class GraphvizReportGenerator:
    def __init__(self, index: ProjectIndex, graph: DependencyGraph) -> None:
        self.index = index
        self.graph = graph

    def generate_dot(self, output_path: Path, max_nodes: Optional[int] = None) -> Path:
        output_path = output_path.resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        lines: list[str] = []
        lines.append("digraph GameMakerProject {")
        lines.append("  rankdir=LR;")
        lines.append("  node [shape=box, style=rounded, fontname=monospace];")
        lines.append("  edge [fontname=monospace, fontsize=10];")
        lines.append("")

        node_colors = {
            "object": "#1f77b4",
            "room": "#2ca02c",
            "script": "#ff7f0e",
            "sprite": "#9467bd",
            "sound": "#d62728",
            "font": "#8c564b",
        }

        nodes = list(self.graph.graph.nodes())
        if max_nodes and len(nodes) > max_nodes:
            suspicious_names = {
                item.name for item in getattr(self, "_suspicious_names", set())
            }
            high_degree = sorted(
                nodes,
                key=lambda n: self.graph.graph.degree(n),
                reverse=True,
            )[:max_nodes]
            nodes = list(set(high_degree) | suspicious_names & set(nodes))

        for node in nodes:
            node_type = self.graph.resource_type(node)
            color = node_colors.get(node_type.name.lower() if node_type else "", "#999")
            label = node.replace("_", "\\n")
            lines.append(f'  "{node}" [label="{label}", fillcolor="{color}", style="filled,rounded", fontcolor="white"];')

        lines.append("")

        edges = list(self.graph.graph.edges(data=True))
        if max_nodes:
            edges = [(u, v, d) for u, v, d in edges if u in nodes and v in nodes]

        for u, v, data in edges:
            label = data.get("label", "")
            if label:
                lines.append(f'  "{u}" -> "{v}" [label="{label}"];')
            else:
                lines.append(f'  "{u}" -> "{v}";')

        lines.append("}")

        content = "\n".join(lines)
        output_path.write_text(content, encoding="utf-8")
        return output_path

    def generate_svg(self, dot_path: Path, output_path: Path) -> Optional[Path]:
        try:
            import subprocess
            result = subprocess.run(
                ["dot", "-Tsvg", str(dot_path), "-o", str(output_path)],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode == 0:
                return output_path
            return None
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None
