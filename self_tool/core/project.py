"""ProjectContext: cross-file audit context for project-level detectors."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Sequence

from self_tool.core.scanner import FileContext, FrameworkInfo
from self_tool.graph.model import Graph
from self_tool.graph.builder import build_project_graph


@dataclass
class ProjectContext:
    files: List[FileContext]
    framework: FrameworkInfo
    graph: Graph
    knowledge_snapshot: dict = field(default_factory=dict)

    @classmethod
    def build(
        cls,
        files: Sequence[FileContext],
        framework: FrameworkInfo,
        knowledge_snapshot: Optional[dict] = None,
    ) -> "ProjectContext":
        graph = build_project_graph(files, framework=framework.name)
        return cls(
            files=list(files),
            framework=framework,
            graph=graph,
            knowledge_snapshot=dict(knowledge_snapshot or {}),
        )

    @property
    def project_fingerprint(self) -> str:
        return self.graph.project_fingerprint

    def files_for_language(self, language: str) -> List[FileContext]:
        return [f for f in self.files if f.language == language]