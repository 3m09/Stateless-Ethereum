import json
import os
import re
from pathlib import Path
from typing import Any

SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
ARTIFACT_CATEGORIES = ("datasets", "trees", "proofs", "jobs", "tmp")


class UnsafeArtifactPath(ValueError):
    pass


class ArtifactStore:
    """Provides guarded access to application-owned artifact directories."""

    def __init__(self, root: Path):
        self.root = root.resolve()

    def bootstrap(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        for category in ARTIFACT_CATEGORIES:
            (self.root / category).mkdir(exist_ok=True)

    def path_for(
        self,
        category: str,
        artifact_id: str,
        *parts: str,
        create: bool = False,
    ) -> Path:
        components = (category, artifact_id, *parts)
        if category not in ARTIFACT_CATEGORIES:
            raise UnsafeArtifactPath(f"Unknown artifact category: {category}")
        if any(not SAFE_COMPONENT.fullmatch(component) for component in components):
            raise UnsafeArtifactPath("Artifact paths may contain only safe components")

        candidate = self.root.joinpath(*components).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise UnsafeArtifactPath("Artifact path escapes the configured root")
        if create:
            candidate.mkdir(parents=True, exist_ok=True)
        return candidate

    def initialize_job(self, job_id: str, manifest: dict[str, Any]) -> Path:
        workspace = self.path_for("jobs", job_id, create=True)
        self.write_json(workspace / "manifest.json", manifest)
        return workspace

    def write_json(self, target: Path, payload: dict[str, Any]) -> None:
        target = target.resolve()
        if self.root not in target.parents:
            raise UnsafeArtifactPath("Cannot write outside the artifact root")
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(f"{target.suffix}.tmp")
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, target)

    def read_json(self, target: Path) -> dict[str, Any]:
        target = target.resolve()
        if self.root not in target.parents:
            raise UnsafeArtifactPath("Cannot read outside the artifact root")
        return json.loads(target.read_text(encoding="utf-8"))
