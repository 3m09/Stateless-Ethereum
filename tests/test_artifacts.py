from pathlib import Path

import pytest

from app.artifacts import ArtifactStore, UnsafeArtifactPath


def test_artifact_store_creates_expected_directories(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    store.bootstrap()

    workspace = store.initialize_job(
        "3df90acd-a5f6-430b-a81a-f274fc800762",
        {"status": "queued"},
    )

    assert workspace.is_dir()
    assert (workspace / "manifest.json").read_text().endswith("\n")
    assert (store.root / "trees").is_dir()


@pytest.mark.parametrize(
    ("category", "artifact_id", "parts"),
    [
        ("unknown", "safe-id", ()),
        ("jobs", "../escape", ()),
        ("jobs", "safe-id", ("..", "escape")),
        ("jobs", "/absolute", ()),
    ],
)
def test_artifact_store_rejects_unsafe_paths(
    tmp_path: Path,
    category: str,
    artifact_id: str,
    parts: tuple[str, ...],
) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    store.bootstrap()

    with pytest.raises(UnsafeArtifactPath):
        store.path_for(category, artifact_id, *parts)
