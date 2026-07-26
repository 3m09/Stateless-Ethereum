import json

import httpx2
import pytest

pytestmark = pytest.mark.anyio


async def test_dashboard_and_health_check(client: httpx2.AsyncClient) -> None:
    dashboard = await client.get("/")
    health = await client.get("/healthz")

    assert dashboard.status_code == 200
    assert "Build, prove" in dashboard.text
    assert health.status_code == 200
    assert health.json() == {
        "status": "ok",
        "version": "0.5.0",
        "database": "ok",
        "artifact_store": "ok",
    }


async def test_job_lifecycle_is_persisted(client: httpx2.AsyncClient) -> None:
    created = await client.post(
        "/api/v1/jobs",
        json={
            "kind": "tree_generation",
            "parameters": {"tree_type": "merkle", "num_keys": 128},
        },
    )

    assert created.status_code == 201
    job = created.json()
    assert job["status"] == "queued"
    assert job["progress"] == 0

    running = await client.patch(
        f"/api/v1/jobs/{job['id']}",
        json={
            "status": "running",
            "progress": 30,
            "message": "Inserting Ethereum account 38 of 128",
        },
    )
    assert running.status_code == 200
    assert running.json()["started_at"] is not None
    assert running.json()["progress"] == 30

    succeeded = await client.patch(
        f"/api/v1/jobs/{job['id']}",
        json={
            "status": "succeeded",
            "result": {"root": "0x1234"},
            "message": "Tree generated",
        },
    )
    assert succeeded.status_code == 200
    assert succeeded.json()["status"] == "succeeded"
    assert succeeded.json()["progress"] == 100
    assert succeeded.json()["finished_at"] is not None

    fetched = await client.get(f"/api/v1/jobs/{job['id']}")
    assert fetched.status_code == 200
    assert fetched.json()["result"] == {"root": "0x1234"}

    manifest_path = (
        client.application.state.artifacts.root / "jobs" / job["id"] / "manifest.json"
    )
    manifest = json.loads(manifest_path.read_text())
    assert manifest["job_id"] == job["id"]
    assert manifest["parameters"]["num_keys"] == 128


async def test_invalid_job_transition_returns_conflict(
    client: httpx2.AsyncClient,
) -> None:
    job = (
        await client.post(
            "/api/v1/jobs",
            json={"kind": "ethereum_import", "parameters": {}},
        )
    ).json()

    response = await client.patch(
        f"/api/v1/jobs/{job['id']}",
        json={"status": "succeeded"},
    )

    assert response.status_code == 409
    assert "Cannot transition" in response.json()["detail"]


async def test_job_list_can_be_filtered(client: httpx2.AsyncClient) -> None:
    await client.post(
        "/api/v1/jobs",
        json={"kind": "system", "parameters": {"name": "one"}},
    )
    second = (
        await client.post(
            "/api/v1/jobs",
            json={"kind": "system", "parameters": {"name": "two"}},
        )
    ).json()
    await client.patch(
        f"/api/v1/jobs/{second['id']}",
        json={"status": "running", "progress": 10},
    )

    queued = (await client.get("/api/v1/jobs", params={"status": "queued"})).json()
    running = (await client.get("/api/v1/jobs", params={"status": "running"})).json()

    assert len(queued) == 1
    assert len(running) == 1
    assert running[0]["id"] == second["id"]


async def test_unknown_job_returns_not_found(
    client: httpx2.AsyncClient,
) -> None:
    response = await client.get("/api/v1/jobs/not-a-real-job")
    assert response.status_code == 404
