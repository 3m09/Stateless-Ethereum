from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models import ProofStatus
from app.schemas import JobRead


class ProofExperimentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120)
    tree_id: str = Field(min_length=36, max_length=36)
    prover_type: str = Field(min_length=1, max_length=64)
    verifier_type: str = Field(min_length=1, max_length=64)
    setup_type: str = Field(default="", max_length=64)
    num_keys_to_prove: int = Field(default=1, ge=1, le=250)
    selection_seed: int = Field(default=0, ge=0, le=2_147_483_647)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        cleaned = " ".join(value.split())
        if not cleaned:
            raise ValueError("Experiment name cannot be blank")
        return cleaned

    @field_validator("prover_type", "verifier_type", "setup_type")
    @classmethod
    def normalize_identifier(cls, value: str) -> str:
        return value.strip().lower()


class ProofExperimentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    tree_id: str
    job_id: str
    prover_type: str
    verifier_type: str
    setup_type: str
    width: int
    tree_type: str
    requested_key_count: int
    num_keys_tree: int
    selection_seed: int
    sampled_keys: list
    proof_size: int | None
    proving_time: float | None
    verification_time: float | None
    verified: bool | None
    root_hash: str | None
    status: ProofStatus
    artifact_path: str | None
    error: str | None
    created_at: datetime
    completed_at: datetime | None


class ProofExperimentAccepted(BaseModel):
    experiment: ProofExperimentRead
    job: JobRead


class ProofProfileRead(BaseModel):
    id: str
    label: str
    tree_type: str
    hash_function: str
    prover_type: str
    verifier_type: str
    setup_type: str
    description: str
