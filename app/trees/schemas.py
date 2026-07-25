from datetime import datetime
from enum import Enum

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)

from app.models import (
    TreeHashFunction,
    TreeStatus,
    TreeType,
)
from app.schemas import JobRead


class InsertionOrder(str, Enum):
    DATASET = "dataset"
    SECURE_KEY = "secure_key"


MPT_MIN_WIDTH = 4
MPT_MAX_WIDTH = 128
VERKLE_WIDTHS = {16, 32, 64, 128, 256, 512}


class TreeBuildCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120)
    dataset_id: str = Field(min_length=36, max_length=36)
    tree_type: TreeType = TreeType.MERKLE_PATRICIA
    hash_function: TreeHashFunction = TreeHashFunction.KECCAK
    setup_type: str = Field(default="", max_length=32)
    key_length: int = Field(default=32, ge=1, le=64)
    width: int = Field(default=16, ge=2, le=512)
    key_count: int | None = Field(default=None, ge=1, le=250)
    insertion_order: InsertionOrder = InsertionOrder.SECURE_KEY

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        cleaned = " ".join(value.split())
        if not cleaned:
            raise ValueError("Tree name cannot be blank")
        return cleaned

    @field_validator("setup_type")
    @classmethod
    def clean_setup_type(cls, value: str) -> str:
        return value.strip().lower()

    @model_validator(mode="after")
    def validate_tree_profile(self) -> "TreeBuildCreate":
        if self.key_length != 32:
            raise ValueError(
                "Ethereum secure account keys require KEY_LENGTH=32"
            )

        if self.tree_type == TreeType.MERKLE_PATRICIA:
            if self.hash_function != TreeHashFunction.KECCAK:
                raise ValueError("Standard MPT requires HASH_FN=keccak")
            if self.setup_type:
                raise ValueError("Standard MPT does not use SETUP_TYPE")
            if not MPT_MIN_WIDTH <= self.width <= MPT_MAX_WIDTH:
                raise ValueError(
                    f"MPT WIDTH must be between {MPT_MIN_WIDTH} and "
                    f"{MPT_MAX_WIDTH}"
                )

        elif self.tree_type == TreeType.POSEIDON_MERKLE:
            if self.hash_function != TreeHashFunction.POSEIDON:
                raise ValueError("Poseidon MPT requires HASH_FN=poseidon")
            if self.setup_type:
                raise ValueError("Poseidon MPT does not use SETUP_TYPE")
            if not MPT_MIN_WIDTH <= self.width <= MPT_MAX_WIDTH:
                raise ValueError(
                    f"Poseidon MPT WIDTH must be between {MPT_MIN_WIDTH} and "
                    f"{MPT_MAX_WIDTH}"
                )

        elif self.tree_type == TreeType.VERKLE:
            if self.hash_function != TreeHashFunction.KZG:
                raise ValueError("Verkle requires HASH_FN=kzg")
            if self.setup_type != "verkle_kzg":
                raise ValueError("Verkle requires SETUP_TYPE=verkle_kzg")
            if self.width not in VERKLE_WIDTHS:
                allowed = ", ".join(str(width) for width in sorted(VERKLE_WIDTHS))
                raise ValueError(f"Verkle WIDTH must be one of: {allowed}")
        return self


class GeneratedTreeRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    dataset_id: str
    job_id: str
    tree_type: TreeType
    hash_function: TreeHashFunction
    width: int
    requested_key_count: int
    key_count: int
    node_count: int
    leaf_count: int
    extension_count: int
    branch_count: int
    max_depth: int
    root_hash: str | None
    build_duration_ms: int | None
    status: TreeStatus
    configuration: dict
    artifact_path: str | None
    storage_path: str | None
    error: str | None
    created_at: datetime
    completed_at: datetime | None

    @field_serializer("configuration")
    def serialize_configuration(self, value: dict) -> dict:
        # Also protects records created before the secret became server-only.
        return {key: item for key, item in value.items() if key != "secret"}


class TreeBuildAccepted(BaseModel):
    tree: GeneratedTreeRead
    job: JobRead


class TreeVisualization(BaseModel):
    schema_version: int
    tree_id: str
    root_id: str
    nodes: list[dict]
    edges: list[dict]
    insertion_events: list[dict]
    metrics: dict
