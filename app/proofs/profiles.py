from __future__ import annotations

from dataclasses import asdict, dataclass

from app.models import GeneratedTree, TreeHashFunction, TreeType


@dataclass(frozen=True)
class ProofProfile:
    id: str
    label: str
    tree_type: TreeType
    hash_function: TreeHashFunction
    prover_type: str
    verifier_type: str
    setup_type: str
    description: str

    def as_dict(self) -> dict:
        payload = asdict(self)
        payload["tree_type"] = self.tree_type.value
        payload["hash_function"] = self.hash_function.value
        return payload


PROOF_PROFILES = (
    ProofProfile(
        id="mpt_standard",
        label="MPT standard proof",
        tree_type=TreeType.MERKLE_PATRICIA,
        hash_function=TreeHashFunction.KECCAK,
        prover_type="merkle",
        verifier_type="merkle",
        setup_type="",
        description="One complete Keccak MPT path per sampled key.",
    ),
    ProofProfile(
        id="mpt_optimized",
        label="MPT deduplicated multiproof",
        tree_type=TreeType.MERKLE_PATRICIA,
        hash_function=TreeHashFunction.KECCAK,
        prover_type="merkle_optimized",
        verifier_type="merkle_optimized",
        setup_type="",
        description="Shared encoded MPT nodes are stored only once.",
    ),
    ProofProfile(
        id="verkle_multiproof_optimized",
        label="Verkle optimized KZG multiproof",
        tree_type=TreeType.VERKLE,
        hash_function=TreeHashFunction.KZG,
        prover_type="verkle_multiproof_optimized",
        verifier_type="verkle_multiproof_optimized",
        setup_type="verkle_kzg",
        description="Aggregated KZG openings verified against the persisted root.",
    ),
)


class UnsupportedProofProfile(ValueError):
    pass


def profiles_for_tree(tree: GeneratedTree) -> list[ProofProfile]:
    return [
        profile
        for profile in PROOF_PROFILES
        if profile.tree_type == tree.tree_type
        and profile.hash_function == tree.hash_function
    ]


def resolve_profile(
    tree: GeneratedTree,
    *,
    prover_type: str,
    verifier_type: str,
    setup_type: str,
) -> ProofProfile:
    for profile in profiles_for_tree(tree):
        if (
            profile.prover_type == prover_type
            and profile.verifier_type == verifier_type
            and profile.setup_type == setup_type
        ):
            return profile
    if tree.tree_type == TreeType.POSEIDON_MERKLE:
        raise UnsupportedProofProfile(
            "Poseidon proving is not available: the thesis PySNARK prover and "
            "verifier do not yet share a complete proof contract."
        )
    raise UnsupportedProofProfile(
        "The selected prover, verifier, and setup are not compatible with "
        f"this {tree.tree_type.value} tree."
    )
