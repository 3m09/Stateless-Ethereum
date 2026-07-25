from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.trees.poseidon import parameter_manifest, poseidon_hash_bytes


@dataclass
class TreeBuildOutput:
    root_hash: str
    visualization: dict[str, Any]
    persisted_node_count: int
    storage_engine: str
    leveldb_directory: str
    root_file: str
    extra_manifest: dict[str, Any] = field(default_factory=dict)


def hex_bytes(value: str) -> bytes:
    return bytes.fromhex(value.removeprefix("0x"))


def build_merkle_patricia_tree(
    *,
    tree_id: str,
    storage_directory: Path,
    accounts: list[dict[str, str]],
    width: int,
) -> TreeBuildOutput:
    """Build a Keccak radix-Patricia tree over secured Ethereum keys."""

    return _build_registered_mpt(
        tree_id=tree_id,
        storage_directory=storage_directory,
        accounts=accounts,
        hash_function="keccak",
        width=width,
    )


def _path_label(path: Any) -> str:
    digits = [path.at(index) for index in range(len(path))]
    if getattr(path, "_width", 16) == 16:
        return "".join(f"{digit:x}" for digit in digits)
    return ".".join(str(digit) for digit in digits)


def _build_registered_mpt(
    *,
    tree_id: str,
    storage_directory: Path,
    accounts: list[dict[str, str]],
    hash_function: str,
    width: int,
) -> TreeBuildOutput:
    from merkle.hash import keccak_hash
    from merkle.nibble_path import NibblePath
    from merkle.node import Node
    from tree.merkle_tree import MerklePatriciaTrie
    from zkSNARK.zk_encoder_decoder import _zk_decode

    trie = MerklePatriciaTrie(
        width=width,
        db_path=str(storage_directory),
        hash_fn=hash_function,
    )
    is_poseidon = hash_function == "poseidon"
    decoder = _zk_decode if is_poseidon else Node.decode
    reference_hash = poseidon_hash_bytes if is_poseidon else keccak_hash
    if is_poseidon and width == 16:
        encoding_name = "32-byte-aligned ZK node encoding"
    elif is_poseidon:
        encoding_name = "versioned RLP nodes with Poseidon references"
    else:
        encoding_name = "Ethereum RLP" if width == 16 else "extended radix RLP"
    try:
        for account in accounts:
            trie.insert(
                hex_bytes(account["secure_trie_key"]),
                hex_bytes(account["account_rlp"]),
            )

        graph_nodes: dict[str, dict[str, Any]] = {}
        graph_edges: dict[tuple[str, str], dict[str, Any]] = {}
        insertion_events: list[dict[str, Any]] = []

        for step, account in enumerate(accounts):
            key = hex_bytes(account["secure_trie_key"])
            key_path = NibblePath(key, width=width)
            proof = trie.get_proof_tree(key)
            path_ids: list[str] = []
            consumed = 0

            for structural_depth, encoded in enumerate(proof):
                node = decoder(encoded)
                node_id = f"0x{reference_hash(encoded).hex()}"
                path_ids.append(node_id)
                if isinstance(node, Node.Leaf):
                    kind = "leaf"
                    segment = _path_label(node.path)
                elif isinstance(node, Node.Extension):
                    kind = "extension"
                    segment = _path_label(node.path)
                else:
                    kind = "branch"
                    segment = ""

                existing = graph_nodes.get(node_id)
                if existing is None:
                    graph_nodes[node_id] = {
                        "id": node_id,
                        "type": kind,
                        "hash": node_id,
                        "hash_label": f"{node_id[:10]}…{node_id[-6:]}",
                        "structural_depth": structural_depth,
                        "nibble_depth": consumed,
                        "path_segment": segment,
                        "rlp_bytes": len(encoded),
                        "encoding": encoding_name,
                        "reference": (
                            "poseidon field hash" if is_poseidon else "keccak hash"
                        ),
                        "reveal_step": step,
                    }
                else:
                    existing["reveal_step"] = min(
                        existing["reveal_step"],
                        step,
                    )

                if structural_depth + 1 < len(proof):
                    child_id = (
                        f"0x{reference_hash(proof[structural_depth + 1]).hex()}"
                    )
                    if isinstance(node, Node.Extension):
                        edge_label = segment
                        consumed += len(node.path)
                    elif isinstance(node, Node.Branch):
                        edge_label = str(key_path.at(consumed))
                        consumed += 1
                    else:
                        edge_label = ""
                    edge_key = (node_id, child_id)
                    current_edge = graph_edges.get(edge_key)
                    if current_edge is None:
                        graph_edges[edge_key] = {
                            "source": node_id,
                            "target": child_id,
                            "label": edge_label,
                            "reveal_step": step,
                        }
                    else:
                        current_edge["reveal_step"] = min(
                            current_edge["reveal_step"],
                            step,
                        )

            insertion_events.append(
                {
                    "step": step,
                    "number": step + 1,
                    "address": account["address"],
                    "secure_trie_key": account["secure_trie_key"],
                    "value_bytes": len(hex_bytes(account["account_rlp"])),
                    "path": path_ids,
                }
            )

        node_values = list(graph_nodes.values())
        counts = {
            kind: sum(1 for node in node_values if node["type"] == kind)
            for kind in ("leaf", "extension", "branch")
        }
        root_hash = f"0x{trie.root_hash().hex()}"
        visualization = {
            "schema_version": 1,
            "tree_id": tree_id,
            "root_id": root_hash,
            "nodes": node_values,
            "edges": list(graph_edges.values()),
            "insertion_events": insertion_events,
            "metrics": {
                "node_count": len(node_values),
                "leaf_count": counts["leaf"],
                "extension_count": counts["extension"],
                "branch_count": counts["branch"],
                "max_depth": max(
                    (node["structural_depth"] for node in node_values),
                    default=0,
                ),
            },
        }
        (storage_directory / "root.bin").write_bytes(trie.root_hash())
        with trie.db.iterator(include_value=False) as iterator:
            persisted_node_count = sum(1 for _key in iterator)
        extra_manifest: dict[str, Any] = {
            "node_encoding": encoding_name,
            "key_encoding": (
                "32-byte secured Ethereum account key routed as "
                f"base-{width} digits"
            ),
            "value_encoding": "Ethereum account RLP",
            "ethereum_compatible": width == 16,
        }
        if is_poseidon:
            extra_manifest["poseidon_parameters"] = parameter_manifest()
        return TreeBuildOutput(
            root_hash=root_hash,
            visualization=visualization,
            persisted_node_count=persisted_node_count,
            storage_engine=(
                f"registered thesis {hash_function} MerklePatriciaTrie + LevelDB"
            ),
            leveldb_directory="merkle_state_db",
            root_file="root.bin",
            extra_manifest=extra_manifest,
        )
    finally:
        trie.db.close()


def build_poseidon_merkle_patricia_tree(
    *,
    tree_id: str,
    storage_directory: Path,
    accounts: list[dict[str, str]],
    width: int,
) -> TreeBuildOutput:
    """Build the thesis Poseidon MPT with 32-byte field references."""

    return _build_registered_mpt(
        tree_id=tree_id,
        storage_directory=storage_directory,
        accounts=accounts,
        hash_function="poseidon",
        width=width,
    )


def _verkle_path(width: int, key: bytes) -> list[int]:
    from verkle.utils.key_to_path import _key_to_path

    return _key_to_path(width, key)


@lru_cache(maxsize=8)
def _verkle_setup(secret: int, width: int) -> Any:
    from setups.verkle_kzg_setup import VerkleKZGSetup

    return VerkleKZGSetup(secret, width)


def build_verkle_tree(
    *,
    tree_id: str,
    storage_directory: Path,
    accounts: list[dict[str, str]],
    width: int,
    secret: int,
) -> TreeBuildOutput:
    """Build the registered KZG Verkle tree used by generate_tree.py."""

    from tree.verkle_tree import VerkleTree

    setup = _verkle_setup(secret, width)
    tree = VerkleTree(
        width,
        db_path=str(storage_directory),
        setup_object=setup,
    )
    try:
        for account in accounts:
            tree.insert(
                hex_bytes(account["secure_trie_key"]),
                hex_bytes(account["account_rlp"]),
            )

        path_depth = len(
            _verkle_path(width, hex_bytes(accounts[0]["secure_trie_key"]))
        )
        graph_nodes: dict[str, dict[str, Any]] = {}
        graph_edges: dict[tuple[str, str], dict[str, Any]] = {}

        def visit(reference: bytes, depth: int) -> None:
            node_id = f"0x{reference.hex()}"
            if node_id in graph_nodes:
                return
            node = tree._make_tree_node(reference)
            encoded = tree.db.get(reference) or b""
            kind = "suffix" if depth == path_depth - 1 else "internal"
            graph_nodes[node_id] = {
                "id": node_id,
                "type": kind,
                "hash": node_id,
                "hash_label": f"{node_id[:10]}…{node_id[-6:]}",
                "structural_depth": depth,
                "nibble_depth": depth,
                "path_segment": "",
                "rlp_bytes": len(encoded),
                "encoding": "compressed length-delimited Verkle vector node",
                "reference": "KZG commitment field hash",
                "commitment": [
                    str(int(node.commitment_to_children[0])),
                    str(int(node.commitment_to_children[1])),
                ],
                "reveal_step": len(accounts),
            }
            if depth >= path_depth - 1:
                return
            for child_index, child_reference in enumerate(node.children):
                if child_reference is None:
                    continue
                child_id = f"0x{child_reference.hex()}"
                graph_edges[(node_id, child_id)] = {
                    "source": node_id,
                    "target": child_id,
                    "label": str(child_index),
                    "reveal_step": len(accounts),
                }
                visit(child_reference, depth + 1)

        visit(tree._root_ref, 0)

        insertion_events = []
        for step, account in enumerate(accounts):
            path = _verkle_path(
                width,
                hex_bytes(account["secure_trie_key"]),
            )
            reference = tree._root_ref
            path_ids = [f"0x{reference.hex()}"]
            for depth, child_index in enumerate(path[:-1]):
                node = tree._make_tree_node(reference)
                child_reference = node.children[child_index]
                if child_reference is None:
                    raise RuntimeError("Generated Verkle route is incomplete")
                source_id = f"0x{reference.hex()}"
                target_id = f"0x{child_reference.hex()}"
                graph_nodes[source_id]["reveal_step"] = min(
                    graph_nodes[source_id]["reveal_step"],
                    step,
                )
                graph_nodes[target_id]["reveal_step"] = min(
                    graph_nodes[target_id]["reveal_step"],
                    step,
                )
                graph_edges[(source_id, target_id)]["reveal_step"] = min(
                    graph_edges[(source_id, target_id)]["reveal_step"],
                    step,
                )
                reference = child_reference
                path_ids.append(target_id)
                if depth + 1 == path_depth - 1:
                    break

            insertion_events.append(
                {
                    "step": step,
                    "number": step + 1,
                    "address": account["address"],
                    "secure_trie_key": account["secure_trie_key"],
                    "value_bytes": len(hex_bytes(account["account_rlp"])),
                    "path": path_ids,
                    "suffix_index": path[-1],
                }
            )

        node_values = list(graph_nodes.values())
        internal_count = sum(
            node["type"] == "internal" for node in node_values
        )
        suffix_count = sum(node["type"] == "suffix" for node in node_values)
        root_hash = f"0x{tree._root_ref.hex()}"
        visualization = {
            "schema_version": 1,
            "tree_id": tree_id,
            "root_id": root_hash,
            "nodes": node_values,
            "edges": list(graph_edges.values()),
            "insertion_events": insertion_events,
            "metrics": {
                "node_count": len(node_values),
                "leaf_count": suffix_count,
                "extension_count": 0,
                "branch_count": internal_count,
                "internal_count": internal_count,
                "suffix_count": suffix_count,
                "max_depth": max(
                    (node["structural_depth"] for node in node_values),
                    default=0,
                ),
            },
        }
        (storage_directory / "root.bin").write_bytes(tree._root_ref)
        with tree.db.iterator(include_value=False) as iterator:
            persisted_node_count = sum(1 for _key in iterator)
        return TreeBuildOutput(
            root_hash=root_hash,
            visualization=visualization,
            persisted_node_count=persisted_node_count,
            storage_engine="thesis KZG VerkleTree + LevelDB",
            leveldb_directory="verkle_state_db",
            root_file="root.bin",
            extra_manifest={
                "node_encoding": (
                    "zlib-compressed length-delimited Verkle vector nodes"
                ),
                "key_encoding": (
                    f"32-byte secure key split into base-{width} path digits"
                ),
                "value_encoding": (
                    "Ethereum account RLP interpreted modulo the "
                    "BLS12-381 scalar field for KZG commitment"
                ),
                "setup": {
                    "type": "verkle_kzg",
                    "curve": "BLS12-381",
                    "width": width,
                    "secret_source": "server environment",
                },
                "root_commitment": [
                    str(int(tree.root.commitment_to_children[0])),
                    str(int(tree.root.commitment_to_children[1])),
                ],
            },
        )
    finally:
        tree.db.close()
