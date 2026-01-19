from pysnark.runtime import PrivVal, PubVal, snark, LinComb, backend
from pysnark.poseidon_hash import poseidon_hash
from registry.provers import BaseProver, register_prover
from tree.merkle_tree import MerklePatriciaTrie
from merkle.node import Node
from merkle.nibble_path import NibblePath
from merkle.hash import keccak_hash
import atexit

def serialize_proof_tree_poseidon(proof_nodes: list[bytes], key: bytes):
    if not proof_nodes:
        raise ValueError("Empty proof")

    # 1. Decode all nodes
    decoded_nodes = [Node.decode(n) for n in proof_nodes]
    
    # 2. Pre-calculate path depths (Top-Down)
    # This ensures we know exactly which nibble each Branch node should look at.
    node_depths = []
    current_depth = 0
    path_obj = NibblePath(key)

    for node in decoded_nodes:
        node_depths.append(current_depth)
        if isinstance(node, Node.Leaf):
            current_depth += len(node.path)
        elif isinstance(node, Node.Extension):
            current_depth += len(node.path)
        elif isinstance(node, Node.Branch):
            current_depth += 1  # Branch consumes exactly one nibble

    # 3. Process nodes (Bottom-Up)
    zk_path = []
    last_node_hash = None

    # We iterate backwards to pass Poseidon hashes up the tree
    for i in reversed(range(len(decoded_nodes))):
        node = decoded_nodes[i]
        depth = node_depths[i]
        
        if isinstance(node, Node.Leaf):
            # The leaf data is the end of the chain
            value_int = PubVal(int.from_bytes(node.data, "big"))
            node_hash = poseidon_hash(nibblepath_to_list(node.path)+[value_int])
            
            zk_path.insert(0, {
                "type": "leaf",
                "path": nibblepath_to_list(node.path),
                "value": value_int,
                "poseidon_hash": node_hash
            })
            last_node_hash = node_hash

        elif isinstance(node, Node.Extension):
            # path_hash = poseidon_hash(nibbles)
            # node_hash = poseidon_hash(path_hash, last_node_hash)
            node_hash = poseidon_hash(nibblepath_to_list(node.path) + last_node_hash)
            
            zk_path.insert(0, {
                "type": "extension",
                "path": nibblepath_to_list(node.path),
                "next_hash": last_node_hash, # The Poseidon hash of the child
                "poseidon_hash": node_hash
            })
            last_node_hash = node_hash

        elif isinstance(node, Node.Branch):
            # Get the specific nibble that leads to our leaf
            next_nibble_idx = path_obj.at(depth)

            # Reconstruct the children array
            children_for_poseidon = []
            for idx, ref in enumerate(node.branches):
                if idx == next_nibble_idx:
                    # Use the Poseidon hash we just calculated from the child
                    children_for_poseidon.append(last_node_hash[0])
                else:
                    # Keep the original reference (Keccak hash or RLP encoded short node)
                    # If empty, use zero; if exists, use the existing Keccak reference as raw data
                    if len(ref) == 0:
                        children_for_poseidon.append(PrivVal(0))
                    elif len(ref) < 32:
                        # Standard MPT hashes short nodes; we must keep it consistent
                        children_for_poseidon.append(PrivVal(int.from_bytes(keccak_hash(ref), "big")))
                    else:
                        children_for_poseidon.append(PrivVal(int.from_bytes(ref, "big")))

            value_int = int.from_bytes(node.data, "big")
            value_hash = poseidon_hash([PrivVal(value_int)]) if node.data else poseidon_hash([PrivVal(0)])
            
            # Now compute the Poseidon hash of this branch node
            # The circuit will take these 16 children + value and Poseidon hash them
            node_hash = poseidon_hash(children_for_poseidon + value_hash)

            zk_path.insert(0, {
                "type": "branch",
                "children": children_for_poseidon, # Mixed: 15 Keccak/Null, 1 Poseidon
                "value": value_hash,
                "next_index": next_nibble_idx,
                "poseidon_hash": node_hash
            })
            last_node_hash = node_hash

    return zk_path

def proof_tree_to_zk_path(proof_nodes: list[bytes], key: bytes):
    """
    Convert a Merkle-Patricia proof tree (RLP-encoded nodes)
    into a zkSNARK-friendly path representation.

    Returns:
        path: list[dict]
    """

    if not proof_nodes:
        raise ValueError("Empty proof")

    # Apply secure trie hashing if enabled
    encoded_key = key
    # if self._secure:
    #     encoded_key = keccak_hash(encoded_key)

    path_obj = NibblePath(encoded_key)
    zk_path = []

    for i, encoded_node in enumerate(proof_nodes):
        node = Node.decode(encoded_node)

        # ----------------------------
        # BRANCH NODE
        # ----------------------------
        if isinstance(node, Node.Branch):
            # Determine next nibble (if any)
            next_index = None
            if len(path_obj) > 0:
                next_index = path_obj.at(0)
                path_obj = path_obj.consume(1)

            children = []
            for ref in node.branches:
                if len(ref) == 0:
                    children.append(b"\x00" * 32)
                elif len(ref) < 32:
                    children.append(keccak_hash(ref))
                else:
                    children.append(ref)

            value = (
                keccak_hash(node.data)
                if node.data is not None
                else b"\x00" * 32
            )

            zk_path.append({
                "type": "branch",
                "children": children,      # 16 × bytes32
                "value": value,            # bytes32
                "next_index": next_index   # None if terminal
            })

        # ----------------------------
        # EXTENSION NODE
        # ----------------------------
        elif isinstance(node, Node.Extension):
            if not path_obj.starts_with(node.path):
                raise ValueError("Extension path mismatch")

            # Consume extension path
            path_obj = path_obj.consume(len(node.path))

            next_ref = node.next_ref
            if len(next_ref) < 32:
                next_hash = keccak_hash(next_ref)
            else:
                next_hash = next_ref

            zk_path.append({
                "type": "extension",
                "path": nibblepath_to_list(node.path),   # list of nibbles
                "next_hash": next_hash     # bytes32
            })

        # ----------------------------
        # LEAF NODE
        # ----------------------------
        elif isinstance(node, Node.Leaf):
            if node.path != path_obj:
                raise ValueError("Leaf path mismatch")

            zk_path.append({
                "type": "leaf",
                "path": nibblepath_to_list(node.path),   # list of nibbles
                "value": node.data         # raw value bytes
            })
            return zk_path

        else:
            raise TypeError(f"Unknown node type: {type(node)}")

    raise ValueError("Proof ended without reaching a leaf")

def rehash_proof_path_with_poseidon(zk_path):
    """
    Convert a Keccak-based zk_path into a Poseidon-based one.
    """

    def h(*vals):
        ints = [PrivVal(int.from_bytes(v, "big")) for v in vals]
        return poseidon_hash(ints)[0]

    new_path = []

    for node in zk_path:
        if node["type"] == "branch":
            children = [h(c) for c in node["children"]]
            value = h(node["value"])

            new_path.append({
                "type": "branch",
                "children": children,
                "value": value,
                "next_index": node["next_index"]
            })

        elif node["type"] == "extension":
            new_path.append({
                "type": "extension",
                "path": node["path"],
                "next_hash": h(node["next_hash"])
            })

        elif node["type"] == "leaf":
            new_path.append({
                "type": "leaf",
                "path": node["path"],
                "value": node["value"]
            })

    return new_path

def nibblepath_to_list(path: NibblePath) -> list[int]:
    return [PrivVal(path.at(i)) for i in range(len(path))]

@snark
def generate_zk_proof(
    values: list[bytes],
    keys: list[bytes],
    root_hash: bytes,
    proofs,
    setup_object=None
):

    # pub_root = poseidon_hash([PubVal(int.from_bytes(root_hash, "big"))])[0]

    for key, value, proof in zip(keys, values, proofs):
        # zk_path = proof_tree_to_zk_path(proof, key)
        zk_path = serialize_proof_tree_poseidon(proof, key)
        pub_root = zk_path[0]["poseidon_hash"]
        # path = rehash_proof_path_with_poseidon(zk_path)
        _prove_mpt_membership(
            value,
            pub_root,
            zk_path
        )
    
    # snark.prove()

    # return {
    #     "public": {
    #         "root": root_hash,
    #         "keys": keys,
    #         "values": values
    #     },
    #     "proof": snark.export_proof()
    # }


def _prove_mpt_membership(value, root_pub, path):

    cur = root_pub

    for node in path:

        if node["type"] == "branch":
            children = node["children"]
            value_ref = node["value"]
            # idx = PrivVal(node["next_index"])

            # verify branch hash
            branch_hash = poseidon_hash(children + value_ref)

            if isinstance(cur, list) and isinstance(branch_hash, list):
                branch_hash[0].assert_eq(cur[0])
            elif isinstance(cur, LinComb) and isinstance(branch_hash, LinComb):
                branch_hash.assert_eq(cur)
            else:
                print('branch_hash:', branch_hash)
                print('cur:', cur)
                raise TypeError("Mismatched types in branch hash comparison")

            # # one-hot child selection
            # selectors = [PrivVal(0) for _ in range(16)]
            # sum(selectors).assert_eq(1)
            # idx.assert_eq(sum(i * selectors[i] for i in range(16)))

            # cur = sum(children[i] * selectors[i] for i in range(16))
            cur = [children[node["next_index"]]]

        elif node["type"] == "extension":
            path = node["path"]
            next_hash = node["next_hash"]

            ext_hash = poseidon_hash(path+next_hash)
            # ext_hash[0].assert_eq(cur[0])
            if isinstance(cur, list) and isinstance(ext_hash, list):
                ext_hash[0].assert_eq(cur[0])
            elif isinstance(cur, LinComb) and isinstance(ext_hash, LinComb):
                ext_hash.assert_eq(cur)
            else:
                raise TypeError("Mismatched types in extension hash comparison")

            cur = next_hash

        elif node["type"] == "leaf":
            path = node["path"]
            leaf_val = PubVal(int.from_bytes(value, "big"))

            leaf_hash = poseidon_hash(path+[leaf_val])
            # leaf_hash[0].assert_eq(cur[0])
            if isinstance(cur, list) and isinstance(leaf_hash, list):
                leaf_hash[0].assert_eq(cur[0])
            elif isinstance(cur, LinComb) and isinstance(leaf_hash, LinComb):
                leaf_hash.assert_eq(cur)
            else:
                raise TypeError("Mismatched types in leaf hash comparison")
            return

@register_prover("zksnarkmerkle")
class ZKSnarkMerkleProof(BaseProver):

    def __init__(self, setup_object=None):
        self.setup_object = setup_object
    
    
    def generate_proof(self, tree: MerklePatriciaTrie, keys: list[bytes]):
        values = [tree.get(key) for key in keys]
        proofs = [tree.get_proof_tree(key) for key in keys]
        root_hash = tree.root_hash()
        # root_hash = poseidon_hash(PubVal(int.from_bytes(root_hash_keccak, "big")).value.to_bytes(32, "big")).to_bytes(32, "big")
        generate_zk_proof(
            values,
            keys,
            root_hash,
            proofs
        )

        atexit._run_exitfuncs()
        # print(f"DEBUG: Constraints generated: {len(backend.constraints)}")
        # print(f"DEBUG: Public inputs: {len(backend.pubvals)}")

        return 'dummy_commitments', 'dummy_witness'  # Placeholder



