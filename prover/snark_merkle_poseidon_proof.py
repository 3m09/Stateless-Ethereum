from pysnark.runtime import PrivVal, PubVal, snark, LinComb
from pysnark.poseidon_hash import poseidon_hash
from registry.provers import BaseProver, register_prover
from tree.poseidon_merkle_tree import PoseidonMerklePatriciaTrie
from merkle.node import Node
from merkle.nibble_path import NibblePath
import atexit
import os

def _assert_eq(a, b):
    if isinstance(a, list) and isinstance(b, list):
        a[0].assert_eq(b[0])
    elif isinstance(a, LinComb) and isinstance(b, LinComb):
        a.assert_eq(b)
    elif isinstance(a, list) and isinstance(b, LinComb):
        a[0].assert_eq(b)
    elif isinstance(a, LinComb) and isinstance(b, list):
        a.assert_eq(b[0])
    else:
        raise TypeError("Mismatched types in hash comparison")

FIELD_MOD = 21888242871839275222246405745257275088548364400416034343698204186575808495617

def _poseidon_sponge_circuit(chunk_lincombs):
    """
    Sequential ZK Sponge Hash. 
    Mirrors the off-circuit hash.py t=2 logic perfectly.
    """
    current_hash = PrivVal(0)
    for element in chunk_lincombs:
        current_hash = poseidon_hash([current_hash + element])[0]
    return current_hash

def _zk_encode(node):
    if isinstance(node, Node.Leaf):
        path_bytes = node.path.encode(is_leaf=True)
        safe_data = node.data if node.data else b''
        return (
            (1).to_bytes(32, 'big') +
            len(path_bytes).to_bytes(32, 'big') +
            path_bytes.ljust(32, b'\0') +
            len(safe_data).to_bytes(32, 'big') +
            safe_data.ljust(32, b'\0')
        )
    elif isinstance(node, Node.Extension):
        path_bytes = node.path.encode(is_leaf=False)
        return (
            (2).to_bytes(32, 'big') +
            len(path_bytes).to_bytes(32, 'big') +
            path_bytes.ljust(32, b'\0') +
            node.next_ref.ljust(32, b'\0')
        )
    elif isinstance(node, Node.Branch):
        res = (3).to_bytes(32, 'big')
        for b in node.branches:
            res += b if b else b'\0'*32
        safe_data = node.data if node.data else b''
        res += len(safe_data).to_bytes(32, 'big')
        res += safe_data.ljust(32, b'\0')
        return res
    raise TypeError("Unknown node type")

def _zk_decode(data):
    node_type = int.from_bytes(data[:32], 'big')
    if node_type == 1:
        path_len = int.from_bytes(data[32:64], 'big')
        path_bytes = data[64 : 64 + path_len]
        path, _ = NibblePath.decode_with_type(path_bytes)
        data_len = int.from_bytes(data[96:128], 'big')
        data_val = data[128 : 128 + data_len]
        return Node.Leaf(path, data_val)
    elif node_type == 2:
        path_len = int.from_bytes(data[32:64], 'big')
        path_bytes = data[64 : 64 + path_len]
        path, _ = NibblePath.decode_with_type(path_bytes)
        next_ref = data[96:128] 
        return Node.Extension(path, next_ref)
    elif node_type == 3:
        branches = []
        for i in range(16):
            b_bytes = data[32 + (i * 32) : 64 + (i * 32)]
            branches.append(b_bytes if b_bytes != b'\0'*32 else b'')
        data_len = int.from_bytes(data[544:576], 'big')
        data_val = data[576 : 576 + data_len]
        return Node.Branch(branches, data_val)
    raise ValueError(f"Unknown ZK node type: {node_type}")

@snark
def generate_zk_proof(values, keys, root_hash, proofs):
    root_pub = PubVal(int.from_bytes(root_hash, "big") % FIELD_MOD)

    for key, value, proof in zip(keys, values, proofs):
        value_pub = PubVal(int.from_bytes(value, "big") % FIELD_MOD)
        decoded_nodes = [_zk_decode(n) for n in proof]

        node_depths = []
        current_depth = 0
        path_obj = NibblePath(key)

        for node in decoded_nodes:
            node_depths.append(current_depth)
            if isinstance(node, Node.Leaf) or isinstance(node, Node.Extension):
                current_depth += len(node.path)
            elif isinstance(node, Node.Branch):
                current_depth += 1

        # 1) Leaf extraction and direct constraint injection
        leaf = decoded_nodes[-1]
        leaf_enc = _zk_encode(leaf)
        leaf_chunks = [PrivVal(int.from_bytes(leaf_enc[j:j+32], 'big') % FIELD_MOD) for j in range(0, len(leaf_enc), 32)]
        
        # Inject the public value into Chunk 5 (Index 4)
        leaf_chunks[4] = value_pub  
        current_hash_lincomb = _poseidon_sponge_circuit(leaf_chunks)

        # 2) Bottom-up algebraic traversal
        for i in reversed(range(len(decoded_nodes) - 1)):
            parent = decoded_nodes[i]
            depth = node_depths[i]
            parent_enc = _zk_encode(parent)
            parent_chunks = [PrivVal(int.from_bytes(parent_enc[j:j+32], 'big') % FIELD_MOD) for j in range(0, len(parent_enc), 32)]

            if isinstance(parent, Node.Extension):
                parent_chunks[3] = current_hash_lincomb
            elif isinstance(parent, Node.Branch):
                next_nibble_idx = path_obj.at(depth)
                parent_chunks[1 + next_nibble_idx] = current_hash_lincomb

            current_hash_lincomb = _poseidon_sponge_circuit(parent_chunks)

        # 3) Root assertion
        _assert_eq(current_hash_lincomb, root_pub)

@register_prover("zksnarkmerkle_poseidon")
class ZKSnarkMerklePoseidonProof(BaseProver):
    def __init__(self, setup_object=None):
        self.setup_object = setup_object

    def generate_proof(self, tree: PoseidonMerklePatriciaTrie, keys: list[bytes]):
        values = [tree.get(key) for key in keys]
        proofs = [tree.get_proof_tree(key) for key in keys]
        root_hash = tree.root_hash()
        generate_zk_proof(values, keys, root_hash, proofs)
        atexit._run_exitfuncs()
        return "dummy_commitments", "dummy_witness"

    def proof_size(self, commitments, witness) -> int:
        file_names = ["circuit.zkif", "computation.zkif"]
        total_size = 0
        for file_name in file_names:
            if os.path.exists(file_name):
                total_size += os.path.getsize(file_name)
        return total_size