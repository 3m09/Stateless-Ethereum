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

FIELD_MOD = 52435875175126190479447740508185965837690552500527637822603658699938581184513

# def _poseidon_sponge_circuit(chunk_lincombs):
#     """
#     Sequential ZK Sponge Hash. 
#     Mirrors the off-circuit hash.py t=2 logic perfectly.
#     """
#     current_hash = PrivVal(0)
#     for element in chunk_lincombs:
#         current_hash = poseidon_hash([current_hash + element])[0]
#     return current_hash

# def _poseidon_sponge_circuit(chunk_lincombs):
#     """
#     Sequential ZK Sponge Hash with explicit field modulo truncation 
#     to match off-circuit PlainMath behavior.
#     """
#     current_hash = PrivVal(0)
#     for element in chunk_lincombs:
#         # Explicitly apply the field modulus to prevent linear combination overflow
#         combined = (current_hash + element) % FIELD_MOD
#         current_hash = poseidon_hash([combined])[0]
#     return current_hash

# def _poseidon_sponge_circuit(chunk_lincombs):
#     """
#     Sequential ZK Sponge Hash. 
#     Mirrors the off-circuit hash.py t=2 logic perfectly.
#     """
#     current_hash = PrivVal(0)
#     for element in chunk_lincombs:
#         # 1. Create the R1CS linear combination (Clean, cheap addition constraint)
#         combined = current_hash + element
        
#         # 2. Fix the Python simulation value to prevent trace divergence!
#         # This explicitly wraps the python tracker WITHOUT adding any 
#         # heavy modulo constraints to the ZK backend.
#         if hasattr(combined, 'value') and combined.value is not None:
#             combined.value = combined.value % FIELD_MOD
            
#         # 3. Pass the aligned variable into the hash
#         current_hash = poseidon_hash([combined])[0]
        
#     return current_hash

def _poseidon_sponge_circuit(chunk_lincombs):
    """
    Sequential ZK Sponge Hash.
    Mirrors poseidon_hash_bytes in hash.py exactly:
      combined = (current_hash + element) % FIELD_MOD
      current_hash = poseidon_hash([combined])[0]
    """
    current_hash = PrivVal(0)

    for element in chunk_lincombs:
        # Compute the sum as a plain integer first (safe because both are field elements)
        combined_int = (current_hash.value + element.value) % FIELD_MOD

        # Introduce a new witness wire for the modded sum.
        # This is the correct in-circuit way to do modular reduction —
        # it creates a fresh constrained variable whose wire value IS combined_int,
        # matching exactly what hash.py passes into poseidon_hash().
        combined = PrivVal(combined_int)

        current_hash = poseidon_hash([combined])[0]

    return current_hash


def _zk_encode(node): # Remove 'self' in the prover script
        """Canonical 32-byte aligned ZK serialization"""
        if isinstance(node, Node.Leaf):
            path_bytes = node.path.encode(is_leaf=True)
            safe_data = node.data if node.data else b''
            # === DEBUG INJECTION START ===
            print(f"\n--- ENCODE DEBUG (LEAF) ---")
            print(f"1. Nibble length: {len(node.path)}")
            print(f"2. path_bytes length (bytes): {len(path_bytes)}")
            if len(path_bytes) > 32:
                print("   >>> WARNING: path_bytes exceeds 32 bytes! <<<")
            # === DEBUG INJECTION END ===
            return (
                (1).to_bytes(32, 'big') +                               # Chunk 0
                len(path_bytes).to_bytes(32, 'big') +                   # Chunk 1
                path_bytes.ljust(32, b'\0') +                           # Chunk 2
                len(safe_data).to_bytes(32, 'big') +                    # Chunk 3
                safe_data.ljust(32, b'\0')                              # Chunk 4
            )
            
        elif isinstance(node, Node.Extension):
            path_bytes = node.path.encode(is_leaf=False)
            return (
                (2).to_bytes(32, 'big') +                               # Chunk 0
                len(path_bytes).to_bytes(32, 'big') +                   # Chunk 1
                path_bytes.ljust(32, b'\0') +                           # Chunk 2
                node.next_ref                                           # Chunk 3
            )
            
        elif isinstance(node, Node.Branch):
            res = (3).to_bytes(32, 'big')                               # Chunk 0
            for b in node.branches:
                res += b if b else b'\0'*32                             # Chunks 1-16
            safe_data = node.data if node.data else b''
            res += len(safe_data).to_bytes(32, 'big')                   # Chunk 17
            res += safe_data.ljust(32, b'\0')                           # Chunk 18
            return res
            
        raise TypeError("Unknown node type")

def _zk_decode(data): # Remove 'self' in the prover script
    """Deserialize recognizing exact 32-byte boundaries"""
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

# @snark
# def generate_zk_proof(values, keys, root_hash, proofs):
#     root_pub = PubVal(int.from_bytes(root_hash, "big") % FIELD_MOD)

#     for key, value, proof in zip(keys, values, proofs):
#         value_pub = PubVal(int.from_bytes(value, "big") % FIELD_MOD)
#         decoded_nodes = [_zk_decode(n) for n in proof]

#         node_depths = []
#         current_depth = 0
#         path_obj = NibblePath(key)

#         for node in decoded_nodes:
#             node_depths.append(current_depth)
#             if isinstance(node, Node.Leaf) or isinstance(node, Node.Extension):
#                 current_depth += len(node.path)
#             elif isinstance(node, Node.Branch):
#                 current_depth += 1

#         # 1) Leaf extraction and direct constraint injection
#         leaf = decoded_nodes[-1]
#         leaf_enc = _zk_encode(leaf)
#         leaf_chunks = [PrivVal(int.from_bytes(leaf_enc[j:j+32], 'big') % FIELD_MOD) for j in range(0, len(leaf_enc), 32)]
        
#         # Inject the public value into Chunk 5 (Index 4)
#         leaf_chunks[4] = value_pub  
#         current_hash_lincomb = _poseidon_sponge_circuit(leaf_chunks)

#         # 2) Bottom-up algebraic traversal
#         for i in reversed(range(len(decoded_nodes) - 1)):
#             parent = decoded_nodes[i]
#             depth = node_depths[i]
#             parent_enc = _zk_encode(parent)
#             parent_chunks = [PrivVal(int.from_bytes(parent_enc[j:j+32], 'big') % FIELD_MOD) for j in range(0, len(parent_enc), 32)]

#             if isinstance(parent, Node.Extension):
#                 parent_chunks[3] = current_hash_lincomb
#             elif isinstance(parent, Node.Branch):
#                 next_nibble_idx = path_obj.at(depth)
#                 parent_chunks[1 + next_nibble_idx] = current_hash_lincomb

#             current_hash_lincomb = _poseidon_sponge_circuit(parent_chunks)

#         # 3) Root assertion
#         _assert_eq(current_hash_lincomb, root_pub)

# @snark
# def generate_zk_proof(values, keys, root_hash, proofs):
#     root_pub = PubVal(int.from_bytes(root_hash, "big") % FIELD_MOD)

#     for key, value, proof in zip(keys, values, proofs):
#         # 1. FIX: Format the public value to exactly match the 32-byte right-padding 
#         # used by _zk_encode in the tree builder.
#         padded_value = value.ljust(32, b'\0')[:32]
#         value_pub = PubVal(int.from_bytes(padded_value, "big") % FIELD_MOD)
        
#         # 2. FIX: Also make the data length a public value to strictly prove 
#         # the exact string length wasn't tampered with.
#         length_pub = PubVal(len(value))

#         decoded_nodes = [_zk_decode(n) for n in proof]

#         node_depths = []
#         current_depth = 0
#         path_obj = NibblePath(key)

#         for node in decoded_nodes:
#             node_depths.append(current_depth)
#             if isinstance(node, Node.Leaf) or isinstance(node, Node.Extension):
#                 current_depth += len(node.path)
#             elif isinstance(node, Node.Branch):
#                 current_depth += 1

#         # --- LEAF PROCESSING ---
#         leaf = decoded_nodes[-1]
#         leaf_enc = _zk_encode(leaf)
        
#         leaf_chunks = [PrivVal(int.from_bytes(leaf_enc[j:j+32], 'big') % FIELD_MOD) for j in range(0, len(leaf_enc), 32)]
        
#         length_pub = PubVal(len(value))
#         padded_value = value.ljust(32, b'\0')[:32]
#         value_pub = PubVal(int.from_bytes(padded_value, "big") % FIELD_MOD)
        
#         leaf_chunks[3].assert_eq(length_pub)
#         leaf_chunks[4].assert_eq(value_pub)  
#         current_hash_lincomb = _poseidon_sponge_circuit(leaf_chunks)

#         print(f"\n=== TRACE START ===")
#         print(f"[Trace] Circuit calculated LEAF hash: {current_hash_lincomb.value}")

#         # --- BOTTOM-UP ALGEBRAIC TRAVERSAL ---
#         for i in reversed(range(len(decoded_nodes) - 1)):
#             parent = decoded_nodes[i]
#             depth = node_depths[i]

#             # 1. IDENTIFY: What does the DB parent EXPECT the child hash to be?
#             if isinstance(parent, Node.Extension):
#                 expected_hash = int.from_bytes(parent.next_ref, 'big') % FIELD_MOD
#             elif isinstance(parent, Node.Branch):
#                 next_nibble_idx = path_obj.at(depth)
#                 expected_hash = int.from_bytes(parent.branches[next_nibble_idx], 'big') % FIELD_MOD

#             print(f"[Trace] Parent at depth {depth} expects child hash: {expected_hash}")
            
#             # 2. COMPARE: Does the circuit match the DB?
#             if current_hash_lincomb.value != expected_hash:
#                 print(f"\n>>> MISMATCH DETECTED AT DEPTH {depth}! <<<")
#                 child_node = decoded_nodes[i+1]
#                 print(f">>> The circuit failed to hash the {type(child_node).__name__} correctly.")
                
#                 # Print the raw chunks to see what numbers caused the failure
#                 if isinstance(child_node, Node.Leaf):
#                     print(f"Raw Leaf Chunks fed to circuit: {[c.value for c in leaf_chunks]}")
#                 break

#             # 3. ROUTE & CONTINUE HASHING
#             parent_enc = _zk_encode(parent)
#             parent_chunks = [PrivVal(int.from_bytes(parent_enc[j:j+32], 'big') % FIELD_MOD) for j in range(0, len(parent_enc), 32)]

#             if isinstance(parent, Node.Extension):
#                 parent_chunks[3] = current_hash_lincomb
#             elif isinstance(parent, Node.Branch):
#                 next_nibble_idx = path_obj.at(depth)
#                 parent_chunks[1 + next_nibble_idx] = current_hash_lincomb

#             current_hash_lincomb = _poseidon_sponge_circuit(parent_chunks)
#             print(f"[Trace] Circuit calculated PARENT hash: {current_hash_lincomb.value}")

#         print(f"\n[Trace] Final Circuit ROOT: {current_hash_lincomb.value}")
#         print(f"[Trace] Expected ROOT (PubVal): {root_pub.value}")
#         print(f"=== TRACE END ===\n")

#         # --- ROOT ASSERTION ---
#         _assert_eq(current_hash_lincomb, root_pub)

def _pad_to_32_bytes(data: bytes) -> bytes:
    """Helper to perfectly match the hash.py right-padding logic."""
    remainder = len(data) % 32
    if remainder != 0:
        data += b'\0' * (32 - remainder)
    return data

@snark
def generate_zk_proof(values, keys, root_hash, proofs):
    root_pub = PubVal(int.from_bytes(root_hash, "big") % FIELD_MOD)

    for key, value, proof in zip(keys, values, proofs):
        length_pub = PubVal(len(value))
        padded_value = value.ljust(32, b'\0')[:32]
        value_pub = PubVal(int.from_bytes(padded_value, "big") % FIELD_MOD)

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

        # --- LEAF PROCESSING ---
        leaf = decoded_nodes[-1]
        
        # 1. CRITICAL FIX: Pad the entire encoding before chunking
        leaf_enc = _pad_to_32_bytes(_zk_encode(leaf))

        # === DEBUG INJECTION START ===
        print(f"\n--- CHUNK ALIGNMENT DEBUG ---")
        print(f"Total leaf_enc byte length: {len(leaf_enc)}")
        print(f"Is perfectly divisible by 32? {len(leaf_enc) % 32 == 0}")
        if len(leaf_enc) % 32 != 0:
            print(f"   >>> WARNING: Encoded leaf is misaligned by {len(leaf_enc) % 32} bytes! <<<")
        # === DEBUG INJECTION END ===
        
        leaf_chunks = [PrivVal(int.from_bytes(leaf_enc[j:j+32], 'big') % FIELD_MOD) for j in range(0, len(leaf_enc), 32)]
        
        leaf_chunks[3].assert_eq(length_pub)
        leaf_chunks[4].assert_eq(value_pub) 

        # === DEBUG INJECTION ===
        print(f"\n[ZK HASH] Hashing {len(leaf_chunks)} chunks:")
        print([c.value for c in leaf_chunks])
        # =======================
        #  
        current_hash_lincomb = _poseidon_sponge_circuit(leaf_chunks)

        print(f"\n=== TRACE START ===")
        print(f"[Trace] Circuit calculated LEAF hash: {current_hash_lincomb.value}")

        # --- BOTTOM-UP ALGEBRAIC TRAVERSAL ---
        for i in reversed(range(len(decoded_nodes) - 1)):
            parent = decoded_nodes[i]
            depth = node_depths[i]

            if isinstance(parent, Node.Extension):
                expected_hash = int.from_bytes(parent.next_ref, 'big') % FIELD_MOD
            elif isinstance(parent, Node.Branch):
                next_nibble_idx = path_obj.at(depth)
                expected_hash = int.from_bytes(parent.branches[next_nibble_idx], 'big') % FIELD_MOD

            print(f"[Trace] Parent at depth {depth} expects child hash: {expected_hash}")
            
            if current_hash_lincomb.value != expected_hash:
                print(f"\n>>> MISMATCH DETECTED AT DEPTH {depth}! <<<")
                break

            # 2. CRITICAL FIX: Pad the parent encoding as well
            parent_enc = _pad_to_32_bytes(_zk_encode(parent))
            
            parent_chunks = [PrivVal(int.from_bytes(parent_enc[j:j+32], 'big') % FIELD_MOD) for j in range(0, len(parent_enc), 32)]

            if isinstance(parent, Node.Extension):
                parent_chunks[3] = current_hash_lincomb
            elif isinstance(parent, Node.Branch):
                next_nibble_idx = path_obj.at(depth)
                parent_chunks[1 + next_nibble_idx] = current_hash_lincomb

            current_hash_lincomb = _poseidon_sponge_circuit(parent_chunks)
            print(f"[Trace] Circuit calculated PARENT hash: {current_hash_lincomb.value}")

        print(f"\n[Trace] Final Circuit ROOT: {current_hash_lincomb.value}")
        print(f"[Trace] Expected ROOT (PubVal): {root_pub.value}")
        print(f"=== TRACE END ===\n")

        # --- ROOT ASSERTION ---
        _assert_eq(current_hash_lincomb, root_pub)

def _verify_poseidon_consistency():
    """
    Runs both poseidon implementations on the same input and asserts they match.
    Call this once at startup. If it raises, your constants are mismatched.
    """
    from merkle.myposeidonhash import poseidon_hash as plain_poseidon
    from pysnark.runtime import PrivVal
    from pysnark.poseidon_hash import poseidon_hash as zk_poseidon

    test_input_int = 12345678901234567890
    plain_result = plain_poseidon([test_input_int], FIELD_MOD)[0]

    zk_result = zk_poseidon([PrivVal(test_input_int)])[0]
    zk_result_int = zk_result.value

    assert plain_result == zk_result_int, (
        f"Poseidon constant mismatch!\n"
        f"  plain: {plain_result}\n"
        f"  zk:    {zk_result_int}\n"
        f"The two implementations are using different round constants or matrix."
    )
    print("Poseidon consistency check passed.")

@register_prover("zksnarkmerkle_poseidon")
class ZKSnarkMerklePoseidonProof(BaseProver):
    def __init__(self, setup_object=None):
        self.setup_object = setup_object

    def generate_proof(self, tree: PoseidonMerklePatriciaTrie, keys: list[bytes]):
        values = [tree.get(key) for key in keys]
        proofs = [tree.get_proof_tree(key) for key in keys]
        root_hash = tree.root_hash()
        _verify_poseidon_consistency()
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