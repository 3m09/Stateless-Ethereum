from pysnark.runtime import PrivVal, PubVal, snark, LinComb
from pysnark.poseidon_hash import poseidon_hash
from registry.provers import BaseProver, register_prover
from tree.poseidon_merkle_tree import PoseidonMerklePatriciaTrie
from merkle.node import Node
from merkle.nibble_path import NibblePath
import atexit
import os
from zkSNARK.zk_encoder_decoder import _zk_encode, _zk_decode

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

# def _poseidon_sponge_circuit(chunk_lincombs):
#     """
#     Sequential ZK Sponge Hash.
#     Mirrors poseidon_hash_bytes in hash.py exactly:
#       combined = (current_hash + element) % FIELD_MOD
#       current_hash = poseidon_hash([combined])[0]
#     """
#     current_hash = PrivVal(0)

#     for element in chunk_lincombs:
#         # Compute the sum as a plain integer first (safe because both are field elements)
#         combined_int = (current_hash.value + element.value) % FIELD_MOD

#         # Introduce a new witness wire for the modded sum.
#         # This is the correct in-circuit way to do modular reduction —
#         # it creates a fresh constrained variable whose wire value IS combined_int,
#         # matching exactly what hash.py passes into poseidon_hash().
#         combined = PrivVal(combined_int)

#         current_hash = poseidon_hash([combined])[0]

#     return current_hash
def _poseidon_sponge_circuit(chunk_lincombs):
    """
    Sequential ZK Sponge Hash.
    """
    # Start with a standard, free Python integer
    current_hash = 0 

    for element in chunk_lincombs:
        # CRITICAL FIX: Flip the addition order!
        # element (LinComb) + current_hash (int) works perfectly.
        # It creates a new constrained LinComb with zero overhead.
        combined = element + current_hash

        # Pass it into the hash
        current_hash = poseidon_hash([combined])[0]

    return current_hash

def _pad_to_32_bytes(data: bytes) -> bytes:
    """Helper to perfectly match the hash.py right-padding logic."""
    remainder = len(data) % 32
    if remainder != 0:
        data += b'\0' * (32 - remainder)
    return data

# @snark
# def generate_zk_proof(values, keys, root_hash, proofs):
#     root_pub = PubVal(int.from_bytes(root_hash, "big") % FIELD_MOD)

#     for key, value, proof in zip(keys, values, proofs):
#         # length_pub = PubVal(len(value))
#         # padded_value = value.ljust(32, b'\0')[:32]
#         # value_pub = PubVal(int.from_bytes(padded_value, "big") % FIELD_MOD)

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
        
#         # 1. CRITICAL FIX: Pad the entire encoding before chunking
#         leaf_enc = _pad_to_32_bytes(_zk_encode(leaf))

#         # === DEBUG INJECTION START ===
#         print(f"\n--- CHUNK ALIGNMENT DEBUG ---")
#         print(f"Total leaf_enc byte length: {len(leaf_enc)}")
#         print(f"Is perfectly divisible by 32? {len(leaf_enc) % 32 == 0}")
#         if len(leaf_enc) % 32 != 0:
#             print(f"   >>> WARNING: Encoded leaf is misaligned by {len(leaf_enc) % 32} bytes! <<<")
#         # === DEBUG INJECTION END ===
        
#         leaf_chunks = [PrivVal(int.from_bytes(leaf_enc[j:j+32], 'big') % FIELD_MOD) for j in range(0, len(leaf_enc), 32)]
        
#         # leaf_chunks[3].assert_eq(length_pub)
#         # leaf_chunks[4].assert_eq(value_pub)

#         # === DEBUG INJECTION ===
#         print(f"\n[ZK HASH] Hashing {len(leaf_chunks)} chunks:")
#         print([c.value for c in leaf_chunks])
#         # =======================
#         #  
#         current_hash_lincomb = _poseidon_sponge_circuit(leaf_chunks)

#         # print(f"\n=== TRACE START ===")
#         # print(f"[Trace] Circuit calculated LEAF hash: {current_hash_lincomb.value}")

#         # --- BOTTOM-UP ALGEBRAIC TRAVERSAL ---
#         for i in reversed(range(len(decoded_nodes) - 1)):
#             parent = decoded_nodes[i]
#             depth = node_depths[i]

#             if isinstance(parent, Node.Extension):
#                 expected_hash = int.from_bytes(parent.next_ref, 'big') % FIELD_MOD
#             elif isinstance(parent, Node.Branch):
#                 next_nibble_idx = path_obj.at(depth)
#                 expected_hash = int.from_bytes(parent.branches[next_nibble_idx], 'big') % FIELD_MOD

#             # print(f"[Trace] Parent at depth {depth} expects child hash: {expected_hash}")
            
#             if current_hash_lincomb.value != expected_hash:
#                 print(f"\n>>> MISMATCH DETECTED AT DEPTH {depth}! <<<")
#                 break

#             # 2. CRITICAL FIX: Pad the parent encoding as well
#             parent_enc = _pad_to_32_bytes(_zk_encode(parent))
            
#             parent_chunks = [PrivVal(int.from_bytes(parent_enc[j:j+32], 'big') % FIELD_MOD) for j in range(0, len(parent_enc), 32)]

#             if isinstance(parent, Node.Extension):
#                 parent_chunks[3] = current_hash_lincomb
#             elif isinstance(parent, Node.Branch):
#                 next_nibble_idx = path_obj.at(depth)
#                 parent_chunks[1 + next_nibble_idx] = current_hash_lincomb

#             current_hash_lincomb = _poseidon_sponge_circuit(parent_chunks)
#             # print(f"[Trace] Circuit calculated PARENT hash: {current_hash_lincomb.value}")

#         print(f"\n[Trace] Final Circuit ROOT: {current_hash_lincomb.value}")
#         print(f"[Trace] Expected ROOT (PubVal): {root_pub.value}")
#         print(f"=== TRACE END ===\n")

#         # --- ROOT ASSERTION ---
#         _assert_eq(current_hash_lincomb, root_pub)

@snark
def generate_zk_proof(values, keys, root_hash, proofs):
    root_pub = PubVal(int.from_bytes(root_hash, "big") % FIELD_MOD)

    for key, value, proof in zip(keys, values, proofs):
        
        # 1. UNCOMMENT AND ENFORCE THE PUBLIC VALUES
        # This is how we force the circuit to prove the specific value!
        length_pub = PubVal(len(value))
        # padded_value = value.ljust(32, b'\0')[:32]
        # value_pub = PubVal(int.from_bytes(padded_value, "big") % FIELD_MOD)
        padded_value = value.ljust(96, b'\0')
        
        val_pub_0 = PubVal(int.from_bytes(padded_value[0:32], "big") % FIELD_MOD)
        val_pub_1 = PubVal(int.from_bytes(padded_value[32:64], "big") % FIELD_MOD)
        val_pub_2 = PubVal(int.from_bytes(padded_value[64:96], "big") % FIELD_MOD)

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
        leaf_enc = _pad_to_32_bytes(_zk_encode(leaf))
        
        leaf_chunks = [PrivVal(int.from_bytes(leaf_enc[j:j+32], 'big') % FIELD_MOD) for j in range(0, len(leaf_enc), 32)]
        
        # # 2. CONSTRAIN THE LEAF TO THE PUBLIC VALUE
        # # Instead of constructing a new leaf, we mathematically force the 
        # # prover's leaf to contain our exact public values.
        # leaf_chunks[4].assert_eq(length_pub)
        # leaf_chunks[5].assert_eq(value_pub)

        # 2. CONSTRAIN ALL 3 CHUNKS OF THE DATA
        leaf_chunks[4].assert_eq(length_pub)
        leaf_chunks[5].assert_eq(val_pub_0)
        leaf_chunks[6].assert_eq(val_pub_1)
        leaf_chunks[7].assert_eq(val_pub_2)

        current_hash_lincomb = _poseidon_sponge_circuit(leaf_chunks)

        # --- BOTTOM-UP ALGEBRAIC TRAVERSAL ---
        for i in reversed(range(len(decoded_nodes) - 1)):
            parent = decoded_nodes[i]
            depth = node_depths[i]
            
            parent_enc = _pad_to_32_bytes(_zk_encode(parent))
            parent_chunks = [PrivVal(int.from_bytes(parent_enc[j:j+32], 'big') % FIELD_MOD) for j in range(0, len(parent_enc), 32)]

            # 3. CRITICAL FIX: CONSTRAIN INSTEAD OF OVERWRITE
            # Use .assert_eq() to link the child hash to the parent's pointer.
            # This consumes the PrivVal and prevents the 'unconstrained' error!
            if isinstance(parent, Node.Extension):
                parent_chunks[4].assert_eq(current_hash_lincomb) 
            elif isinstance(parent, Node.Branch):
                next_nibble_idx = path_obj.at(depth)
                parent_chunks[1 + next_nibble_idx].assert_eq(current_hash_lincomb)

            # Pass the constrained chunks into the sponge
            current_hash_lincomb = _poseidon_sponge_circuit(parent_chunks)

        # --- ROOT ASSERTION ---
        _assert_eq(current_hash_lincomb, root_pub)

def _verify_poseidon_consistency():
    """
    Runs both poseidon implementations on the same input and asserts they match.
    Call this once at startup. If it raises, your constants are mismatched.
    """
    from zkSNARK.myposeidonhash import poseidon_hash as plain_poseidon
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

@register_prover("zksnarkmerkle")
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