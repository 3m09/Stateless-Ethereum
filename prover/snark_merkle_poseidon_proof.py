import json
import subprocess
import os
import math
import atexit
from registry.provers import BaseProver, register_prover
from tree.poseidon_merkle_tree import PoseidonMerklePatriciaTrie
from merkle.node import Node
from merkle.nibble_path import NibblePath
<<<<<<< HEAD
=======
import atexit
import os
>>>>>>> refs/remotes/origin/stark_dev
from zkSNARK.zk_encoder_decoder import _zk_encode, _zk_decode

# ==============================================================================
# CONFIGURATION
# ==============================================================================
CIRCUIT_DIR = "circuit_directory"
WITNESS_GEN = os.path.join(CIRCUIT_DIR, "mpt_batch_16_cpp", "mpt_batch_16")  # The Circom C++ executable for batched proofs
PROVER_BIN = "rapidsnark/package/bin/prover"
ZKEY_PATH = "mpt_batch_16.zkey"
BUILD_DIR = "snark_proofs"

<<<<<<< HEAD
FIELD_MOD = 21888242871839275222246405745257275088548364400416034343698204186575808495617
MAX_DEPTH = 10
MAX_CHUNKS = 40
BATCH_SIZE = 4 # Poseidon Arity

# ------------------------------------------------------------------------------
# CHANGE THIS TO TEST DIFFERENT BATCH SIZES (Must match mpt.circom main component)
# ------------------------------------------------------------------------------
KEYS_BATCH_SIZE = 16

os.makedirs(BUILD_DIR, exist_ok=True)

def _pad_to_32_bytes(data: bytes) -> bytes:
    remainder = len(data) % 32
    if remainder != 0:
        data += b"\0" * (32 - remainder)
    return data
=======
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
>>>>>>> refs/remotes/origin/stark_dev

def _get_node_data(node) -> tuple[list[str], str]:
    enc = _pad_to_32_bytes(_zk_encode(node))
    chunks = [str(int.from_bytes(enc[j : j + 32], "big") % FIELD_MOD) for j in range(0, len(enc), 32)]
    actual_batches = str(math.ceil(len(chunks) / BATCH_SIZE))
    padded_chunks = chunks + ["0"] * (MAX_CHUNKS - len(chunks))
    if len(padded_chunks) > MAX_CHUNKS:
        raise ValueError(f"Node exceeds MAX_CHUNKS ({MAX_CHUNKS}).")
    return padded_chunks, actual_batches

<<<<<<< HEAD
=======
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

>>>>>>> refs/remotes/origin/stark_dev
@register_prover("zksnarkmerkle")
class ZKSnarkMerklePoseidonProof(BaseProver):
    def __init__(self, setup_object=None):
        self.setup_object = setup_object

    def generate_proof(self, tree: PoseidonMerklePatriciaTrie, keys: list[bytes]):
        values = [tree.get(key) for key in keys]
        proofs = [tree.get_proof_tree(key) for key in keys]
        root_hash = tree.root_hash()
<<<<<<< HEAD
        
        proof_files = []
        public_files = []
=======
        _verify_poseidon_consistency()
        generate_zk_proof(values, keys, root_hash, proofs)
        atexit._run_exitfuncs()
        return "dummy_commitments", "dummy_witness"
>>>>>>> refs/remotes/origin/stark_dev

        # Process the list of keys in chunks of KEYS_BATCH_SIZE
        for chunk_idx, i in enumerate(range(0, len(keys), KEYS_BATCH_SIZE)):
            chunk_keys = keys[i : i + KEYS_BATCH_SIZE]
            chunk_values = values[i : i + KEYS_BATCH_SIZE]
            chunk_proofs = proofs[i : i + KEYS_BATCH_SIZE]

            # Pad the chunk by duplicating the last valid key if it's too small
            while len(chunk_keys) < KEYS_BATCH_SIZE:
                chunk_keys.append(chunk_keys[-1])
                chunk_values.append(chunk_values[-1])
                chunk_proofs.append(chunk_proofs[-1])

            # Initialize the batched JSON structure
            batch_input = {
                "root_pub": [], "length_pub": [], "val_pub_0": [], "val_pub_1": [], "val_pub_2": [],
                "actual_depth": [], "leaf_chunks": [], "leaf_batches": [],
                "node_types": [], "node_nibbles": [], "node_chunks": [], "node_batches": []
            }

            # Process every key in this batch
            for key, value, proof in zip(chunk_keys, chunk_values, chunk_proofs):
                root_pub = str(int.from_bytes(root_hash, "big") % FIELD_MOD)
                length_pub = str(len(value))
                
                padded_value = value.ljust(96, b"\0")
                val_pub_0 = str(int.from_bytes(padded_value[0:32],  "big") % FIELD_MOD)
                val_pub_1 = str(int.from_bytes(padded_value[32:64], "big") % FIELD_MOD)
                val_pub_2 = str(int.from_bytes(padded_value[64:96], "big") % FIELD_MOD)

                decoded_nodes = [_zk_decode(n) for n in proof]
                path_obj = NibblePath(key)
                
                leaf = decoded_nodes[-1]
                leaf_chunks, leaf_batches = _get_node_data(leaf)

                parent_nodes = decoded_nodes[:-1]
                actual_depth = len(parent_nodes)
                
                node_types, node_nibbles, node_chunks, node_batches = [], [], [], []
                
                current_depth = 0
                depths = []
                for node in parent_nodes:
                    depths.append(current_depth)
                    if isinstance(node, (Node.Leaf, Node.Extension)):
                        current_depth += len(node.path)
                    elif isinstance(node, Node.Branch):
                        current_depth += 1
                
                for parent, d in zip(reversed(parent_nodes), reversed(depths)):
                    chunks, batches = _get_node_data(parent)
                    
                    if isinstance(parent, Node.Extension):
                        node_types.append("0")
                        node_nibbles.append("0")
                    elif isinstance(parent, Node.Branch):
                        node_types.append("1")
                        node_nibbles.append(str(path_obj.at(d)))
                    else:
                        node_types.append("0")
                        node_nibbles.append("0")
                        
                    node_chunks.append(chunks)
                    node_batches.append(batches)

                padding_needed = MAX_DEPTH - actual_depth
                node_types.extend(["0"] * padding_needed)
                node_nibbles.extend(["0"] * padding_needed)
                node_batches.extend(["0"] * padding_needed)
                node_chunks.extend([["0"] * MAX_CHUNKS] * padding_needed)

                # Append data to the arrays
                batch_input["root_pub"].append(root_pub)
                batch_input["length_pub"].append(length_pub)
                batch_input["val_pub_0"].append(val_pub_0)
                batch_input["val_pub_1"].append(val_pub_1)
                batch_input["val_pub_2"].append(val_pub_2)
                batch_input["actual_depth"].append(str(actual_depth))
                batch_input["leaf_chunks"].append(leaf_chunks)
                batch_input["leaf_batches"].append(leaf_batches)
                batch_input["node_types"].append(node_types)
                batch_input["node_nibbles"].append(node_nibbles)
                batch_input["node_chunks"].append(node_chunks)
                batch_input["node_batches"].append(node_batches)

            # File Paths
            input_json_path = os.path.join(BUILD_DIR, f"input_batch_{chunk_idx}.json")
            witness_path = os.path.join(BUILD_DIR, f"witness_batch_{chunk_idx}.wtns")
            proof_path = os.path.join(BUILD_DIR, f"proof_batch_{chunk_idx}.json")
            public_path = os.path.join(BUILD_DIR, f"public_batch_{chunk_idx}.json")

            with open(input_json_path, "w") as f:
                json.dump(batch_input, f)

            print(f"\n[Batch {chunk_idx+1}] Generating Witness (Circom C++)...")
            subprocess.run([WITNESS_GEN, input_json_path, witness_path], check=True)

            print(f"[Batch {chunk_idx+1}] Generating Proof (RapidSnark)...")
            subprocess.run([PROVER_BIN, ZKEY_PATH, witness_path, proof_path, public_path], check=True)
            
            proof_files.append(proof_path)
            public_files.append(public_path)
        
        return proof_files, public_files

    def proof_size(self, proof_files, public_files) -> int:
        """
        Parses the JSON proof and physically packs the field elements into a 
        raw byte array exactly as they would be sent to an Ethereum EVM contract.
        Returns the true byte length.
        """
        total_size = 0
        for file_name in proof_files:
            if os.path.exists(file_name):
                with open(file_name, 'r') as f:
                    proof = json.load(f)
                    
                packed_bytes = bytearray()
                
                # 1. Pack pi_a (G1 Point: X, Y)
                packed_bytes.extend(int(proof["pi_a"][0]).to_bytes(32, "big"))
                packed_bytes.extend(int(proof["pi_a"][1]).to_bytes(32, "big"))
                
                # 2. Pack pi_b (G2 Point: X_im, X_re, Y_im, Y_re)
                # Note: Ethereum's precompile expects the imaginary part first
                packed_bytes.extend(int(proof["pi_b"][0][1]).to_bytes(32, "big"))
                packed_bytes.extend(int(proof["pi_b"][0][0]).to_bytes(32, "big"))
                packed_bytes.extend(int(proof["pi_b"][1][1]).to_bytes(32, "big"))
                packed_bytes.extend(int(proof["pi_b"][1][0]).to_bytes(32, "big"))
                
                # 3. Pack pi_c (G1 Point: X, Y)
                packed_bytes.extend(int(proof["pi_c"][0]).to_bytes(32, "big"))
                packed_bytes.extend(int(proof["pi_c"][1]).to_bytes(32, "big"))
                
                # The length of packed_bytes will be exactly 256
                total_size += len(packed_bytes)
                
        return total_size