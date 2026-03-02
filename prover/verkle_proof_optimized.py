from registry.provers import BaseProver, register_prover
from tree.verkle_tree import VerkleTree
from verkle.commitment_scheme import generate_quotient
from py_ecc import optimized_bls12_381 as b
from verkle.utils.multicombs import lincomb
from verkle.randomness_scheme import derive_r, derive_r_factor_hash
from verkle.hash_scheme import generate_root_bytes
from verkle.utils.key_to_path import _key_to_path

@register_prover("verkle_optimized")
class VerkleProofGenerator(BaseProver):

    def __init__(self, setup_object):
        self.setup_object = setup_object
        self.tree = None

    def generate_proof(self, tree: VerkleTree, keys: list[bytes]):
        self.tree = tree
        setup = self.setup_object.setup
        committee_root = tree.root.commitment_to_children
        
        # Generate a random r value for random linear combination
        r = derive_r(generate_root_bytes(committee_root), [_key_to_path(tree.width, k) for k in keys], b.curve_order)
        
        # Total polynomial that we are evaluating
        total_poly_evaluations = [0] * tree.width
        
        # Collect all commitments and build deduplication map
        commitment_list = []  # List of unique commitments
        commitment_map = {}   # Maps commitment hash to index
        proof_paths = []      # List of {key, commitment_indices}
        
        for key_idx, key in enumerate(keys):
            path = _key_to_path(tree.width, key)
            node = tree.root
            key_commitment_indices = []
            
            for i in range(len(path)):
                # Generate the quotient polynomial for this node
                child_values = []
                all_none = True
                for child_node in node.children:
                    if child_node is None:
                        child_values.append(0)
                    else:
                        all_none = False
                        child_values.append(int.from_bytes(child_node, byteorder='big'))
                
                P_over_Q = generate_quotient(child_values, path[i], self.setup_object)
                if all_none:
                    print('all children are None')
                
                # Add to the total polynomial with appropriate r^level factor
                r_factor = derive_r_factor_hash(generate_root_bytes(committee_root), path, i, b.curve_order)
                for j in range(tree.width):
                    total_poly_evaluations[j] = (total_poly_evaluations[j] + P_over_Q[j] * r_factor) % b.curve_order
                
                # Move to the next node
                if i < len(path) - 1:
                    # Get the child node
                    child = tree._make_tree_node(node.children[path[i]])
                    commitment = child.commitment_to_children
                    
                    # Create a hashable key for deduplication (convert to tuple)
                    comm_key = (int(commitment[0]), int(commitment[1]))
                    
                    # Check if we've seen this commitment before
                    if comm_key not in commitment_map:
                        commitment_map[comm_key] = len(commitment_list)
                        commitment_list.append(commitment)
                    
                    # Record the index of this commitment for this key's path
                    key_commitment_indices.append(commitment_map[comm_key])
                    node = child
            
            # Store the commitment indices for this key
            proof_paths.append({
                'key_idx': key_idx,
                'commitment_indices': key_commitment_indices
            })
        
        # Generate a polynomial commitment for the result
        witness = b.normalize(lincomb(setup[2], total_poly_evaluations, b.add, b.Z1))
        
        # Return deduplicated proof
        deduplicated_proof = {
            'commitments': commitment_list,
            'proof_paths': proof_paths
        }
        
        return deduplicated_proof, witness
    
    def proof_size(self, deduplicated_proof, witness) -> int:
        commitment_list = deduplicated_proof['commitments']
        # Each commitment is ~64 bytes (2 field elements, 32 bytes each)
        # Witness is ~48 bytes (G1 point in BLS12-381)
        num_commitments = len(commitment_list)
        commitment_size = num_commitments * 64
        witness_size = 48
        
        # Size of proof paths (key + indices)
        proof_paths_size = 0
        for path_info in deduplicated_proof['proof_paths']:
            key_idx_size = len(path_info['key_idx'].to_bytes(4, byteorder='big'))  # assuming max 2^32 keys
            # Each index is stored as int (assume 1-2 bytes for typical trees)
            indices_size = len(path_info['commitment_indices']) * 2
            proof_paths_size += key_idx_size + indices_size
        
        return commitment_size + witness_size + proof_paths_size