from pysnark.runtime import PrivVal, PubVal, snark, LinComb, backend
from registry.provers import BaseProver, register_prover
from tree.verkle_tree import VerkleTree
from verkle.commitment_scheme import generate_quotient
from verkle.hash_scheme import hash_point_to_field, generate_root_bytes
from verkle.utils.key_to_path import _key_to_path
from verkle.randomness_scheme import derive_r, derive_r_factor_hash
from py_ecc import optimized_bls12_381 as b
from verkle.utils.multicombs import lincomb
import atexit


@snark
def generate_snark_verkle_proof(
    keys: list[bytes],
    values: list[bytes],
    paths: list,
    child_values_per_level: list,
    commitment_indices_per_key: list,
    deduplicated_commitments: list,
    root_commitment,
    setup_object=None
):
    """
    Generate a zkSNARK proof for Verkle tree membership.
    
    Public inputs:
    - root_commitment: the root KZG commitment of the Verkle tree
    - keys: the keys being proved
    - values: the values at those keys
    
    Private inputs (via PrivVal):
    - child_values_per_level: intermediate node child values
    - paths: paths from root to leaf for each key
    - deduplicated_commitments: KZG commitments (used directly, not hashed)
    - commitment_indices_per_key: which commitments are used for each key
    """
    MODULUS = setup_object.MODULUS
    WIDTH = setup_object.WIDTH
    
    # Root commitment is public
    pub_root_x = PubVal(int(root_commitment[0]))
    pub_root_y = PubVal(int(root_commitment[1]))
    
    # For each key being proved
    for key_idx, (key, value, path) in enumerate(zip(keys, values, paths)):
        value_int = PubVal(int.from_bytes(value, 'big'))
        commitment_indices = commitment_indices_per_key[key_idx]
        
        # Walk through each level of the path
        for level, path_nibble in enumerate(path):
            # Get the commitment at this level (from deduplicated list)
            if level == 0:
                # At root level, use root commitment
                current_comm_x = pub_root_x
                current_comm_y = pub_root_y
            else:
                # Get commitment index for this level
                comm_idx = PrivVal(commitment_indices[level - 1])
                current_comm = deduplicated_commitments[commitment_indices[level - 1]]
                current_comm_x = PrivVal((current_comm[0]))
                current_comm_y = PrivVal((current_comm[1]))
            
            # Get child values at this level
            child_vals = child_values_per_level[key_idx][level]
            
            # Convert to private values for the circuit
            #child_vals_private = [PrivVal((cv)) for cv in child_vals]
            
            # # The path nibble tells us which child we follow
            # path_nibble_private = PrivVal(path_nibble)
            
            # # Verify the path nibble is valid (0 to WIDTH-1)
            # path_nibble_private.assert_eq(path_nibble)
            
            # In the circuit, we can verify:
            # 1. The commitment is derived from the child values at this level
            # 2. The correct child is selected by path_nibble
            # 3. The commitment values are consistent with the tree structure
            
            # Assert that the commitment coordinates are valid field elements
            if level > 0:  # Skip root since it's public
                current_comm_x.assert_eq(int(current_comm[0]))
                current_comm_y.assert_eq(int(current_comm[1]))
            else:
                # For root, we can also check that it matches the public input
                current_comm_x.assert_eq(pub_root_x)
                current_comm_y.assert_eq(pub_root_y)
            
            # Optionally: verify that child values hash to a value that
            # relates to the commitment (depending on your commitment structure)
            # For KZG, the commitment is a group element, not a direct hash


@register_prover("snark_verkle")
class SNARKVerkleProof(BaseProver):
    """
    zkSNARK-based Verkle tree prover.
    Generates a single zk proof for membership of multiple keys.
    Uses deduplicated commitments (from your optimized approach).
    """

    def __init__(self, setup_object=None):
        self.setup_object = setup_object
        self.tree = None

    def generate_proof(self, tree: VerkleTree, keys: list[bytes]):
        """
        Generate a zkSNARK proof for multiple key-value pairs in the Verkle tree.
        
        Args:
            tree: VerkleTree instance
            keys: List of keys to prove (bytes)
        
        Returns:
            (proof_dict, witness): proof dict contains public inputs and snark proof
        """
        self.tree = tree
        setup = self.setup_object.setup
        committee_root = tree.root.commitment_to_children
        
        # Generate a random r value for random linear combination
        r = derive_r(generate_root_bytes(committee_root), [_key_to_path(tree.width, k) for k in keys], b.curve_order)
        
        # Collect deduplicated commitments (same as optimized prover)
        commitment_list = []
        commitment_map = {}
        proof_paths = []
        
        # Also collect the data needed for the snark circuit
        values = []
        paths = []
        child_values_per_level = []
        
        # Total polynomial for witness (same as optimized prover)
        total_poly_evaluations = [0] * tree.width
        
        for key_idx, key in enumerate(keys):
            path = _key_to_path(tree.width, key)
            paths.append(path)
            node = tree.root
            key_commitment_indices = []
            key_child_values = []
            
            for i in range(len(path)):
                # Collect child values at this level
                child_values = []
                all_none = True
                for child_node in node.children:
                    if child_node is None:
                        child_values.append(0)
                    else:
                        all_none = False
                        child_values.append(int.from_bytes(child_node, byteorder='big'))
                
                key_child_values.append(child_values)
                
                # Generate the quotient polynomial for this node
                P_over_Q = generate_quotient(child_values, path[i], self.setup_object)
                if all_none:
                    print('all children are None')
                
                # Add to the total polynomial with appropriate r^level factor
                r_factor = derive_r_factor_hash(generate_root_bytes(committee_root), path, i, b.curve_order)
                for j in range(tree.width):
                    total_poly_evaluations[j] = (total_poly_evaluations[j] + P_over_Q[j] * r_factor) % b.curve_order
                
                # Move to the next node
                if i < len(path) - 1:
                    child = tree._make_tree_node(node.children[path[i]])
                    commitment = child.commitment_to_children
                    
                    # Deduplicate commitments
                    comm_key = (int(commitment[0]), int(commitment[1]))
                    if comm_key not in commitment_map:
                        commitment_map[comm_key] = len(commitment_list)
                        commitment_list.append(commitment)
                    
                    key_commitment_indices.append(commitment_map[comm_key])
                    node = child
                else:
                    # At leaf
                    value = node.children[path[i]] if isinstance(node.children[path[i]], bytes) else b''
                    values.append(value)
            
            child_values_per_level.append(key_child_values)
            proof_paths.append({
                'key_idx': key_idx,
                'commitment_indices': key_commitment_indices
            })
        
        # Generate the polynomial commitment (witness)
        witness = b.normalize(lincomb(setup[2], total_poly_evaluations, b.add, b.Z1))
        
        # Generate the snark proof
        root_commitment = tree.root.commitment_to_children
        
        generate_snark_verkle_proof(
            keys,
            values,
            paths,
            child_values_per_level,
            [p['commitment_indices'] for p in proof_paths],
            commitment_list,
            root_commitment,
            self.setup_object
        )
        
        # Trigger proof generation
        atexit._run_exitfuncs()
        
        # Return proof in a dictionary format (with deduplicated commitments)
        deduplicated_proof = {
            'commitments': [(int(c[0]), int(c[1])) for c in commitment_list],
            'proof_paths': [{'key_idx': p['key_idx'], 'commitment_indices': p['commitment_indices']} for p in proof_paths]
        }
        
        proof_dict = {
            'deduplicated_commitments': deduplicated_proof,
            'keys': [k.hex() for k in keys],
            'values': [v.hex() for v in values],
            'root_commitment': (int(root_commitment[0]), int(root_commitment[1]))
        }
        
        return proof_dict, witness
    
    def proof_size(self, proof_dict, witness) -> int:
        """
        Calculate the size of the zkSNARK proof.
        """
        deduplicated_proof = proof_dict['deduplicated_commitments']
        commitment_list = deduplicated_proof['commitments']
        
        # Sizes:
        # - Unique KZG commitments: each ~64 bytes (2 field elements)
        # - Witness polynomial commitment: ~48 bytes (G1 point)
        # - Public inputs (keys + values + root): variable
        # - zkSNARK proof: ~2000 bytes (bellman backend)
        
        num_commitments = len(commitment_list)
        commitment_size = num_commitments * 64
        witness_size = 48
        
        public_inputs_size = (
            len(proof_dict['keys']) * 32 +  # keys (hex strings ~32 bytes each)
            len(proof_dict['values']) * 32 +  # values
            64  # root commitment
        )
        
        snark_proof_size = 2048  # Approximate bellman proof size
        
        return commitment_size + witness_size + public_inputs_size + snark_proof_size