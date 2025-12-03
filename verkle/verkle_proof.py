from registry.provers import BaseProver, register_prover
from verkle.verkle_tree import VerkleTree
from commitment_scheme import generate_quotient
from py_ecc import optimized_bls12_381 as b
from utils.multicombs import lincomb
from randomness_scheme import derive_r, derive_r_factor_hash

@register_prover("verkle")
class VerkleProofGenerator(BaseProver):

    def __init__(self, setup_object):
        self.setup_object = setup_object

    def generate_proof(self, tree: VerkleTree, keys: list[bytes]):
        setup = self.setup_object.setup
        committee_root = tree.get_proof_tree(keys[0])[0]
        # Generate a random r value;
        # to create a random linear combination
        r = derive_r(committee_root[0].n, [tree._key_to_path(k) for k in keys], b.curve_order)
        #print("r", r)
        
        # Total polynomial that we are evaluating
        total_poly_evaluations = [0] * tree.width
        # The set of all intermediate commitments
        commitments = [tree.get_proof_tree(k) for k in keys]

        for key in keys:
            path = tree._key_to_path(key)
            # Walk from top to bottom of the tree
            node = tree.root
            for level, idx in enumerate(path):
                # Generate the quotient polynomial for this node
                child_values = []
                for child in node.children:
                    if child is None:
                        child_values.append(0)
                    else:
                        child_values.append(child.value)
                P_over_Q = generate_quotient(child_values, idx, self.setup_object)
                
                # Add to the total polynomial with appropriate r^level factor
                r_factor = derive_r_factor_hash(committee_root[0].n, path, level, b.curve_order)
                for j in range(tree.width):
                    total_poly_evaluations[j] = (total_poly_evaluations[j] + P_over_Q[j] * r_factor) % b.curve_order
                
                # Move to the next node
                node = node.children[idx]
        # Generate a polynomial commitment for the result
        return commitments, b.normalize(lincomb(setup[2], total_poly_evaluations, b.add, b.Z1))