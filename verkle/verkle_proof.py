from registry.provers import BaseProofGenerator, register_proof_generator
from verkle.verkle_tree import VerkleTree

@register_proof_generator("verkle")
class VerkleProofGenerator(BaseProofGenerator):
    def generate_proof(self, tree: VerkleTree, key: bytes):
        proof_tree = tree.get_proof_tree(key)
        return proof_tree