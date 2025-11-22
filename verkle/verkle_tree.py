from registry.trees import BaseTree, register_tree
from registry.trees import TreeNode 
import math

@register_tree("verkle")
class VerkleTree(BaseTree):

    def _key_to_path(self, key: bytes):
        step_bits = int(math.log2(self.width))

        bitstring = ''.join(f"{byte:08b}" for byte in key)

        if len(bitstring) % step_bits != 0:
            pad_len = step_bits - (len(bitstring) % step_bits)
            bitstring = ("0" * pad_len) + bitstring

        chunks = [
            bitstring[i:i + step_bits]
            for i in range(0, len(bitstring), step_bits)
        ]

        path = [int(chunk, 2) for chunk in chunks]

        return path

    def insert(self, key, value):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("Key must be bytes or bytearray")

        path = self._key_to_path(key)

        node = self.root
        for idx in path:
            if node.children[idx] is None:
                node.children[idx] = TreeNode(self.width)
            node = node.children[idx]

        # Store leaf data
        node.key = key
        node.value = value

    def get_proof_tree(self, key):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("Key must be bytes or bytearray")

        proof = []
        node = self.root
        path = self._key_to_path(key)

        for idx in path:
            proof.append(node)

            if node.children[idx] is None:
                return None   

            node = node.children[idx]

        # append leaf node
        proof.append(node)
        return proof
