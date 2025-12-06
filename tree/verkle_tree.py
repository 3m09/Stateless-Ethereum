from registry.trees import BaseTree, register_tree
from registry.trees import TreeNode
from verkle.commitment_scheme import commit
from verkle.hash_scheme import hash_point_to_field
import math

@register_tree("verkle")
class VerkleTree(BaseTree):

    def __init__(self, width, setup_object):
        super().__init__(width, setup_object)
        #self.setup_object = setup_object

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
        stack = [node]

        for idx in path:
            if node.children[idx] is None:
                node.children[idx] = TreeNode(self.width)
            node = node.children[idx]
            stack.append(node)

        node.value = value

        # popping the leaf node to avoid recomputing its commitment
        stack.pop()

        while stack:
            current = stack.pop()

            child_values = []
            for child in current.children:
                if child is None:
                    child_values.append(0)
                else:
                    child_values.append(child.value)
            
            # print("Committing at level with child values:", child_values)
            current.commitment_to_children = commit(child_values, self.setup_object)
            current.value = hash_point_to_field(current.commitment_to_children, self.setup_object.MODULUS)

    def get(self, key):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("Key must be bytes or bytearray")

        node = self.root
        path = self._key_to_path(key)

        for idx in path:
            if node.children[idx] is None:
                return None   

            node = node.children[idx]

        return node.value
    
    def get_proof_tree(self, key):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("Key must be bytes or bytearray")

        proof = []
        node = self.root
        path = self._key_to_path(key)
        for i, idx in enumerate(path):
            if node.children[idx] is None:
                return None   

            node = node.children[idx]

            if i < len(path) - 1:
                proof.append(node.commitment_to_children)

            # excluding the root and leaf commitments
        return proof
