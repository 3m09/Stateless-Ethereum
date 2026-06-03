from registry.trees import BaseTree, register_tree
from registry.trees import TreeNode
from verkle.commitment_scheme_ipa import commit
from verkle.hash_scheme import hash_point_to_field
from verkle.utils.key_to_path import _key_to_path
from verkle.serialization import serialize_verkle_node_flexible, deserialize_verkle_node_flexible
import plyvel, os

@register_tree("verkle_ipa")
class VerkleTreeIPA(BaseTree):

    def __init__(self, width, setup_object):
        super().__init__(width, setup_object)
        self.db = plyvel.DB('./verkle/verkle_state_db_ipa', create_if_missing=True)
        self._root_ref = open('./roots/verkle_root_ref_ipa.bin', 'rb').read() if os.path.exists('./roots/verkle_root_ref_ipa.bin') else None
        if self._root_ref:
            self.root = self._make_tree_node(self._root_ref)

    def insert(self, key, value):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("Key must be bytes or bytearray")

        path = _key_to_path(self.width, key)

        node = self.root
        stack = [node]

        for i in range(len(path)-1):
            if node.children[path[i]] is None:
                node = TreeNode(self.width)
            else:
                node = self._make_tree_node(node.children[path[i]])
            stack.append(node)

        node.children[path[-1]] = value
        node.type = 'leaf'

        path_indices = path[:-1]

        while stack:
            current = stack.pop()
            parent = stack[-1] if stack else None

            child_values = []
            all_Child_none_flag = True
            for child in current.children:
                if child is None:
                    child_values.append(0)
                else:
                    all_Child_none_flag = False
                    child_values.append(int.from_bytes(child, byteorder='big'))
            if all_Child_none_flag:
                pass

            current.commitment_to_children = commit(child_values, self.setup_object)
            current.value = hash_point_to_field(current.commitment_to_children, self.setup_object.MODULUS).to_bytes(32, 'big')
            self._store_node(current)
            if parent:
                path_idx = path_indices.pop()
                parent.children[path_idx] = current.value
            node = current

        with open('./roots/verkle_root_ref_ipa.bin', 'wb') as f:
            f.write(node.value)
        self._root_ref = node.value
        self.root = node

    def get(self, key):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("Key must be bytes or bytearray")

        node = self.root
        path = _key_to_path(self.width, key)

        for i in range(len(path)-1):
            if node.children[path[i]] is None:
                return None   
            node = self._make_tree_node(node.children[path[i]])
            
        node.type = 'leaf'

        return int.from_bytes(node.children[path[-1]], byteorder='big')
    
    def get_proof_tree(self, key):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("Key must be bytes or bytearray")

        proof = []
        node = self.root
        path = _key_to_path(self.width, key)
        for i in range(len(path)-1):
            if node.children[path[i]] is None:
                return None   
            node = self._make_tree_node(node.children[path[i]])
            proof.append(node.commitment_to_children)
        return proof
    
    def _store_node(self, node):
        encoded = serialize_verkle_node_flexible(node.commitment_to_children, node.children)                               
        reference = node.value          
        self.db.put(reference, encoded)
        return reference
    
    def _make_tree_node(self, reference, type='non_leaf'):
        data = self.db.get(reference)
        if data is None:
            raise KeyError("Node not found: " + reference.hex())
        comm, child_hashes = deserialize_verkle_node_flexible(data)
        node = TreeNode(self.width)
        node.type = type
        node.commitment_to_children = comm
        node.value = hash_point_to_field(comm, self.setup_object.MODULUS).to_bytes(32, 'big')
        if node.value != reference:
            print('Warning: computed node reference does not match stored reference!')
            print('Computed:', node.value.hex())
            print('Stored:', reference.hex())
        node.children = child_hashes
        return node