from registry.trees import BaseTree, register_tree
from registry.trees import TreeNode
from verkle.commitment_scheme import commit
from verkle.hash_scheme import hash_point_to_field
from verkle.utils.key_to_path import _key_to_path
from verkle.serialization import serialize_verkle_node_flexible, deserialize_verkle_node_flexible, serialize_verkle_leaf_flexible, deserialize_verkle_leaf_flexible
import plyvel, os
import zlib

@register_tree("verkle")
class VerkleTree(BaseTree):

    def __init__(self, width, setup_object):
        super().__init__(width, setup_object)
        self.db = plyvel.DB('./verkle/verkle_state_db', create_if_missing=True)
        self._root_ref = open('./roots/verkle_root_ref.bin', 'rb').read() if os.path.exists('./roots/verkle_root_ref.bin') else None
        if self._root_ref:
            self.root = self._make_tree_node(self._root_ref)


    # def insert(self, key, value):
    #     if not isinstance(key, (bytes, bytearray)):
    #         raise TypeError("Key must be bytes or bytearray")
        
    #     value = int.from_bytes(value, byteorder='big')

    #     path = _key_to_path(self.width, key)

    #     node = self.root
    #     stack = [node]

    #     for idx in path:
    #         if node.children[idx] is None:
    #             node.children[idx] = TreeNode(self.width)
    #         node = node.children[idx]
    #         stack.append(node)

    #     node.value = value
    #     node.type = 'leaf'

    #     while stack:
    #         current = stack.pop()

    #         child_values = []
    #         for child in current.children:
    #             if child is None:
    #                 child_values.append(0)
    #             else:
    #                 child_values.append(child.value)
            
    #         # print("Committing at level with child values:", child_values)
    #         current.commitment_to_children = commit(child_values, self.setup_object)
    #         if current.type != 'leaf':
    #             current.value = hash_point_to_field(current.commitment_to_children, self.setup_object.MODULUS)
    #         self._store_node(current)

    # def insert(self, key, value):
    #     if not isinstance(key, (bytes, bytearray)):
    #         raise TypeError("Key must be bytes or bytearray")
        
    #     value = int.from_bytes(value, byteorder='big')

    #     path = _key_to_path(self.width, key)

    #     leaf = TreeNode(self.width)
    #     leaf.value = value
    #     leaf.type = 'leaf'
    #     leaf.commitment_to_children = commit([value] + [0]*(self.width - 1), self.setup_object)

    #     cur_node_ref = self._store_leaf(leaf)
    #     cur_node = leaf

    #     for idx in path[::-1]:
    #         parent = TreeNode(self.width)
    #         parent.children[idx] = cur_node_ref
    #         child_values = [ int.from_bytes(c, byteorder='big') if c is not None else 0 for c in parent.children ]
    #         parent.commitment_to_children = commit(child_values, self.setup_object)
    #         parent.value = hash_point_to_field(parent.commitment_to_children, self.setup_object.MODULUS).to_bytes(32, 'big')
    #         self._store_node(parent)
    #         cur_node = parent
    #         cur_node_ref = parent.value
        
    #     with open('./roots/verkle_root_ref.bin', 'wb') as f:
    #         f.write(cur_node_ref)
    #     self._root_ref = cur_node_ref
    #     self.root = cur_node

    def insert(self, key, value):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("Key must be bytes or bytearray")
        
        # value = int.from_bytes(value, byteorder='big')

        path = _key_to_path(self.width, key)

        node = self.root
        stack = [node]

        # for idx in path:
        #     if node.children[idx] is None:
        #         node.children[idx] = TreeNode(self.width)
        #     node = self._make_tree_node(node.children[idx])
        #     stack.append(node)

        for i in range(len(path)-1):
            if node.children[path[i]] is None:
                node = TreeNode(self.width)
            else:
                # print('making tree node for child at index', path[i])
                # print('child reference:', node.children[path[i]].hex())
                # print('commitment to children:', node.commitment_to_children)
                node = self._make_tree_node(node.children[path[i]])
            stack.append(node)

        node.children[path[-1]] = value
        node.type = 'leaf'

        path_indices = path[:-1]

        while stack:
            current = stack.pop()
            parent = stack[-1] if stack else None
            # node = current
            # if current.type == 'leaf':
            #     print('found leaf node in the while loop:')
            child_values = []
            all_Child_none_flag = True
            for child in current.children:
                if child is None:
                    child_values.append(0)
                else:
                    all_Child_none_flag = False
                    child_values.append(int.from_bytes(child, byteorder='big'))
            if all_Child_none_flag:
                print('all children are None, skipping commit')
            
            # print("Committing at level with child values:", child_values)
            current.commitment_to_children = commit(child_values, self.setup_object)
            current.value = hash_point_to_field(current.commitment_to_children, self.setup_object.MODULUS).to_bytes(32, 'big')
            self._store_node(current)
            if parent:
                path_idx = path_indices.pop()
                parent.children[path_idx] = current.value
            node = current

        with open('./roots/verkle_root_ref.bin', 'wb') as f:
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

            # excluding the root and leaf commitments
        return proof
    
    def _store_node(self, node):
        encoded = serialize_verkle_node_flexible(node.commitment_to_children, node.children)                               
        reference = node.value          
        self.db.put(reference, encoded)
        return reference
    
    # def _store_leaf(self, node):
    #     encoded = serialize_verkle_leaf_flexible(node.commitment_to_children, node.value)                               
    #     reference = hash_point_to_field(node.commitment_to_children, self.setup_object.MODULUS).to_bytes(32, 'big')          
    #     self.db.put(reference, encoded)
    #     return reference
    
    # def _get_data(self, reference):
    #     data = self.db.get(reference)
    #     if data is None:
    #         raise KeyError("Node not found: " + reference.hex())
    #     type = zlib.decompress(data)[0]
    #     if type == 0:
    #         return deserialize_verkle_node_flexible(data), 'non_leaf'
    #     elif type == 1:
    #         return deserialize_verkle_leaf_flexible(data), 'leaf'
    #     else:
    #         raise ValueError("Invalid serialized data prefix")
    
    # def _get_node_data(self, reference):
    #     data = self.db.get(reference)
    #     if data is None:
    #         raise KeyError("Node not found: " + reference.hex())
    #     return deserialize_verkle_node_flexible(data)
    
    # def _get_leaf_data(self, reference):
    #     data = self.db.get(reference)
    #     if data is None:
    #         raise KeyError("Leaf not found: " + reference.hex())
    #     return deserialize_verkle_leaf_flexible(data)
    
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
        # print('printing commitment to children', comm)
        return node
    
    # def _make_leaf_node(self, reference):
    #     commitment_to_children, value_bytes = self._get_leaf_data(reference)
    #     node = TreeNode(self.width)
    #     node.commitment_to_children = commitment_to_children
    #     node.type = 'leaf'
    #     node.value = int.from_bytes(value_bytes, 'big')
    #     return node

   

    def get_proof_size(
        self,
        commitments: int,
        opening_proofs: int,
        scalar_count = 2) -> int:
        """
        commitments_count: number of commitment G1 points
        opening_proofs_count: number of witness G1 points
        scalar_count: number of field elements
        """
        size = 0
        for c in commitments:
            commitments_count = len(c)
            size += commitments_count * 48

        opening_proofs_count = len(opening_proofs)
        size += opening_proofs_count * 48
        size += scalar_count * 32

        return size


