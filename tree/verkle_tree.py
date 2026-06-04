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

    def __init__(self, width, db_path='./verkle', hash_fn=None, setup_object=None):
        super().__init__(width, db_path=db_path, hash_fn=hash_fn, setup_object=setup_object)
        self.db = plyvel.DB(self.db_path + '/verkle_state_db', create_if_missing=True)
        self._root_ref = open(self.db_path + '/verkle_root_ref.bin', 'rb').read() if os.path.exists(self.db_path + '/verkle_root_ref.bin') else None
        if self._root_ref:
            self.root = self._make_tree_node(self._root_ref)

    def insert(self, key, value):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("Key must be bytes or bytearray")
        
        # value = int.from_bytes(value, byteorder='big')

        path = _key_to_path(self.width, key)

        node = self.root
        stack = [node]

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

        with open(self.db_path + '/verkle_root_ref.bin', 'wb') as f:
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


    # def get_proof_size(self, commitments, final_commitment):
    #     total_size = 0
    #     # Serialize each list of intermediate commitments per key
    #     for key_commitments in commitments:
    #         print("key commitments length:", len(key_commitments))
    #         for comm in key_commitments:
    #             # Serialize each commitment (x, y) as bytes
    #             data = bytearray()
    #             x_int = int(comm[0])
    #             y_int = int(comm[1])
                
    #             # Calculate minimal byte length needed
    #             x_len = (x_int.bit_length() + 7) // 8 or 1
    #             y_len = (y_int.bit_length() + 7) // 8 or 1
                
    #             x_bytes = x_int.to_bytes(x_len, 'big')
    #             y_bytes = y_int.to_bytes(y_len, 'big')
                
    #             data += x_bytes
    #             data += y_bytes
    #             total_size += len(data)
    #     # Serialize the final commitment
    #     data = bytearray()
    #     x_int = int(final_commitment[0])
    #     y_int = int(final_commitment[1])
        
    #     # Calculate minimal byte length needed
    #     x_len = (x_int.bit_length() + 7) // 8 or 1
    #     y_len = (y_int.bit_length() + 7) // 8 or 1
        
    #     x_bytes = x_int.to_bytes(x_len, 'big')
    #     y_bytes = y_int.to_bytes(y_len, 'big')
        
    #     data += x_bytes
    #     data += y_bytes
    #     total_size += len(data)
    #     return total_size

    def get_proof_size(self, commitments, final_commitment):
        COMPRESSED_POINT_SIZE = 48
        total_size = 0
        
        for key_commitments in commitments:
            # 48 bytes per compressed point
            total_size += len(key_commitments) * COMPRESSED_POINT_SIZE
            
        # Add the final commitment
        total_size += COMPRESSED_POINT_SIZE 
        
        # NOTE: You still need to add path lengths and value lengths to this!
        return total_size

