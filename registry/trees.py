from .pkg_importer import auto_import_submodules
import tree

class TreeNode:
    def __init__(self, width):
        self.width = width                       
        self.children = [None] * width           
        self.value = None  
        self.commitment_to_children = None                                              

class BaseTree:
    def __init__(self, width, setup_object=None):
        self.width = width
        self.root = TreeNode(width)
        self.setup_object = setup_object

    def insert(self, key, value):
        raise NotImplementedError

    def get_proof_tree(self, key):
        raise NotImplementedError
    
    def get(self, key):
        raise NotImplementedError
    

TREE_REGISTRY = {}

def register_tree(name):
    def decorator(cls):
        TREE_REGISTRY[name] = cls
        return cls
    return decorator

auto_import_submodules(tree)