class TreeNode:
    def __init__(self, width):
        self.width = width                       
        self.children = [None] * width           
        self.value = None                        
        self.key = None                          

class BaseTree:
    def __init__(self, width):
        self.width = width
        self.root = TreeNode(width)

    def insert(self, key, value):
        raise NotImplementedError

    def get_proof_tree(self, key):
        raise NotImplementedError
    

TREE_REGISTRY = {}

def register_tree(name):
    def decorator(cls):
        TREE_REGISTRY[name] = cls
        return cls
    return decorator