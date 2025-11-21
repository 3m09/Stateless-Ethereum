class BaseTree:
    def insert(self, key, value):
        raise NotImplementedError

    def get(self, key):
        raise NotImplementedError

TREE_REGISTRY = {}

def register_tree(name):
    def decorator(cls):
        TREE_REGISTRY[name] = cls
        return cls
    return decorator