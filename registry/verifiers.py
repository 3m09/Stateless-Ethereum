class BaseVerifier:
    def verify_proof(self, values, root, proof, keys, setup=None):
        raise NotImplementedError

VERIFIER_REGISTRY = {}

def register_verifier(name):
    def decorator(cls):
        VERIFIER_REGISTRY[name] = cls
        return cls
    return decorator