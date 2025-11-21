class BaseProver:
    def generate_proof(self, data):
        raise NotImplementedError

PROVER_REGISTRY = {}

def register_prover(name):
    def decorator(cls):
        PROVER_REGISTRY[name] = cls
        return cls
    return decorator
