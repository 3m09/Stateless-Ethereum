import prover

from .pkg_importer import auto_import_submodules


class BaseProver:
    def generate_proof(self, tree, keys, setup=None):
        raise NotImplementedError


PROVER_REGISTRY = {}
PROVER_IMPORT_ERRORS = {}


def register_prover(name):
    def decorator(cls):
        PROVER_REGISTRY[name] = cls
        return cls

    return decorator


PROVER_IMPORT_ERRORS = auto_import_submodules(prover, ignore_errors=True)
