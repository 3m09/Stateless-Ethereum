import time
import json
from registry.provers import PROVER_REGISTRY
from registry.verifiers import VERIFIER_REGISTRY
from registry.trees import TREE_REGISTRY
from registry.setup import SETUP_REGISTRY

def generate_proof(method, tree, keys, setup=None):
    prover_class = PROVER_REGISTRY[method]
    prover = prover_class(setup)
    return prover.generate_proof(tree, keys)

def verify_proof(method, proof, root, keys, values, setup=None):
    verifier_class = VERIFIER_REGISTRY[method]
    verifier = verifier_class(setup)
    return verifier.verify_proof(values, root, proof, keys)

def generate_tree(method, width, setup=None):
    tree_class = TREE_REGISTRY[method]
    tree = tree_class(width, setup)
    return tree

def generate_setup(method, secret):
    setup_class = SETUP_REGISTRY[method]
    setup = setup_class(secret)
    return setup

def test():
    setup_object = generate_setup("verkle_kzg", 1927409816240961209460912649124)
    print("Generated setup")
    data = {}
    with open("data.json") as f:
        data = json.load(f)

    print("Loaded random test data")

    data_tree = generate_tree("verkle", "16", setup_object)
    print("Generated data and commitment tree")

    coords = [729 % 16 ** 3, 505 % 16 ** 3]

    a = time.time()

    commitments, w = generate_proof("verkle", data_tree, coords, setup_object)

    print("Generated proof in %.3f seconds" % (time.time() - a))
    print('-------------------')

    print("Witness: ", commitments, w)
    
    a = time.time()
    assert verify_proof("verkle", (commitments, w), data_tree.root.value, coords, [data[c] for c in coords], setup_object)
    
    print("Verified proof in %.3f seconds" % (time.time() - a))

if __name__ == '__main__':
    test()