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

def verify_proof(method, proof, root, keys, values, paths, setup=None):
    verifier_class = VERIFIER_REGISTRY[method]
    verifier = verifier_class(setup)
    return verifier.verify_proof(values, keys, root, proof, paths)

def generate_tree(method, width, setup=None):
    tree_class = TREE_REGISTRY[method]
    tree = tree_class(width, setup)
    return tree

def generate_setup(method, secret, width=None):
    if not method:
        return None
    setup_class = SETUP_REGISTRY[method]
    setup = setup_class(secret, width)
    return setup

def hex_to_bytes(s, expected_length=32):
    s = s[2:] if s.startswith("0x") else s
    b = bytes.fromhex(s)
    if len(b) < expected_length:
        b = b'\x00' * (expected_length - len(b)) + b
    return b

def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')

def test():
    global_setup = json.load(open("global_setup.json"))
    
    WIDTH = global_setup["WIDTH"]
    KEY_LENGTH = global_setup["KEY_LENGTH"]
    VALUE_LENGTH = global_setup["VALUE_LENGTH"]
    SECRET = global_setup["SECRET"]
    TREE_TYPE = global_setup["TREE_TYPE"]
    PROVER_TYPE = global_setup["PROVER_TYPE"]
    VERIFIER_TYPE = global_setup["VERIFIER_TYPE"]
    SETUP_TYPE = global_setup["SETUP_TYPE"]
    KEYS_TO_PROVE = global_setup["KEYS_TO_PROVE"]

    setup_object = generate_setup(SETUP_TYPE, SECRET, WIDTH)
    print("Generated setup")

    data = {}
    with open("data.json") as f:
        data = json.load(f)

    print("Loaded random test data")

    data_tree = generate_tree(TREE_TYPE, WIDTH, setup_object)

    print("Generated data tree")

    for idx, (k, v) in enumerate(data.items()):
        if idx % 1000 == 0:
            print(f" Inserting key of index: {idx}")
        # convert key string -> bytes 
        key_bytes = hex_to_bytes(k, KEY_LENGTH)

        val_bytes = hex_to_bytes(v, VALUE_LENGTH)
        v = bytes_to_int(val_bytes)

        # insert into tree
        #print("Inserting key:", k, "value:", int(v, 16))
        data_tree.insert(key_bytes, v)
    print("Inserted data into tree")

    key_bytes = [hex_to_bytes(k, KEY_LENGTH) for k in KEYS_TO_PROVE]
    paths_to_prove = [data_tree._key_to_path(k) for k in key_bytes]   
    a = time.time()

    commitments, w = generate_proof(PROVER_TYPE, data_tree, key_bytes, setup_object)
    print("Generated proof in %.3f seconds" % (time.time() - a))
    print('-------------------')

    print("Witness: ", commitments, w)
    
    a = time.time()
    
    assert verify_proof(VERIFIER_TYPE, (commitments, w), data_tree.root.commitment_to_children, key_bytes, [int(data[k], 16) for k in KEYS_TO_PROVE], paths_to_prove, setup_object)

    print("Verified proof in %.3f seconds" % (time.time() - a))

if __name__ == '__main__':
    test()