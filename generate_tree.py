import json
from registry.trees import TREE_REGISTRY
from registry.setup import SETUP_REGISTRY
from datetime import datetime
from pathlib import Path
import uuid


def generate_tree(method, width, hash_fn=None, setup=None):
    tree_class = TREE_REGISTRY[method]
    tree_id = str(uuid.uuid4())
    storage_root = Path("tree_storage")
    storage_root.mkdir(parents=True, exist_ok=True)

    db_path = str(storage_root / tree_id)
    Path(db_path).mkdir(parents=True, exist_ok=True)

    # write tree_info.json from tree_generation_setup.json
    setup_data = json.load(open("tree_generation_setup.json"))
    info_path = Path(db_path) / "tree_info.json"
    with open(info_path, "w") as f:
        json.dump(setup_data, f, indent=2)

    # append tree id to tree_ids.txt
    ids_path = "tree_ids.txt"
    with open(ids_path, "a") as f:
        f.write(tree_id + "\n")

    tree = tree_class(width, db_path=db_path, hash_fn=hash_fn, setup_object=setup)
    return tree

def generate_setup(method, secret, width=None):
    if not method:
        return None
    setup_class = SETUP_REGISTRY[method]
    setup = setup_class(secret, width)
    return setup

def get_root_data(method, root):
    if method == 'verkle':
        return root.commitment_to_children
    return root.value

def hex_to_bytes(s, expected_length=32):
    s = s[2:] if s.startswith("0x") else s
    b = bytes.fromhex(s)
    if len(b) < expected_length:
        b = b'\x00' * (expected_length - len(b)) + b
    return b

def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')

def test():
    global_setup = json.load(open("tree_generation_setup.json"))
    
    WIDTH = global_setup["WIDTH"]
    KEY_LENGTH = global_setup["KEY_LENGTH"]
    VALUE_LENGTH = global_setup["VALUE_LENGTH"]
    SECRET = global_setup["SECRET"]
    TREE_TYPE = global_setup["TREE_TYPE"]
    SETUP_TYPE = global_setup["SETUP_TYPE"]
    HASH_FN = global_setup["HASH_FN"]

    setup_object = generate_setup(SETUP_TYPE, SECRET, WIDTH)
    print("Generated setup")

    data = {}
    with open("data.json") as f:
        data = json.load(f)

    print("Loaded random test data")

    data_tree = generate_tree(TREE_TYPE, WIDTH, hash_fn=HASH_FN, setup=setup_object)

    print("Generated data tree")

    for idx, (k, v) in enumerate(data.items()):
        if idx % 1000 == 0:
            print(f" Inserting key of index: {idx}")
        # convert key string -> bytes 
        key_bytes = hex_to_bytes(k, KEY_LENGTH)

        val_bytes = hex_to_bytes(v, VALUE_LENGTH)
        #v = bytes_to_int(val_bytes)

        # insert into tree
        #print("Inserting key:", k, "value:", int(v, 16))
        data_tree.insert(key_bytes, val_bytes)
    print("Inserted data into tree")

if __name__ == '__main__':
    test()