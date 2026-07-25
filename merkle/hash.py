from Crypto.Hash import keccak

from app.trees.poseidon import poseidon_hash_bytes

FIELD_MOD = 52435875175126190479447740508185965837690552500527637822603658699938581184513

def keccak_hash(data):
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(data)
    return keccak_hash.digest()
