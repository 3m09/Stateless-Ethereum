import hashlib

# Just sha256
def hash(x):
    return hashlib.sha256(x).digest()

# Hashes a curve point to a number
def hash_point_to_field(pt, MODULUS):
    assert len(pt) == 2
    return int.from_bytes(hash(str(pt).encode('utf-8')), 'big') % MODULUS