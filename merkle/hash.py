# from Crypto.Hash import keccak
# # from pysnark.poseidon_hash import poseidon_hash
# # from pysnark.runtime import PrivVal
# import poseidon

# FIELD_MOD = 21888242871839275222246405745257275088548364400416034343698204186575808495617  # BN128

# poseidon_hasher = poseidon.Poseidon(
#     p=FIELD_MOD, 
#     security_level=128, 
#     alpha=5, 
#     input_rate=1, 
#     t=2
# )

# def keccak_hash(data):
#     keccak_hash = keccak.new(digest_bits=256)
#     keccak_hash.update(data)
#     return keccak_hash.digest()

# def poseidon_hash_bytes(data: bytes) -> bytes:
#         """
#         Poseidon hash for bytes -> bytes (32 bytes).
#         Adjust FIELD_MOD and BYTE_LEN to your curve if needed.
#         """
#         BYTE_LEN = 32

#         x = int.from_bytes(data, "big") % FIELD_MOD
#         hash_int = poseidon_hasher.run_hash([x])
#         return int(hash_int).to_bytes(BYTE_LEN, "big")

from Crypto.Hash import keccak
import poseidon

FIELD_MOD = 21888242871839275222246405745257275088548364400416034343698204186575808495617  # BN128

# Initializing the hasher with input_rate=1, t=2 allows it to act as a "Sponge".
# It will absorb arrays of any length, one element at a time.
poseidon_hasher = poseidon.Poseidon(
    p=FIELD_MOD, 
    security_level=128, 
    alpha=5, 
    input_rate=1, 
    t=2
)

def keccak_hash(data):
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(data)
    return keccak_hash.digest()

def poseidon_hash_bytes(data: bytes) -> bytes:
    """
    ZK-Friendly Poseidon Hash for arbitrary length nodes.
    Converts a flat byte string into an array of 32-byte field elements
    and hashes them sequentially to respect the t=2 arity.
    """
    # 1. Pad the data to ensure it is a perfect multiple of 32 bytes.
    remainder = len(data) % 32
    if remainder != 0:
        data += b'\0' * (32 - remainder)

    # 2. Slice the byte string into a list of 32-byte chunks
    chunks = [data[i:i+32] for i in range(0, len(data), 32)]
    
    # 3. Convert each chunk into a prime field integer
    field_elements = [int.from_bytes(chunk, "big") % FIELD_MOD for chunk in chunks]

    # 4. Sequential Hash Chaining
    current_hash = 0
    for element in field_elements:
        # Combine the running hash with the next chunk
        combined = (current_hash + element) % FIELD_MOD
        
        # run_hash strictly takes a list of length 1 (input_rate=1)
        hash_result = poseidon_hasher.run_hash([combined])
        
        # Extract the integer result for the next loop
        current_hash = int(hash_result)
    
    return current_hash.to_bytes(32, "big")