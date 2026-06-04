from Crypto.Hash import keccak

# Import your custom, constraint-free Poseidon implementation
from zkSNARK.myposeidonhash import poseidon_hash

FIELD_MOD = 52435875175126190479447740508185965837690552500527637822603658699938581184513

def keccak_hash(data):
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(data)
    return keccak_hash.digest()

def poseidon_hash_bytes(data: bytes) -> bytes:
    """
    Sequential ZK Sponge Hash (t=2 arity).
    Uses the custom pure-Python myposeidonhash to guarantee exact matrix matching 
    without triggering PySnark's constraint writer.
    """
    # 1. Pad to exact 32-byte alignment
    remainder = len(data) % 32
    if remainder != 0:
        data += b'\0' * (32 - remainder)

    # 2. Slice into 32-byte chunks
    chunks = [data[i:i+32] for i in range(0, len(data), 32)]
    field_elements = [int.from_bytes(chunk, "big") % FIELD_MOD for chunk in chunks]

    # 3. Execute the pure Python sponge loop
    current_hash = 0
    
    for element in field_elements:
        # Modulo the addition to prevent field overflow
        combined = (current_hash + element) % FIELD_MOD
        
        # Call your custom pure-Python hash function. 
        # It takes a list of integers and the modulus.
        hash_result = poseidon_hash([combined], FIELD_MOD) 
        
        # The result is a list of integers, extract the first one
        current_hash = hash_result[0]

    return current_hash.to_bytes(32, "big")