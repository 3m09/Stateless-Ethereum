from registry.verifiers import BaseVerifier, register_verifier
from verkle.randomness_scheme import derive_r, derive_r_factor_hash
from py_ecc import optimized_bls12_381 as b
from verkle.hash_scheme import hash_point_to_field
from verkle.hash_scheme import generate_root_bytes
from verkle.utils.key_to_path import _key_to_path


@register_verifier("verkle")
class VerkleProofVerifier(BaseVerifier):

    def __init__(self, setup_object):
        self.setup_object = setup_object

    def verify_proof(self, values: list[bytes], keys: list[bytes], root, proof):
        paths = [_key_to_path(self.setup_object.WIDTH, k) for k in keys]
        values = [int.from_bytes(v, byteorder='big') for v in values]
        setup = self.setup_object.setup
        MODULUS = self.setup_object.MODULUS
        LAGRANGE_POLYS = self.setup_object.LAGRANGE_POLYS
        WIDTH = self.setup_object.WIDTH

        r = derive_r(generate_root_bytes(root), paths, b.curve_order)
        commitments, witness = proof
        pairing_check = b.FQ12.one()
        for (c, key, v, path) in zip(commitments, keys, values, paths):
           for level, idx in enumerate(path):
               r_factor = derive_r_factor_hash(generate_root_bytes(root), path, level, b.curve_order)
               comm = c[level-1] if level > 0 else root
               comm = (comm[0], comm[1], b.FQ.one())
               leaf = hash_point_to_field(c[level],MODULUS) if level < len(path) - 1 else v
               comm_minus_leaf_times_r = b.multiply(b.add(comm, b.multiply(b.G1, MODULUS - leaf)), r_factor)
               Z_comm = b.multiply(setup[3][idx], self.setup_object.field.inv(LAGRANGE_POLYS[idx][-1]))
               pairing_check *= b.pairing(Z_comm, comm_minus_leaf_times_r, False)
        global_Z_comm = b.add(setup[1][WIDTH], b.neg(setup[1][0]))
        # Subtract out sum [Q_i * r_i * Z(everything)]
        pairing_check *= b.pairing(b.neg(global_Z_comm), (witness[0], witness[1], b.FQ.one()), False)
        o = b.final_exponentiate(pairing_check)
        assert o == b.FQ12.one(), o
        return o == b.FQ12.one()