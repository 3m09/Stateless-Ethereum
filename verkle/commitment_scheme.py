from py_ecc import optimized_bls12_381 as b
from .utils.fft import fft
from .utils.multicombs import lincomb
from .utils.poly_utils import PrimeField

def commit(values, setup_object):
    MODULUS = setup_object.MODULUS
    WIDTH = setup_object.WIDTH
    ROOT_OF_UNITY = setup_object.ROOT_OF_UNITY
    values += [0] * (WIDTH - len(values))
    coeffs = fft(values, MODULUS, ROOT_OF_UNITY, inv=True)
    
    return b.normalize(lincomb(setup_object.setup[0][:len(coeffs)], coeffs, b.add, b.Z1))

def generate_quotient(values, index, setup_object):
    MODULUS = setup_object.MODULUS
    WIDTH = setup_object.WIDTH
    POWERS = setup_object.POWERS
    INVERSES = setup_object.INVERSES
    LAGRANGE_POLYS = setup_object.LAGRANGE_POLYS

    field = PrimeField(MODULUS)

    #x = pow(ROOT_OF_UNITY, index, MODULUS)
    P = [field.sub(v, values[index]) for v in values]
    P[index] = 0
    inv_Q = INVERSES[index]
    P_over_Q = [field.mul(a,b) for a,b in zip(P, inv_Q)]
    top_coeff = field.div(sum([field.mul(a, p) for a, p in zip(P_over_Q, POWERS)]), WIDTH)
    lagrange_coefficient = field.div(top_coeff, LAGRANGE_POLYS[index][-1])
    P_over_Q[index] = MODULUS - lagrange_coefficient
    #P_over_Q_coeffs = fft(P_over_Q, MODULUS, ROOT_OF_UNITY, inv=True)
    #assert P_over_Q_coeffs[-1] == 0
    #assert fft(field.mul_polys(P_over_Q_coeffs[:-1], [-x, 1]), MODULUS, ROOT_OF_UNITY) == P
    return P_over_Q