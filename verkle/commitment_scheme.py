from setup import load_data_from_json
from py_ecc import optimized_bls12_381 as b
from utils.fft import fft
from utils.multicombs import lincomb

def commit(values, setup):
    global_data = load_data_from_json()
    MODULUS = global_data['MODULUS']
    WIDTH = global_data['WIDTH']
    ROOT_OF_UNITY = global_data['ROOT_OF_UNITY']
    values += [0] * (WIDTH - len(values))
    coeffs = fft(values, MODULUS, ROOT_OF_UNITY, inv=True)
    
    return b.normalize(lincomb(setup[0][:len(coeffs)], coeffs, b.add, b.Z1))