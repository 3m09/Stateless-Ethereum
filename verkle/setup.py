from py_ecc import optimized_bls12_381 as b
from utils.fft import fft
from utils.poly_utils import PrimeField
import json
import os

def load_data_from_json():
    filename = 'globals.json'

    if not os.path.exists(filename):
        print(f"Error: Save file '{filename}' not found.")
        return None

    # 1. Load (load) the data from the JSON file
    with open(filename, 'r') as file:
        loaded_data = json.load(file)
        print(f"Data successfully loaded from {filename}")
        return loaded_data

MODULUS = b.curve_order

field = PrimeField(MODULUS)

# Root of unity for a given evaluation domain size
root_of_unity_candidates = {
    512: 12531186154666751577774347439625638674013361494693625348921624593362229945844,
    256: 21071158244812412064791010377580296085971058123779034548857891862303448703672,
    128: 3535074550574477753284711575859241084625659976293648650204577841347885064712,
    64: 6460039226971164073848821215333189185736442942708452192605981749202491651199,
    32: 32311457133713125762627935188100354218453688428796477340173861531654182464166,
    16: 35811073542294463015946892559272836998938171743018714161809767624935956676211
}

def generate_setup(s, WIDTH):
    
    ROOT_OF_UNITY = root_of_unity_candidates[WIDTH]

    assert pow(ROOT_OF_UNITY, WIDTH // 2, MODULUS) != 1
    assert pow(ROOT_OF_UNITY, WIDTH, MODULUS) == 1

    # Powers of the root of unity
    POWERS = [pow(ROOT_OF_UNITY, i, MODULUS) for i in range(WIDTH)]

    # 1/(x-r) evaluated at every r, for every x in the set of powers
    INVERSES = [field.multi_inv([field.sub(p, x) for p in POWERS]) for x in POWERS]

    # Polynomials that evaluate to [000....010....000] across the evaluation domain,
    # one for every possible position of the 1
    LAGRANGE_POLYS = [
        fft([0]*i + [1] + [0]*(WIDTH-1-i), MODULUS, ROOT_OF_UNITY, inv=True)
        for i in range(WIDTH)
    ]

    with open('globals.json', 'w') as f:
        json.dump({
            'MODULUS': MODULUS,
            'LAGRANGE_POLYS': LAGRANGE_POLYS,
            'INVERSES': INVERSES,
            'ROOT_OF_UNITY': ROOT_OF_UNITY,
            'POWERS': POWERS,
        }, f, indent=4)

    return (
        [b.multiply(b.G1, pow(s, i, MODULUS)) for i in range(WIDTH+1)],
        [b.multiply(b.G2, pow(s, i, MODULUS)) for i in range(WIDTH+1)],
        [b.multiply(b.G1, field.eval_poly_at(l, s)) for l in LAGRANGE_POLYS],
        [b.multiply(b.G2, field.eval_poly_at(l, s)) for l in LAGRANGE_POLYS],
    )
