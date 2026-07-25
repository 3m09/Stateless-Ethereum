from functools import lru_cache

from poseidon.parameters import matrix_254, prime_254, round_constants_254

FIELD_MODULUS = prime_254
FULL_ROUNDS = 8
PARTIAL_ROUNDS = 57
STATE_WIDTH = 3
SBOX_EXPONENT = 5


@lru_cache(maxsize=1)
def _parameters() -> tuple[list[int], list[list[int]]]:
    constants = [int(value, 16) for value in round_constants_254]
    matrix = [[int(value, 16) for value in row] for row in matrix_254]
    expected = STATE_WIDTH * (FULL_ROUNDS + PARTIAL_ROUNDS)
    if len(constants) != expected:
        raise RuntimeError("Unexpected Poseidon round-constant count")
    return constants, matrix


def _mix(state: list[int], matrix: list[list[int]]) -> list[int]:
    return [
        sum(
            coefficient * value
            for coefficient, value in zip(row, state, strict=True)
        )
        % FIELD_MODULUS
        for row in matrix
    ]


def poseidon_one(value: int) -> int:
    """Poseidon t=3 permutation returning the first rate element."""

    constants, matrix = _parameters()
    state = [value % FIELD_MODULUS, 0, 0]
    constant_index = 0
    half_full_rounds = FULL_ROUNDS // 2

    for round_index in range(FULL_ROUNDS + PARTIAL_ROUNDS):
        for state_index in range(STATE_WIDTH):
            state[state_index] = (
                state[state_index] + constants[constant_index]
            ) % FIELD_MODULUS
            constant_index += 1

        is_full_round = (
            round_index < half_full_rounds
            or round_index >= half_full_rounds + PARTIAL_ROUNDS
        )
        if is_full_round:
            state = [
                pow(element, SBOX_EXPONENT, FIELD_MODULUS)
                for element in state
            ]
        else:
            state[0] = pow(state[0], SBOX_EXPONENT, FIELD_MODULUS)
        state = _mix(state, matrix)

    return state[1]


def poseidon_hash_bytes(data: bytes) -> bytes:
    """Hash arbitrary bytes with a deterministic sequential Poseidon sponge."""

    if not data:
        data = b"\x00"
    remainder = len(data) % 32
    if remainder:
        data += b"\x00" * (32 - remainder)

    accumulator = 0
    for offset in range(0, len(data), 32):
        element = int.from_bytes(data[offset : offset + 32], "big")
        accumulator = poseidon_one(
            (accumulator + element) % FIELD_MODULUS
        )
    return accumulator.to_bytes(32, "big")


def parameter_manifest() -> dict[str, int | str]:
    return {
        "field": "BN254 scalar field",
        "field_modulus": FIELD_MODULUS,
        "state_width": STATE_WIDTH,
        "input_rate": 2,
        "full_rounds": FULL_ROUNDS,
        "partial_rounds": PARTIAL_ROUNDS,
        "sbox_exponent": SBOX_EXPONENT,
        "byte_hash_mode": "sequential 32-byte field-element sponge",
    }
