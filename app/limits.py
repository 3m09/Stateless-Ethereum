MAX_EXPERIMENT_KEYS = 2048
DEFAULT_ACCOUNT_PAGE_SIZE = 250
POWER_OF_TWO_ACCOUNT_COUNTS = tuple(
    1 << exponent for exponent in range(MAX_EXPERIMENT_KEYS.bit_length())
)


def is_power_of_two_account_count(value: int) -> bool:
    return value in POWER_OF_TWO_ACCOUNT_COUNTS
