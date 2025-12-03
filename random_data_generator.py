import json
import os
from typing import Union


def _compute_value(i: int) -> int:
    return (1720941241 + (pow(i, 70) ^ pow(i, 99))) % (2 ** 200)


def generate_random_kv_json(width: int, height: int, out_path: Union[str, os.PathLike]):
    """Generate deterministic key-value data and write to a JSON file.

    Args:
        width: integer width (used as "WIDTH" in the formula)
        height: integer height (used as "DEPTH" in the formula)
        out_path: path to output JSON file

    The function writes a JSON object where keys are decimal string indexes
    ("0", "1", ...) and values are hex-encoded strings of the computed
    integer value (prefixed with "0x"). The function streams output to
    disk to avoid holding the entire dataset in memory for large sizes.
    """
    if not isinstance(width, int) or not isinstance(height, int):
        raise TypeError("width and height must be integers")
    if width < 1 or height < 1:
        raise ValueError("width and height must be >= 1")

    total = width ** height

    out_dir = os.path.dirname(os.fspath(out_path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    # Stream to file so we don't keep everything in memory for large sizes
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("{")
        for i in range(total):
            val = _compute_value(i)
            # key as decimal string, value as hex string to preserve full precision
            key = str(i)
            value_str = hex(val)
            # write comma between items
            if i != 0:
                f.write(",")
            # minimal JSON escaping - keys here are simple decimal strings
            f.write('\n  "{}": "{}"'.format(key, value_str))
        f.write('\n}\n')


if __name__ == "__main__":
    # Simple CLI so you can run the script directly: python random_data_generator.py <width> <height> [out_path]
    import argparse

    parser = argparse.ArgumentParser(description="Generate deterministic random KV JSON")
    parser.add_argument("width", type=int, help="width (integer)")
    parser.add_argument("height", type=int, help="height / depth (integer)")
    parser.add_argument("out_path", nargs="?", default="data/random_kv.json", help="output JSON path")
    args = parser.parse_args()

    print(f"Generating {args.width} ** {args.height} entries to {args.out_path} (this may take a while)...")
    generate_random_kv_json(args.width, args.height, args.out_path)
    print("Done.")
