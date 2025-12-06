import json
import os
from typing import Union


def _compute_value(i: int) -> int:
    return (1720941241 + (pow(i, 70) ^ pow(i, 99))) % (2 ** 200)


def generate_random_kv_json(width: int, height: int, out_path: Union[str, os.PathLike], key_length: int = 32, value_length: int = 32):
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
            key_str = "0x" + i.to_bytes(key_length, byteorder="big").hex()
            value_str = "0x" + val.to_bytes(value_length, byteorder="big").hex()
            # write comma between items
            if i != 0:
                f.write(",")
            # minimal JSON escaping - keys here are simple decimal strings
            f.write('\n  "{}": "{}"'.format(key_str, value_str))
        f.write('\n}\n')


if __name__ == "__main__":
    # Simple CLI so you can run the script directly: python random_data_generator.py <width> <height> [out_path]
    import argparse

    parser = argparse.ArgumentParser(description="Generate deterministic random KV JSON")
    parser.add_argument("width", type=int, help="width (integer)")
    parser.add_argument("height", type=int, help="height / depth (integer)")
    parser.add_argument("key_length", type=int, help="key length in bytes")
    parser.add_argument("value_length", type=int, help="value length in bytes")
    parser.add_argument("out_path", nargs="?", default="data/random_kv.json", help="output JSON path")
    args = parser.parse_args()

    print(f"Generating {args.width} ** {args.height} entries to {args.out_path} (this may take a while)...")
    generate_random_kv_json(args.width, args.height, args.out_path, args.key_length, args.value_length)
    print("Done.")
