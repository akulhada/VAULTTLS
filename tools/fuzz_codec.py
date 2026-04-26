#!/usr/bin/env python3
"""
Lightweight parser-robustness campaign for codec.py.

This is not a replacement for a full coverage-guided fuzzer, but it provides an
artifact-friendly malformed-input test that can be run anywhere with Python.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import struct
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from codec import (
    decode_alert,
    decode_app_data,
    decode_client_finish,
    decode_client_hello,
    decode_server_hello,
    encode_alert,
    encode_app_data,
    encode_client_finish,
    encode_client_hello,
    encode_server_hello,
    encode_server_hello_core,
)


def _mutate(data: bytes, rng: random.Random) -> bytes:
    buf = bytearray(data)
    if not buf:
        return os.urandom(rng.randint(0, 32))
    action = rng.choice(["flip", "truncate", "extend", "splice"])
    if action == "flip":
        for _ in range(rng.randint(1, min(4, len(buf)))):
            i = rng.randrange(len(buf))
            buf[i] ^= rng.randrange(1, 256)
        return bytes(buf)
    if action == "truncate":
        cut = rng.randrange(len(buf) + 1)
        return bytes(buf[:cut])
    if action == "extend":
        return bytes(buf + os.urandom(rng.randint(1, 16)))
    # splice
    i = rng.randrange(len(buf))
    j = rng.randrange(i, len(buf))
    return bytes(buf[:i] + buf[j:])


def _seed_inputs() -> dict[str, list[bytes]]:
    client_hello = encode_client_hello(1, os.urandom(64), os.urandom(32), b"ke1")
    core = encode_server_hello_core(1, os.urandom(32), b"cert", b"cfg", b"ke2")
    server_hello = encode_server_hello(core, os.urandom(71), os.urandom(71))
    client_finish = encode_client_finish(b"ke3")
    app_data = encode_app_data(7, os.urandom(64))
    alert = encode_alert(2, "fatal")
    return {
        "decode_client_hello": [client_hello],
        "decode_server_hello": [server_hello],
        "decode_client_finish": [client_finish],
        "decode_app_data": [app_data],
        "decode_alert": [alert],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Fuzz codec.py decoders with malformed inputs")
    parser.add_argument("--iterations", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=539)
    parser.add_argument("--output", default="results/fuzz_codec_last.json")
    args = parser.parse_args()

    rng = random.Random(args.seed)
    decoders = {
        "decode_client_hello": decode_client_hello,
        "decode_server_hello": decode_server_hello,
        "decode_client_finish": decode_client_finish,
        "decode_app_data": decode_app_data,
        "decode_alert": decode_alert,
    }
    seeds = _seed_inputs()

    counters: dict[str, Counter] = {name: Counter() for name in decoders}
    unexpected: list[dict] = []

    for name, fn in decoders.items():
        corpus = seeds[name]
        for _ in range(args.iterations):
            if rng.random() < 0.5:
                data = _mutate(rng.choice(corpus), rng)
            else:
                data = os.urandom(rng.randint(0, 128))
            try:
                fn(data)
                counters[name]["accepted"] += 1
            except Exception as exc:  # robustness campaign: record every parser exception
                counters[name][type(exc).__name__] += 1
                if not isinstance(exc, (AssertionError, ValueError, UnicodeDecodeError, struct.error)):
                    unexpected.append({"decoder": name, "exc_type": type(exc).__name__, "message": str(exc)})

    report = {
        "campaign": "codec fuzzing",
        "iterations_per_decoder": args.iterations,
        "seed": args.seed,
        "results": {name: dict(counter) for name, counter in counters.items()},
        "unexpected_exception_samples": unexpected[:20],
        "note": "Accepted malformed inputs are not automatically bugs; some random inputs may accidentally satisfy a message grammar.",
    }

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    print(f"\nWrote fuzz report to {out}")


if __name__ == "__main__":
    main()
