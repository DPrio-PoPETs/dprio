#!/usr/bin/env python3

import subprocess

def run(args):
    result = subprocess.run(args, capture_output=True, check=True)
    print(str(result.stdout[:-1], encoding="utf-8"))

dimensions = ["1", "8", "64", "256"]
for dimension in dimensions:
    args = ["./target/release/examples/comparison", "-f", "prio", "-d", dimension, "-c", "10000"]
    for _ in range(0, 5):
        run(args)
    args = ["./target/release/examples/comparison", "-f", "dprio", "-d", dimension, "-c", "10000"]
    for _ in range(0, 5):
        run(args)

clients = ["10000", "100000", "1000000"]
for n_clients in clients:
    args = ["./target/release/examples/comparison", "-f", "prio", "-d", "1", "-c", n_clients]
    for _ in range(0, 5):
        run(args)
    args = ["./target/release/examples/comparison", "-f", "dprio", "-d", "1", "-c", n_clients]
    for _ in range(0, 5):
        run(args)
