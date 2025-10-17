# Secure Aggregation

This repository contains implementations of secure aggregation protocols.
Currently, this only includes the Willow protocol ([paper](https://eprint.iacr.org/2024/936)).

## Dependencies

The codebase is built using [Bazel](https://bazel.build). All other dependencies are built from source.
We use [SHELL](https://github.com/google/shell-encryption) for homomorphic encryption,
and [Curve25519-Dalek](https://crates.io/crates/curve25519-dalek) for elliptic curve operations.
The library itself is written in Rust.

## Build & Test

To build the library (with performance optimizations enabled), run

```
bazel build -c opt //...
```

To run tests:

```
bazel test -c opt //...
```

Usage examples can be found in [willow/tests/willow_v1_shell.rs](willow/tests/willow_v1_shell.rs).

## Benchmarks

Benchmarks, and information how to run them, can be found in the [benches](willow/benches) folder.

## Security
To report a security issue, please read [SECURITY.md](SECURITY.md).

## Disclaimer

This is not an officially supported Google product. The code is provided as-is,
with no guarantees of correctness or security.

