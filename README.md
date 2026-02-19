# Cairo Circuits

This project contains some Cairo circuits, which can be found in the `src` and `packages` folders.

## Currently Implemented Circuits

- **Binary Merkle Root**
Computes binary Merkle tree root. Compatible with any binary Merkle tree construction including LeanIMT.

- **RLN protocol**
Rate Limiting Nullifier protocol. A zero-knowledge protocol designed for spam prevention in anonymous environments.

## Build

```sh
scarb build
```

## Execute

Execute a circuit using the `input.json` file, which contains input parameters encoded as hexadecimal values.

```sh
scarb execute -p cairo_circuits --print-program-output --arguments-file ./input.json
```

## Generate proof

To generate a proof, run:

```sh
scarb prove -p cairo_circuits --arguments-file ./input.json --execute
```

## Verify proof

To verify a proof, run:

```sh
scarb verify --execution-id <execution-id>
```

## Run tests

```sh
scarb test
```

## References

- [Cairo docs](https://www.cairo-lang.org/)
- [RLN V2 Circom circuits](https://github.com/Rate-Limiting-Nullifier/circom-rln)
- [RLN V2 Noir circuits](https://github.com/Rate-Limiting-Nullifier/noir-rln)
- [RLN V3 Circom circuits](https://github.com/Rate-Limiting-Nullifier/rln-v3/tree/main/circuits/circom)
- [RLN V3 Noir circuits](https://github.com/Rate-Limiting-Nullifier/rln-v3/tree/main/circuits/noir)
- [LeanIMT paper](https://zkkit.org/leanimt-paper.pdf)
- [Binary Merkle Tree Root Circom circuits](https://github.com/zk-kit/zk-kit.circom/tree/main/packages/binary-merkle-root)
- [Binary Merkle Tree Root Noir circuits](https://github.com/zk-kit/zk-kit.noir/tree/main/packages/binary-merkle-root)
- [zk-api-credits-stwo-cairo circuits](https://github.com/omarespejel/zk-api-credits-stwo-cairo)


