# Semaphore Cairo

This project contains a Cairo implementation of Semaphore V4, using the Semaphore V3 identity schema.

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
- [LeanIMT paper](https://zkkit.org/leanimt-paper.pdf)
- [Binary Merkle Tree Root Circom circuits](https://github.com/zk-kit/zk-kit.circom/tree/main/packages/binary-merkle-root)
- [Binary Merkle Tree Root Noir circuits](https://github.com/zk-kit/zk-kit.noir/tree/main/packages/binary-merkle-root)
- [zk-api-credits-stwo-cairo circuits](https://github.com/omarespejel/zk-api-credits-stwo-cairo)
- [Semaphore V4 Circom](https://github.com/semaphore-protocol/semaphore/blob/main/packages/circuits/src/semaphore.circom)
- [Semaphore V3 Circom](https://github.com/semaphore-protocol/semaphore/blob/v3.15.2/packages/circuits/semaphore.circom)
- [Semaphore V4 Noir](https://github.com/hashcloak/semaphore-noir/blob/main/packages/circuits-noir/src/main.nr)
