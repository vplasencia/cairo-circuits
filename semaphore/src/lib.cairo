use core::integer::{u32, u8};
use core::poseidon::poseidon_hash_span;
use cairo_binary_merkle_root::binary_merkle_root::binary_merkle_root;

const MAX_DEPTH: u32 = 10;

fn poseidon1(value: felt252) -> felt252 {
    poseidon_hash_span([value].span())
}

fn poseidon2(left: felt252, right: felt252) -> felt252 {
    poseidon_hash_span([left, right].span())
}

#[executable]
fn main(
    identity_nullifier: felt252,
    identity_trapdoor: felt252,
    merkle_proof_length: u32,
    merkle_proof_indices: [u8; MAX_DEPTH],
    merkle_proof_siblings: [felt252; MAX_DEPTH],
    message: felt252,
    scope: felt252,
) -> (felt252, felt252, felt252, felt252) {

    let secret = poseidon2(identity_nullifier, identity_trapdoor);
    let commitment = poseidon1(secret);

    // Calculate Merkle root.
    let merkle_root = binary_merkle_root(commitment, merkle_proof_length, merkle_proof_indices, merkle_proof_siblings);

    // Nullifier generation.
    let nullifier = poseidon2(scope, identity_nullifier);

    // Output x, the scope, the share, the root and nullifier.
    (scope, message, merkle_root, nullifier)
}
