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
    (message, scope, merkle_root, nullifier)
}

#[cfg(test)]
mod tests {
    use super::main;

    #[test]
    fn test_generate_y_root_and_nullifier() {
        //               Root: -1258611040690975302370648882351730220230771780703118484838674996587042246001
        //                      /                                                                     \
        // -1697215557825991184430658453036604911847986705779947672038501646972528595681   984631471205578712614553929895140960202851439944671757216493909002271097326
        //          /                                                                   \                          /                                    \
        // -1240460965750976929156861911694734022247556984094580622755473812930705557020    2                     3                                       4

        let identity_nullifier = 1; // position of the leaf in the Merkle tree (0-based index)
        let identity_trapdoor = 2;
        let merkle_proof_length = 2;
        let merkle_proof_indices = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let merkle_proof_siblings = [
            2, 984631471205578712614553929895140960202851439944671757216493909002271097326,
            0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        let message = 43;
        let scope = 32;

        let (result_message, result_scope, result_merkle_root, result_nullifier) = main(
            identity_nullifier,
            identity_trapdoor,
            merkle_proof_length,
            merkle_proof_indices,
            merkle_proof_siblings,
            message,
            scope,
        );

        let merkle_root =
            -1258611040690975302370648882351730220230771780703118484838674996587042246001;

        let nullifier =
            1466607489453490973004090925833201773533410091677194412341137268823708554045;

        assert!(result_message == message);
        assert!(result_scope == scope);
        assert!(result_merkle_root == merkle_root);
        assert!(result_nullifier == nullifier);
    }
}