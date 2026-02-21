use cairo_binary_merkle_root::binary_merkle_root::binary_merkle_root;
use core::integer::{u32, u8};
use core::poseidon::poseidon_hash_span;

const MAX_DEPTH: u32 = 10;

fn poseidon1(value: felt252) -> felt252 {
    poseidon_hash_span([value].span())
}

fn poseidon2(left: felt252, right: felt252) -> felt252 {
    poseidon_hash_span([left, right].span())
}

fn poseidon3(a: felt252, b: felt252, c: felt252) -> felt252 {
    poseidon_hash_span([a, b, c].span())
}

#[executable]
fn main(
    secret: felt252,
    user_message_limit: felt252,
    message_id: felt252,
    merkle_proof_length: u32,
    merkle_proof_indices: [u8; MAX_DEPTH],
    merkle_proof_siblings: [felt252; MAX_DEPTH],
    expected_merkle_root: felt252,
    x: felt252,
    scope: felt252,
) -> (felt252, felt252, felt252, felt252, felt252) {
    let identity_commitment = poseidon1(secret);

    let rate_commitment = poseidon2(identity_commitment, user_message_limit);

    // Calculate Merkle root.
    let merkle_root = binary_merkle_root(
        rate_commitment, merkle_proof_length, merkle_proof_indices, merkle_proof_siblings,
    );
    assert!(merkle_root == expected_merkle_root, "invalid merkle root");

    // message_id range check
    // Check 0 <= message_id < user_message_limit
    let message_id_u32: u32 = message_id.try_into().expect('message_id conversion failed');
    let limit_u32: u32 = user_message_limit.try_into().expect('limit conversion failed');
    assert!(message_id_u32 < limit_u32, "message_id out of range");

    // SSS share calculations
    let a1 = poseidon3(secret, scope, message_id);
    let y = a1 * x + secret;

    // Nullifier generation.
    let nullifier = poseidon1(a1);

    // Output x, the scope, the share, the root and nullifier.
    (x, scope, y, merkle_root, nullifier)
}

#[cfg(test)]
mod tests {
    use super::main;

    #[test]
    fn test_generate_y_root_and_nullifier() {
        //               Root:
        //               1304906950737621371309303808943812194997635679334430880908474303267134943875
        //                      /
        //                      \
        // -16486744807027352205489786600957196005677570325699694126518908851079093876
        // 984631471205578712614553929895140960202851439944671757216493909002271097326
        //          /                                                                   \
        //          /                                    \
        // -1503490824099326712114934619828218718690284175124055840777542045490996146590    2
        // 3                                       4

        let secret = 1; // position of the leaf in the Merkle tree (0-based index)
        let user_message_limit = 3;
        let message_id = 1;
        let merkle_proof_length = 2;
        let merkle_proof_indices = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let merkle_proof_siblings = [
            2, 984631471205578712614553929895140960202851439944671757216493909002271097326, 0, 0, 0,
            0, 0, 0, 0, 0,
        ];
        let x = 43;
        let scope = 32;
        let expected_merkle_root =
            1304906950737621371309303808943812194997635679334430880908474303267134943875;

        let (result_x, result_scope, result_y, result_merkle_root, result_nullifier) = main(
            secret,
            user_message_limit,
            message_id,
            merkle_proof_length,
            merkle_proof_indices,
            merkle_proof_siblings,
            expected_merkle_root,
            x,
            scope,
        );

        let y = 1098287955302483310286201757340469267279882425668672374369921451931084611053;

        let merkle_root =
            1304906950737621371309303808943812194997635679334430880908474303267134943875;

        let nullifier = 147168360024309184885242077213476594539192210870918231348220650379991506298;

        assert!(result_x == x);
        assert!(result_scope == scope);
        assert!(result_y == y);
        assert!(result_merkle_root == merkle_root);
        assert!(result_nullifier == nullifier);
    }

    #[test]
    #[should_panic]
    fn test_rejects_wrong_merkle_root() {
        let secret = 1;
        let user_message_limit = 3;
        let message_id = 1;
        let merkle_proof_length = 2;
        let merkle_proof_indices = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let merkle_proof_siblings = [
            2, 984631471205578712614553929895140960202851439944671757216493909002271097326, 0, 0, 0,
            0, 0, 0, 0, 0,
        ];
        let expected_merkle_root = 999;
        let x = 43;
        let scope = 32;

        let _ = main(
            secret,
            user_message_limit,
            message_id,
            merkle_proof_length,
            merkle_proof_indices,
            merkle_proof_siblings,
            expected_merkle_root,
            x,
            scope,
        );
    }

    #[test]
    #[should_panic]
    fn test_rejects_message_id_out_of_range() {
        let secret = 1;
        let user_message_limit = 3;
        let message_id = 3;
        let merkle_proof_length = 2;
        let merkle_proof_indices = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let merkle_proof_siblings = [
            2, 984631471205578712614553929895140960202851439944671757216493909002271097326, 0, 0, 0,
            0, 0, 0, 0, 0,
        ];
        let expected_merkle_root =
            1304906950737621371309303808943812194997635679334430880908474303267134943875;
        let x = 43;
        let scope = 32;

        let _ = main(
            secret,
            user_message_limit,
            message_id,
            merkle_proof_length,
            merkle_proof_indices,
            merkle_proof_siblings,
            expected_merkle_root,
            x,
            scope,
        );
    }

    #[test]
    fn test_accepts_message_id_last_valid_index() {
        let secret = 1;
        let user_message_limit = 3;
        let message_id = 2;
        let merkle_proof_length = 2;
        let merkle_proof_indices = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let merkle_proof_siblings = [
            2, 984631471205578712614553929895140960202851439944671757216493909002271097326, 0, 0, 0,
            0, 0, 0, 0, 0,
        ];
        let expected_merkle_root =
            1304906950737621371309303808943812194997635679334430880908474303267134943875;
        let x = 43;
        let scope = 32;

        let (result_x, result_scope, _, result_merkle_root, _) = main(
            secret,
            user_message_limit,
            message_id,
            merkle_proof_length,
            merkle_proof_indices,
            merkle_proof_siblings,
            expected_merkle_root,
            x,
            scope,
        );

        assert!(result_x == x);
        assert!(result_scope == scope);
        assert!(result_merkle_root == expected_merkle_root);
    }
}
