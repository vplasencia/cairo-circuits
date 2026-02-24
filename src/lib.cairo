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
    assert!(merkle_proof_length <= MAX_DEPTH, "merkle proof length exceeds MAX_DEPTH");
    assert!(merkle_proof_length > 0, "merkle proof length must be positive");

    let limit_result: Option<u32> = user_message_limit.try_into();
    assert!(limit_result.is_some(), "user_message_limit exceeds u32 range");
    let limit_u32: u32 = limit_result.unwrap();

    let msg_id_result: Option<u32> = message_id.try_into();
    assert!(msg_id_result.is_some(), "message_id exceeds u32 range");
    let message_id_u32: u32 = msg_id_result.unwrap();

    assert!(secret != 0, "secret must be non-zero");
    assert!(x != 0, "x must be non-zero");
    assert!(scope != 0, "scope must be non-zero");
    assert!(limit_u32 != 0, "user_message_limit must be positive");
    assert!(message_id_u32 < limit_u32, "message_id out of range");

    // Use validated u32 values converted back to felt252 in all crypto operations.
    // For inputs that pass the u32 range checks above, limit_u32.into() ==
    // user_message_limit and message_id_u32.into() == message_id, so this is
    // semantically equivalent to using the raw felt252 values. Using validated
    // values ensures no gap between what we check and what we hash.
    let identity_commitment = poseidon1(secret);
    let rate_commitment = poseidon2(identity_commitment, limit_u32.into());

    // SAFETY: binary_merkle_root (cairo-binary-merkle-root) loops i from 0..MAX_DEPTH
    // and only reads indices[i]/siblings[i] when i < depth.  Both arrays are [_; MAX_DEPTH],
    // so every access is in-bounds.  Our merkle_proof_length <= MAX_DEPTH assert above is
    // belt-and-suspenders; the library itself never indexes beyond the array size.
    let merkle_root = binary_merkle_root(
        rate_commitment, merkle_proof_length, merkle_proof_indices, merkle_proof_siblings,
    );
    assert!(merkle_root == expected_merkle_root, "invalid merkle root");

    let a1 = poseidon3(secret, scope, message_id_u32.into());
    let y = a1 * x + secret;

    let nullifier = poseidon1(a1);

    (x, scope, y, merkle_root, nullifier)
}

#[cfg(test)]
mod tests {
    use core::poseidon::poseidon_hash_span;
    use super::main;

    const DEFAULT_SECRET: felt252 = 1;
    const DEFAULT_USER_MESSAGE_LIMIT: felt252 = 3;
    const DEFAULT_MESSAGE_ID: felt252 = 1;
    const DEFAULT_MERKLE_PROOF_LENGTH: u32 = 2;
    const DEFAULT_X: felt252 = 43;
    const DEFAULT_SCOPE: felt252 = 32;

    // Depth-2 Merkle tree derivation (all-left path, indices = [0,0]):
    //   leaf        = poseidon2(poseidon1(DEFAULT_SECRET), DEFAULT_USER_MESSAGE_LIMIT)
    //   level-0 hash = poseidon2(leaf, sibling=2)
    //   level-1 hash = poseidon2(level-0 hash, LEVEL1_SIBLING)  =>  DEFAULT_MERKLE_ROOT
    const LEVEL1_SIBLING: felt252 =
        984631471205578712614553929895140960202851439944671757216493909002271097326;
    const DEFAULT_MERKLE_ROOT: felt252 =
        1304906950737621371309303808943812194997635679334430880908474303267134943875;

    fn default_indices() -> [u8; 10] {
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    }

    fn default_siblings() -> [felt252; 10] {
        [2, LEVEL1_SIBLING, 0, 0, 0, 0, 0, 0, 0, 0]
    }

    #[test]
    fn test_generate_y_root_and_nullifier() {
        // Depth-2 binary Merkle tree:
        //   leaf = rate_commitment = poseidon2(poseidon1(secret=1), user_message_limit=3)
        //   level-0 sibling: 2
        //   level-1 sibling: LEVEL1_SIBLING
        //   both indices are 0 (left path)
        //   root: DEFAULT_MERKLE_ROOT

        let (result_x, result_scope, result_y, result_merkle_root, result_nullifier) = main(
            DEFAULT_SECRET,
            DEFAULT_USER_MESSAGE_LIMIT,
            DEFAULT_MESSAGE_ID,
            DEFAULT_MERKLE_PROOF_LENGTH,
            default_indices(),
            default_siblings(),
            DEFAULT_MERKLE_ROOT,
            DEFAULT_X,
            DEFAULT_SCOPE,
        );

        assert!(result_x == DEFAULT_X);
        assert!(result_scope == DEFAULT_SCOPE);
        assert!(
            result_y == 1098287955302483310286201757340469267279882425668672374369921451931084611053,
        );
        assert!(result_merkle_root == DEFAULT_MERKLE_ROOT);
        assert!(
            result_nullifier
                == 147168360024309184885242077213476594539192210870918231348220650379991506298,
        );
    }

    #[test]
    #[should_panic(expected: "invalid merkle root")]
    fn test_rejects_wrong_merkle_root() {
        let wrong_root = poseidon_hash_span([999999, 888888, 777777].span());
        let _ = main(
            DEFAULT_SECRET,
            DEFAULT_USER_MESSAGE_LIMIT,
            DEFAULT_MESSAGE_ID,
            DEFAULT_MERKLE_PROOF_LENGTH,
            default_indices(),
            default_siblings(),
            wrong_root,
            DEFAULT_X,
            DEFAULT_SCOPE,
        );
    }

    #[test]
    #[should_panic(expected: "message_id out of range")]
    fn test_rejects_message_id_out_of_range() {
        let _ = main(
            DEFAULT_SECRET,
            DEFAULT_USER_MESSAGE_LIMIT,
            3,
            DEFAULT_MERKLE_PROOF_LENGTH,
            default_indices(),
            default_siblings(),
            DEFAULT_MERKLE_ROOT,
            DEFAULT_X,
            DEFAULT_SCOPE,
        );
    }

    #[test]
    fn test_accepts_message_id_last_valid_index() {
        let message_id = 2;
        let (result_x, result_scope, result_y, result_merkle_root, result_nullifier) = main(
            DEFAULT_SECRET,
            DEFAULT_USER_MESSAGE_LIMIT,
            message_id,
            DEFAULT_MERKLE_PROOF_LENGTH,
            default_indices(),
            default_siblings(),
            DEFAULT_MERKLE_ROOT,
            DEFAULT_X,
            DEFAULT_SCOPE,
        );

        assert!(result_x == DEFAULT_X);
        assert!(result_scope == DEFAULT_SCOPE);
        assert!(result_merkle_root == DEFAULT_MERKLE_ROOT);

        let a1 = super::poseidon3(DEFAULT_SECRET, DEFAULT_SCOPE, message_id);
        let expected_y = a1 * DEFAULT_X + DEFAULT_SECRET;
        let expected_nullifier = super::poseidon1(a1);
        assert!(result_y == expected_y, "Y_MISMATCH_AT_BOUNDARY");
        assert!(result_nullifier == expected_nullifier, "NULLIFIER_MISMATCH_AT_BOUNDARY");
    }

    #[test]
    #[should_panic(expected: "merkle proof length exceeds MAX_DEPTH")]
    fn test_rejects_merkle_proof_length_exceeds_max() {
        let _ = main(
            DEFAULT_SECRET,
            DEFAULT_USER_MESSAGE_LIMIT,
            DEFAULT_MESSAGE_ID,
            11,
            default_indices(),
            default_siblings(),
            DEFAULT_MERKLE_ROOT,
            DEFAULT_X,
            DEFAULT_SCOPE,
        );
    }

    #[test]
    #[should_panic(expected: "merkle proof length must be positive")]
    fn test_rejects_zero_merkle_proof_length() {
        let _ = main(
            DEFAULT_SECRET,
            DEFAULT_USER_MESSAGE_LIMIT,
            DEFAULT_MESSAGE_ID,
            0,
            default_indices(),
            default_siblings(),
            DEFAULT_MERKLE_ROOT,
            DEFAULT_X,
            DEFAULT_SCOPE,
        );
    }

    #[test]
    #[should_panic(expected: "x must be non-zero")]
    fn test_rejects_zero_x() {
        let _ = main(
            DEFAULT_SECRET,
            DEFAULT_USER_MESSAGE_LIMIT,
            DEFAULT_MESSAGE_ID,
            DEFAULT_MERKLE_PROOF_LENGTH,
            default_indices(),
            default_siblings(),
            DEFAULT_MERKLE_ROOT,
            0,
            DEFAULT_SCOPE,
        );
    }

    #[test]
    #[should_panic(expected: "user_message_limit must be positive")]
    fn test_rejects_zero_user_message_limit() {
        let _ = main(
            DEFAULT_SECRET,
            0,
            DEFAULT_MESSAGE_ID,
            DEFAULT_MERKLE_PROOF_LENGTH,
            default_indices(),
            default_siblings(),
            DEFAULT_MERKLE_ROOT,
            DEFAULT_X,
            DEFAULT_SCOPE,
        );
    }

    #[test]
    #[should_panic(expected: "scope must be non-zero")]
    fn test_rejects_zero_scope() {
        let _ = main(
            DEFAULT_SECRET,
            DEFAULT_USER_MESSAGE_LIMIT,
            DEFAULT_MESSAGE_ID,
            DEFAULT_MERKLE_PROOF_LENGTH,
            default_indices(),
            default_siblings(),
            DEFAULT_MERKLE_ROOT,
            DEFAULT_X,
            0,
        );
    }

    #[test]
    #[should_panic(expected: "secret must be non-zero")]
    fn test_rejects_zero_secret() {
        let _ = main(
            0,
            DEFAULT_USER_MESSAGE_LIMIT,
            DEFAULT_MESSAGE_ID,
            DEFAULT_MERKLE_PROOF_LENGTH,
            default_indices(),
            default_siblings(),
            DEFAULT_MERKLE_ROOT,
            DEFAULT_X,
            DEFAULT_SCOPE,
        );
    }

    #[test]
    #[should_panic(expected: "user_message_limit exceeds u32 range")]
    fn test_rejects_user_message_limit_exceeds_u32() {
        let _ = main(
            DEFAULT_SECRET,
            0x100000000,
            DEFAULT_MESSAGE_ID,
            DEFAULT_MERKLE_PROOF_LENGTH,
            default_indices(),
            default_siblings(),
            DEFAULT_MERKLE_ROOT,
            DEFAULT_X,
            DEFAULT_SCOPE,
        );
    }

    #[test]
    #[should_panic(expected: "message_id exceeds u32 range")]
    fn test_rejects_message_id_exceeds_u32() {
        let _ = main(
            DEFAULT_SECRET,
            DEFAULT_USER_MESSAGE_LIMIT,
            0x100000000,
            DEFAULT_MERKLE_PROOF_LENGTH,
            default_indices(),
            default_siblings(),
            DEFAULT_MERKLE_ROOT,
            DEFAULT_X,
            DEFAULT_SCOPE,
        );
    }

    #[test]
    #[should_panic(expected: "message_id exceeds u32 range")]
    fn test_rejects_message_id_negative_felt() {
        // -1 in felt252 is P-1 (field element near PRIME); try_into must reject it
        let _ = main(
            DEFAULT_SECRET,
            DEFAULT_USER_MESSAGE_LIMIT,
            -1,
            DEFAULT_MERKLE_PROOF_LENGTH,
            default_indices(),
            default_siblings(),
            DEFAULT_MERKLE_ROOT,
            DEFAULT_X,
            DEFAULT_SCOPE,
        );
    }
}
