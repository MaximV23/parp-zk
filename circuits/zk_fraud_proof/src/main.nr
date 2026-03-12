mod mpt;

use keccak256::keccak256;
use mpt::{
    MAX_NODE_LEN,
    MAX_DEPTH,
    hash_node,
    verify_branch_child,
    verify_extension_child,
    decode_compact_path,
    key_to_nibbles,
};


// kind values:
//   0 = branch    (17-slot array, we follow one nibble)
//   1 = extension (2-item list, we consume multiple nibbles)
//   2 = leaf      (2-item list, end of path)

struct ProofNode {
    raw:     [u8; MAX_NODE_LEN],
    raw_len: u32,
    kind: u8,
    branch_nibble: u8,
    child_hash: [u8; 32],
    path_offset: u32,
    child_offset: u32,
}


fn main(
    // Public inputs
    trie_root:          pub [u8; 32],
    claimed_value_hash: pub [u8; 32],
    query_key:          pub [u8; 32],

    // Private inputs
    nodes:            [ProofNode; MAX_DEPTH],
    proof_depth:      u32,
    actual_value:     [u8; MAX_NODE_LEN],
    actual_value_len: u32,
) {
    // 1) expand key to nibbles
    let key_nib = key_to_nibbles(query_key);
    let mut nibble_cursor: u32 = 0;

    // 2) walk the proof, verifying the hash chain
    let mut expected: [u8; 32] = trie_root;

    for i in 0..MAX_DEPTH {
        if i < proof_depth {
            let node = nodes[i];

            let node_hash = hash_node(node.raw, node.raw_len);
            assert(node_hash == expected, "hash chain broken: node does not match parent pointer");

            // Branch
            if node.kind == 0 {
                let child_ok = verify_branch_child(
                    node.raw,
                    node.branch_nibble,
                    node.child_hash,
                );
                assert(child_ok, "child hash not found in branch node");

                assert(
                    key_nib[nibble_cursor] == node.branch_nibble,
                    "branch nibble does not match query key",
                );

                expected = node.child_hash;
                nibble_cursor += 1;

            } // Extension 
            else if node.kind == 1 {
                let (_, consumed) = decode_compact_path(
                    node.raw,
                    node.path_offset,
                    key_nib,
                    nibble_cursor,
                );

                let child_ok = verify_extension_child(
                    node.raw,
                    node.child_offset,
                    node.child_hash,
                );
                assert(child_ok, "child hash not found in extension node");

                expected       = node.child_hash;
                nibble_cursor += consumed;

            } // Leaf 
            else {
                let (_, consumed) = decode_compact_path(
                    node.raw,
                    node.path_offset,
                    key_nib,
                    nibble_cursor,
                );
                nibble_cursor += consumed;

                // After a leaf, expected must equal hash(actual_value).
                expected = keccak256(actual_value, actual_value_len);
            }
        }
    }

    // 3) verify the correct leaf value
    let actual_hash = keccak256(actual_value, actual_value_len);
    assert(actual_hash == expected, "actual value does not match the trie leaf");

    // 4) the fraud assertion
    assert(actual_hash != claimed_value_hash, "no fraud: the claimed value matches the trie");
}


#[test]
fn test_key_nibble_expansion() {
    let mut key = [0 as u8; 32];
    key[0] = 0x7a;
    key[1] = 0x57;
    key[2] = 0x15;
    key[3] = 0xf3;

    let nib = key_to_nibbles(key);
    assert(nib[0] == 0x7);
    assert(nib[1] == 0xa);
    assert(nib[2] == 0x5);
    assert(nib[3] == 0x7);
    assert(nib[4] == 0x1);
    assert(nib[5] == 0x5);
    assert(nib[6] == 0xf);
    assert(nib[7] == 0x3);
}

#[test]
fn test_fraud_assertion_logic() {
    let mut a = [0 as u8; MAX_NODE_LEN];
    let mut b = [0 as u8; MAX_NODE_LEN];
    a[0] = 0x01;
    b[0] = 0x02;

    let hash_a = hash_node(a, 1);
    let hash_b = hash_node(b, 1);

    assert(hash_a != hash_b);
}
