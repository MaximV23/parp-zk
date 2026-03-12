use keccak256::keccak256;

// 17 children * 33 bytes (0xa0 + 32-byte hash) + 3 byte list header = 564 B
pub global MAX_NODE_LEN: u32 = 600;
pub global MAX_DEPTH: u32 = 9;

// Turn 32 bytes into 64 nibbles
pub fn key_to_nibbles(key: [u8; 32]) -> [u8; 64] {
    let mut nib = [0 as u8; 64];
    for i in 0..32 {
        nib[i * 2]     = key[i] >> 4;       // 4 high bits
        nib[i * 2 + 1] = key[i] & 0x0f;     // 4 low bits
    }
    nib
}

pub fn hash_node(node: [u8; MAX_NODE_LEN], len: u32) -> [u8; 32] {
    keccak256(node, len)
}

// Check slot[n]'s 0xa0+hash at offset n*33
pub fn verify_branch_child(
    node:       [u8; MAX_NODE_LEN],
    nibble:     u8,
    child_hash: [u8; 32],
) -> bool {
    let header_len: u32 = if node[0] < 0xf8 { 1 } else { 2 };

    let offset: u32 = header_len + (nibble as u32) * 33;

    let prefix_ok = node[offset] == 0xa0;

    let mut hash_ok = true;
    for b in 0..32 {
        if node[offset + 1 + b] != child_hash[b] {
            hash_ok = false;
        }
    }
    prefix_ok & hash_ok
}

// Read flag bits: extension(0,1)/leaf(2,3), odd/even and extract nibbles
pub fn decode_compact_path(
    node:       [u8; MAX_NODE_LEN],
    path_start: u32,
    key_nib:    [u8; 64],
    cursor:     u32,
) -> (bool, u32) {         

    let path_header   = node[path_start];
    let path_byte_len = (path_header - 0x80) as u32;

    let first_byte = node[path_start + 1];
    let flag       = first_byte >> 4;

    let is_leaf = (flag & 0x02) != 0;
    let is_odd  = (flag & 0x01) != 0;

    let mut path_nib = [0 as u8; 64];
    let mut path_len: u32 = 0;

    if is_odd {
        path_nib[0] = first_byte & 0x0f;
        path_len = 1;
    }
    for b in 1..34 {
        if b < path_byte_len {
            let byte = node[path_start + 1 + b];
            path_nib[path_len]     = byte >> 4;
            path_nib[path_len + 1] = byte & 0x0f;
            path_len += 2;
        }
    }

    let mut path_ok = true;
    for i in 0..64 {
        if i < path_len {
            if path_nib[i] != key_nib[cursor + i] {
                path_ok = false;
            }
        }
    }
    assert(path_ok, "path nibbles do not match key");

    (is_leaf, path_len)
}

// Check extension's single child hash
pub fn verify_extension_child(
    node:          [u8; MAX_NODE_LEN],
    child_offset:  u32,
    child_hash:    [u8; 32],
) -> bool {
    let prefix_ok = node[child_offset] == 0xa0;

    let mut hash_ok = true;
    for b in 0..32 {
        if node[child_offset + 1 + b] != child_hash[b] {
            hash_ok = false;
        }
    }

    prefix_ok & hash_ok
}

#[test]
fn test_key_to_nibbles() {
    let mut key = [0 as u8; 32];
    key[0] = 0xde;
    key[1] = 0xad;

    let nib = key_to_nibbles(key);

    assert(nib[0] == 0xd);
    assert(nib[1] == 0xe);
    assert(nib[2] == 0xa);
    assert(nib[3] == 0xd);
    assert(nib[4] == 0x0); 
}

#[test]
fn test_verify_branch_child() {
    let mut node = [0 as u8; MAX_NODE_LEN];

    node[0] = 0xf8;
    node[1] = 0xd0;  

    node[2] = 0xa0;
    for i in 0..32 {
        node[3 + i] = (i as u8) + 1; 
    }

    let mut expected = [0 as u8; 32];
    for i in 0..32 {
        expected[i] = (i as u8) + 1;
    }

    assert(verify_branch_child(node, 0, expected) == true);
    assert(verify_branch_child(node, 1, expected) == false);
}

#[test]
fn test_decode_compact_path_extension_even() {
    let mut node = [0 as u8; MAX_NODE_LEN];
    node[0] = 0x83;
    node[1] = 0x00;
    node[2] = 0xab;
    node[3] = 0xcd;

    let mut key = [0 as u8; 64];
    key[0] = 0xa; key[1] = 0xb; key[2] = 0xc; key[3] = 0xd;

    let (is_leaf, consumed) = decode_compact_path(node, 0, key, 0);
    assert(is_leaf  == false);
    assert(consumed == 4);
}

#[test]
fn test_decode_compact_path_leaf_odd() {
    let mut node = [0 as u8; MAX_NODE_LEN];
    node[0] = 0x81;
    node[1] = 0x3f;

    let mut key = [0 as u8; 64];
    key[5] = 0xf;

    let (is_leaf, consumed) = decode_compact_path(node, 0, key, 5);
    assert(is_leaf  == true);
    assert(consumed == 1);
}
