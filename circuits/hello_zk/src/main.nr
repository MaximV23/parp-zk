use keccak256::keccak256;

fn main(
    secret: Field,
    hash: pub [u8; 32],
) {
    let secret_bytes: [u8; 32] = secret.to_be_bytes();
    let computed = keccak256(secret_bytes, 32);
    assert(computed == hash, "hash does not match secret")
}
