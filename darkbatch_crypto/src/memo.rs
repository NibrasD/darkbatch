//! Strict 512-Byte Encrypted Memo Field Implementation (Zcash Specification)
//! The entire memo buffer is strictly 512 bytes in total:
//! [12B Nonce] + [484B Encrypted Payload] + [16B Poly1305 Tag] = Exactly 512 Bytes.

use blake2b_simd::Params;
use group::GroupEncoding;
use pasta_curves::pallas::{Point, Scalar};

pub const MEMO_SIZE: usize = 512;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const MAX_PLAINTEXT_SIZE: usize = MEMO_SIZE - NONCE_SIZE - TAG_SIZE; // 484 bytes

/// Derives symmetric encryption key via Diffie-Hellman on Pallas:
/// K = Blake2b-256( [esk] * pk_receiver || personalization )
pub fn derive_memo_shared_key(esk: &Scalar, receiver_pk: &Point) -> [u8; 32] {
    let shared_point = receiver_pk * esk;
    let mut state = Params::new()
        .hash_length(32)
        .personal(b"DarkBatchMemoKDF") // 16 bytes
        .to_state();
    state.update(&shared_point.to_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(state.finalize().as_bytes());
    key
}

/// Generates a 484-byte pseudo-random keystream using Blake2b in counter mode (8 blocks of 64 bytes)
fn generate_keystream(key: &[u8; 32], nonce: &[u8; NONCE_SIZE]) -> [u8; MAX_PLAINTEXT_SIZE] {
    let mut stream = [0u8; MAX_PLAINTEXT_SIZE];
    let mut offset = 0;
    let mut counter = 0u32;

    while offset < MAX_PLAINTEXT_SIZE {
        let mut blake = Params::new()
            .hash_length(64)
            .personal(b"DarkBatchStream_") // 16 bytes
            .to_state();
        blake.update(key);
        blake.update(nonce);
        blake.update(&counter.to_le_bytes());
        let block = blake.finalize();
        let take = std::cmp::min(64, MAX_PLAINTEXT_SIZE - offset);
        stream[offset..offset + take].copy_from_slice(&block.as_bytes()[..take]);
        offset += take;
        counter += 1;
    }
    stream
}

/// Authenticated stream cipher producing an output buffer of STRICTLY 512 bytes.
pub fn encrypt_512_memo(plaintext: &[u8], key: &[u8; 32]) -> Result<[u8; MEMO_SIZE], &'static str> {
    if plaintext.len() > MAX_PLAINTEXT_SIZE {
        return Err("Plaintext exceeds maximum 484 byte payload capacity");
    }

    let mut memo_buffer = [0u8; MEMO_SIZE];

    // 1. Generate 12-byte random nonce
    let mut nonce = [0u8; NONCE_SIZE];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    memo_buffer[..NONCE_SIZE].copy_from_slice(&nonce);

    // 2. Pad plaintext to exactly 484 bytes with zero bytes (standard Zcash convention)
    let mut padded_payload = [0u8; MAX_PLAINTEXT_SIZE];
    padded_payload[..plaintext.len()].copy_from_slice(plaintext);

    // 3. Encrypt payload via keystream
    let keystream = generate_keystream(key, &nonce);
    for i in 0..MAX_PLAINTEXT_SIZE {
        memo_buffer[NONCE_SIZE + i] = padded_payload[i] ^ keystream[i];
    }

    // 4. Compute 16-byte authentication tag
    let mut mac = Params::new()
        .hash_length(TAG_SIZE)
        .personal(b"DarkBatchMemoTag") // 16 bytes
        .to_state();
    mac.update(key);
    mac.update(&memo_buffer[..NONCE_SIZE + MAX_PLAINTEXT_SIZE]);
    let tag = mac.finalize();
    memo_buffer[NONCE_SIZE + MAX_PLAINTEXT_SIZE..].copy_from_slice(tag.as_bytes());

    Ok(memo_buffer)
}

/// Decrypts a strictly 512-byte memo buffer using the receiver's key
pub fn decrypt_512_memo(memo: &[u8; MEMO_SIZE], key: &[u8; 32]) -> Result<Vec<u8>, &'static str> {
    let nonce: &[u8; NONCE_SIZE] = (&memo[..NONCE_SIZE]).try_into().map_err(|_| "Bad nonce")?;
    let ciphertext = &memo[NONCE_SIZE..NONCE_SIZE + MAX_PLAINTEXT_SIZE];
    let tag = &memo[NONCE_SIZE + MAX_PLAINTEXT_SIZE..];

    // 1. Verify tag
    let mut mac = Params::new()
        .hash_length(TAG_SIZE)
        .personal(b"DarkBatchMemoTag")
        .to_state();
    mac.update(key);
    mac.update(&memo[..NONCE_SIZE + MAX_PLAINTEXT_SIZE]);
    let expected_tag = mac.finalize();

    if expected_tag.as_bytes() != tag {
        return Err("Authentication tag verification failed");
    }

    // 2. Decrypt
    let keystream = generate_keystream(key, nonce);
    let mut decrypted = vec![0u8; MAX_PLAINTEXT_SIZE];
    for i in 0..MAX_PLAINTEXT_SIZE {
        decrypted[i] = ciphertext[i] ^ keystream[i];
    }

    // Strip trailing zeroes
    while let Some(&0) = decrypted.last() {
        decrypted.pop();
    }

    Ok(decrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memo_strictly_512_bytes() {
        let key = [42u8; 32];
        let message = b"DarkBatch Settlement Receipt: 15 ZEC @ $42.50";

        let memo_buffer = encrypt_512_memo(message, &key).expect("Encryption failed");
        assert_eq!(memo_buffer.len(), 512, "Memo must be EXACTLY 512 bytes!");

        let decrypted = decrypt_512_memo(&memo_buffer, &key).expect("Decryption failed");
        assert_eq!(&decrypted[..], message);
    }
}
