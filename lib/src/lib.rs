use alloy_sol_types::sol;
pub use fn_dsa_vrfy::{signature_size, vrfy_key_size};
use fn_dsa_vrfy::{VerifyingKey, VerifyingKeyStandard, DOMAIN_NONE, HASH_ID_RAW};

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        bytes vrfy_key;
        bytes signature;
        bytes msg;
        bool verified;
    }
}

/// Compute the n'th fibonacci number (wrapping around on overflows), using normal Rust code.
pub fn fibonacci(n: u32) -> (u32, u32) {
    let mut a = 0u32;
    let mut b = 1u32;
    for _ in 0..n {
        let c = a.wrapping_add(b);
        a = b;
        b = c;
    }
    (a, b)
}

/// Verifies a given signature for the message using the verifying key.
/// Returns true if the signature is valid.
pub fn verify_signature(vrfy_key: &[u8], signature: &[u8], message: &[u8]) -> bool {
    if let Some(vk) = VerifyingKeyStandard::decode(vrfy_key) {
        vk.verify(signature, &DOMAIN_NONE, &HASH_ID_RAW, message)
    } else {
        eprintln!("Error: Could not decode verifying key");
        false
    }
}
