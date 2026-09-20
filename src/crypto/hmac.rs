//! hmac.rs - Implementación de HMAC-SHA-256 (RFC 2104) en Rust puro.
//! Proporciona autenticación criptográfica de mensajes e integridad de datos.

use super::sha256::{sha256_digest, Sha256};

const BLOCK_SIZE: usize = 64; // Tamaño de bloque en bytes para SHA-256
const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

/// Calcula el HMAC-SHA-256 de un mensaje con una clave secreta
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k_pad = [0u8; BLOCK_SIZE];

    // Paso 1: Si la clave es mayor a 64 bytes, se reduce con un hash SHA-256
    if key.len() > BLOCK_SIZE {
        let hashed_key = sha256_digest(key);
        k_pad[..32].copy_from_slice(&hashed_key);
    } else {
        k_pad[..key.len()].copy_from_slice(key);
    }

    // Paso 2: Calcular (K ^ ipad) y (K ^ opad)
    let mut k_ipad = [0u8; BLOCK_SIZE];
    let mut k_opad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        k_ipad[i] = k_pad[i] ^ IPAD;
        k_opad[i] = k_pad[i] ^ OPAD;
    }

    // Paso 3: Hash interno H((K ^ ipad) || data)
    let mut inner_hasher = Sha256::new();
    inner_hasher.update(&k_ipad);
    inner_hasher.update(data);
    let inner_hash = inner_hasher.finalize();

    // Paso 4: Hash externo H((K ^ opad) || inner_hash)
    let mut outer_hasher = Sha256::new();
    outer_hasher.update(&k_opad);
    outer_hasher.update(&inner_hash);
    outer_hasher.finalize()
}

/// Compara dos digestos en tiempo constante para evitar ataques de canal lateral (Timing Attacks)
pub fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_rfc4231_test_case_1() {
        // RFC 4231 Test Case 1:
        // Key = 20 bytes 0x0b
        // Data = "Hi There"
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let hmac = hmac_sha256(&key, data);
        let expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
        assert_eq!(to_hex(&hmac), expected);
    }

    #[test]
    fn test_hmac_rfc4231_test_case_2() {
        // RFC 4231 Test Case 2:
        // Key = "Jefe"
        // Data = "what do ya want for nothing?"
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let hmac = hmac_sha256(key, data);
        let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
        assert_eq!(to_hex(&hmac), expected);
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
