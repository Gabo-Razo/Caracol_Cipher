//! kdf.rs - Funciones de derivación de claves (HKDF y PBKDF2) en Rust puro.
//! Transforma una clave maestra y un salt en múltiples subclaves independientes.

use super::hmac::hmac_sha256;

/// HKDF-Extract según RFC 5869
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let actual_salt = if salt.is_empty() {
        &[0u8; 32] as &[u8]
    } else {
        salt
    };
    hmac_sha256(actual_salt, ikm)
}

/// HKDF-Expand según RFC 5869
pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], okm: &mut [u8]) {
    let mut t = [0u8; 32];
    let mut offset = 0;
    let mut counter: u8 = 1;

    while offset < okm.len() {
        let mut input = Vec::with_capacity(32 + info.len() + 1);
        if counter > 1 {
            input.extend_from_slice(&t);
        }
        input.extend_from_slice(info);
        input.push(counter);

        t = hmac_sha256(prk, &input);

        let to_copy = (okm.len() - offset).min(32);
        okm[offset..offset + to_copy].copy_from_slice(&t[..to_copy]);
        offset += to_copy;
        counter += 1;
    }
}

/// PBKDF2 con HMAC-SHA-256 (RFC 2898 / RFC 8018) para derivar claves desde una contraseña
pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    let mut block_index: u32 = 1;
    let mut offset = 0;

    while offset < out.len() {
        // U1 = HMAC(Password, Salt || INT_32_BE(block_index))
        let mut u_input = Vec::with_capacity(salt.len() + 4);
        u_input.extend_from_slice(salt);
        u_input.extend_from_slice(&block_index.to_be_bytes());
        let mut u = hmac_sha256(password, &u_input);
        let mut f = u;

        // U_2 ... U_c
        for _ in 1..iterations {
            u = hmac_sha256(password, &u);
            for k in 0..32 {
                f[k] ^= u[k];
            }
        }

        let to_copy = (out.len() - offset).min(32);
        out[offset..offset + to_copy].copy_from_slice(&f[..to_copy]);
        offset += to_copy;
        block_index += 1;
    }
}

/// Estructura que contiene todas las subclaves derivadas para una sesión criptográfica
pub struct SessionKeys {
    pub k_sub: [u8; 32],    // Clave para la S-Box dinámica
    pub k_spiral: [u8; 32], // Clave para las rotaciones geométricas del caracol
    pub k_xor: [u8; 32],    // Clave para el flujo de confusión XOR (Keystream)
    pub k_mac: [u8; 32],    // Clave para la firma HMAC y el Ancla de Sigilo
    pub k_decoy: [u8; 32],  // Clave para generar el laberinto de caracoles señuelo
}

/// Deriva las 5 subclaves de sesión a partir de la Llave Maestra, Salt y Nonce
pub fn derive_session_keys(master_key: &[u8; 32], salt: &[u8; 16], nonce: &[u8; 16]) -> SessionKeys {
    // 1. Extraer la clave pseudoaleatoria (PRK)
    let prk = hkdf_extract(salt, master_key);

    // 2. Expandir para cada propósito utilizando contextos (info) únicos
    let mut keys = SessionKeys {
        k_sub: [0u8; 32],
        k_spiral: [0u8; 32],
        k_xor: [0u8; 32],
        k_mac: [0u8; 32],
        k_decoy: [0u8; 32],
    };

    let mut info_sub = b"caracol_v6_sub_".to_vec();
    info_sub.extend_from_slice(nonce);
    hkdf_expand(&prk, &info_sub, &mut keys.k_sub);

    let mut info_spiral = b"caracol_v6_spiral_".to_vec();
    info_spiral.extend_from_slice(nonce);
    hkdf_expand(&prk, &info_spiral, &mut keys.k_spiral);

    let mut info_xor = b"caracol_v6_xor_".to_vec();
    info_xor.extend_from_slice(nonce);
    hkdf_expand(&prk, &info_xor, &mut keys.k_xor);

    let mut info_mac = b"caracol_v6_mac_".to_vec();
    info_mac.extend_from_slice(nonce);
    hkdf_expand(&prk, &info_mac, &mut keys.k_mac);

    let mut info_decoy = b"caracol_v6_decoy_".to_vec();
    info_decoy.extend_from_slice(nonce);
    hkdf_expand(&prk, &info_decoy, &mut keys.k_decoy);

    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_distinct_subkeys() {
        let master = [0x77u8; 32];
        let salt = [0x11u8; 16];
        let nonce = [0x22u8; 16];

        let keys = derive_session_keys(&master, &salt, &nonce);

        assert_ne!(keys.k_sub, keys.k_spiral);
        assert_ne!(keys.k_spiral, keys.k_xor);
        assert_ne!(keys.k_xor, keys.k_mac);
        assert_ne!(keys.k_mac, keys.k_decoy);
    }
}
