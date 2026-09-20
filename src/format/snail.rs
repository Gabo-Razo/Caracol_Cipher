//! snail.rs - Formato binario autónomo .snail v6.
//! Permite empaquetar y cifrar archivos directamente sin requerir un recipiente anfitrión.

use crate::crypto::{
    constant_time_eq, derive_session_keys, hmac_sha256, random_16, SecureKey,
};
use crate::engine::{decrypt_block, encrypt_block, DecoyLabyrinth, DecryptedPayload};

const SNAIL_MAGIC: &[u8; 8] = b"SNAIL6\x00\x01"; // Identificador de formato v6

/// Sella un payload en un archivo autónomo .snail v6
pub fn seal_snail(
    payload_data: &[u8],
    file_ext: Option<&str>,
    hidden_msg: Option<&str>,
    master_key: &SecureKey,
    min_dim: usize,
    num_decoys: usize,
    false_exits: usize,
) -> Result<Vec<u8>, String> {
    let salt = random_16()?;
    let nonce = random_16()?;
    let session_keys = derive_session_keys(master_key.as_bytes(), &salt, &nonce);

    let required_len = payload_data.len() + file_ext.unwrap_or("").len() + hidden_msg.unwrap_or("").len() + 32;
    let dimension = crate::engine::spiral::SnailSpiral::calculate_dimension(required_len, min_dim);

    // Cifrar el bloque real con SPN
    let real_block = encrypt_block(payload_data, file_ext, hidden_msg, dimension, &session_keys);

    // Generar laberinto con caracoles señuelo completos y salidas falsas
    let labyrinth = DecoyLabyrinth::build(
        &real_block,
        dimension,
        num_decoys,
        false_exits,
        &session_keys.k_decoy,
        &salt,
    );

    // Ensamblar cabecera y bloques
    let mut buffer = Vec::new();
    buffer.extend_from_slice(SNAIL_MAGIC);
    buffer.extend_from_slice(&salt);
    buffer.extend_from_slice(&nonce);
    buffer.extend_from_slice(&(dimension as u16).to_be_bytes());
    buffer.extend_from_slice(&(num_decoys as u16).to_be_bytes());

    for block in &labyrinth.blocks {
        buffer.extend_from_slice(block);
    }

    // Calcular firma HMAC-SHA256 sobre todo el archivo autónomo
    let hmac_tag = hmac_sha256(&session_keys.k_mac, &buffer);
    buffer.extend_from_slice(&hmac_tag);

    Ok(buffer)
}

/// Abre y descifra un archivo .snail v6 verificando la clave y la integridad HMAC
pub fn open_snail(
    snail_bytes: &[u8],
    master_key: &SecureKey,
) -> Result<DecryptedPayload, String> {
    if snail_bytes.len() < 8 + 16 + 16 + 2 + 2 + 32 {
        return Err("Archivo .snail truncado o no válido".to_string());
    }

    if &snail_bytes[0..8] != SNAIL_MAGIC {
        return Err("Firma mágica no reconocida: no es un archivo .snail v6 válido".to_string());
    }

    let salt: [u8; 16] = snail_bytes[8..24].try_into().unwrap();
    let nonce: [u8; 16] = snail_bytes[24..40].try_into().unwrap();
    let dimension = u16::from_be_bytes(snail_bytes[40..42].try_into().unwrap()) as usize;
    let num_decoys = u16::from_be_bytes(snail_bytes[42..44].try_into().unwrap()) as usize;

    let session_keys = derive_session_keys(master_key.as_bytes(), &salt, &nonce);

    // Verificar HMAC global al final del archivo
    let body_len = snail_bytes.len() - 32;
    let stored_hmac: [u8; 32] = snail_bytes[body_len..].try_into().unwrap();
    let expected_hmac = hmac_sha256(&session_keys.k_mac, &snail_bytes[..body_len]);

    if !constant_time_eq(&stored_hmac, &expected_hmac) {
        return Err("Acceso denegado: Clave incorrecta o archivo .snail corrupto/manipulado".to_string());
    }

    let block_size = dimension * dimension;
    let total_blocks = num_decoys + 1;
    let blocks_data = &snail_bytes[44..body_len];

    if blocks_data.len() != total_blocks * block_size {
        return Err("Discrepancia en la dimensión del laberinto de caracoles".to_string());
    }

    let mut blocks = Vec::with_capacity(total_blocks);
    for i in 0..total_blocks {
        let start = i * block_size;
        let end = start + block_size;
        blocks.push(blocks_data[start..end].to_vec());
    }

    // Extraer el caracol verídico
    let real_block = DecoyLabyrinth::extract_real_block(&blocks, &session_keys.k_decoy, &salt)?;

    // Descifrar con SPN
    let mut payload = decrypt_block(real_block, dimension, &session_keys)?;
    payload.dimension = dimension;
    payload.num_decoys = num_decoys;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snail_v6_roundtrip() {
        let master = SecureKey::new([0x42u8; 32]);
        let data = b"CARACOL_V6_PURE_RUST_ZERO_DEPENDENCIES_TEST_PAYLOAD";
        let ext = Some(".gr");
        let msg = Some("Mensaje confidencial Caracol");

        let sealed = seal_snail(data, ext, msg, &master, 64, 4, 16).unwrap();
        assert!(sealed.len() > data.len());

        let opened = open_snail(&sealed, &master).unwrap();
        assert_eq!(opened.payload, data);
        assert_eq!(opened.file_extension, Some(".gr".to_string()));
        assert_eq!(opened.hidden_message, Some("Mensaje confidencial Caracol".to_string()));

        // Intentar abrir con clave equivocada
        let wrong_key = SecureKey::new([0x44u8; 32]);
        let fail = open_snail(&sealed, &wrong_key);
        assert!(fail.is_err());
    }
}
