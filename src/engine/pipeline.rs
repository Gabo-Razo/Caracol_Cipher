//! pipeline.rs - Orquestador del pipeline criptográfico SPN (Sustitución-Permutación)
//! Conecta la S-Box dinámica, el motor espiral Caracol y el flujo de confusión XOR.

use crate::crypto::{
    hmac_sha256, DynamicSBox, SecureBuffer, SessionKeys,
};
use super::spiral::SnailSpiral;

const INNER_MAGIC: &[u8; 4] = b"S6PL"; // Magic interno de verificación de payload

/// Resultado estructurado del descifrado
pub struct DecryptedPayload {
    pub payload: Vec<u8>,
    pub file_extension: Option<String>,
    pub hidden_message: Option<String>,
    pub dimension: usize,
    pub num_decoys: usize,
}

/// Ejecuta el proceso completo de cifrado de bajo nivel para un payload
pub fn encrypt_block(
    data: &[u8],
    file_ext: Option<&str>,
    hidden_msg: Option<&str>,
    dimension: usize,
    keys: &SessionKeys,
) -> Vec<u8> {
    // Paso 1: Empaquetar datos con metadatos internos y longitud
    let packed = pack_inner_payload(data, file_ext, hidden_msg);
    let total_cells = dimension * dimension;

    // Rellenar hasta la dimensión exacta D x D usando bytes derivados de K_xor
    let mut padded = SecureBuffer::zeroed(total_cells);
    padded[..packed.len()].copy_from_slice(&packed);

    // Padding determinista que parece ruido aleatorio para evitar fugas de longitud
    if packed.len() < total_cells {
        let mut prng_pad = crate::crypto::DeterministicPrng::new(keys.k_xor);
        for byte in padded[packed.len()..].iter_mut() {
            *byte = prng_pad.next_u8();
        }
    }

    // Paso 2: Capa de Confusión (S-Box dinámica no lineal)
    let sbox = DynamicSBox::new(keys.k_sub);
    sbox.substitute(&mut padded);

    // Paso 3: Capa de Difusión Espacial (Caracol 2D mutado por clave)
    let spiral = SnailSpiral::new(total_cells, dimension, &keys.k_spiral);
    let mut transposed = spiral.transpose(&padded);

    // Paso 4: Capa de Mezcla Criptográfica (XOR con Keystream HMAC-CTR)
    apply_keystream(&mut transposed, &keys.k_xor);

    transposed
}

/// Ejecuta el proceso inverso de descifrado del bloque de bajo nivel
pub fn decrypt_block(
    ciphertext: &[u8],
    dimension: usize,
    keys: &SessionKeys,
) -> Result<DecryptedPayload, String> {
    let total_cells = dimension * dimension;
    if ciphertext.len() < total_cells {
        return Err("El bloque cifrado es menor que la dimensión de la matriz".to_string());
    }

    let mut buffer = ciphertext[..total_cells].to_vec();

    // Paso 1: Revertir Keystream XOR
    apply_keystream(&mut buffer, &keys.k_xor);

    // Paso 2: Revertir Difusión Espacial (Des-espiralizar)
    let spiral = SnailSpiral::new(total_cells, dimension, &keys.k_spiral);
    let mut untransposed = spiral.inv_transpose(&buffer);

    // Paso 3: Revertir Confusión (S-Box inversa)
    let sbox = DynamicSBox::new(keys.k_sub);
    sbox.inv_substitute(&mut untransposed);

    // Paso 4: Desempaquetar y validar integridad estructural
    let mut payload = unpack_inner_payload(&untransposed)?;
    payload.dimension = dimension;
    Ok(payload)
}

/// Aplica un flujo pseudoaleatorio en modo contador HMAC-CTR
fn apply_keystream(data: &mut [u8], k_xor: &[u8; 32]) {
    let mut block_counter: u64 = 0;
    let mut offset = 0;

    while offset < data.len() {
        let stream_block = hmac_sha256(k_xor, &block_counter.to_be_bytes());
        let to_xor = (data.len() - offset).min(32);
        for i in 0..to_xor {
            data[offset + i] ^= stream_block[i];
        }
        offset += to_xor;
        block_counter += 1;
    }
}

/// Empaqueta el payload, extensión y mensaje oculto con cabeceras de tamaño
fn pack_inner_payload(data: &[u8], file_ext: Option<&str>, hidden_msg: Option<&str>) -> Vec<u8> {
    let ext_bytes = file_ext.unwrap_or("").as_bytes();
    let hidden_bytes = hidden_msg.unwrap_or("").as_bytes();

    let mut buf = Vec::with_capacity(4 + 2 + ext_bytes.len() + 4 + data.len() + 4 + hidden_bytes.len());
    buf.extend_from_slice(INNER_MAGIC);

    // Longitud de extensión (2 bytes) + extensión
    buf.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(ext_bytes);

    // Longitud de datos principales (4 bytes) + datos
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);

    // Longitud de mensaje oculto (4 bytes) + mensaje
    buf.extend_from_slice(&(hidden_bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(hidden_bytes);

    buf
}

/// Desempaqueta y valida el contenido interno descifrado
fn unpack_inner_payload(bytes: &[u8]) -> Result<DecryptedPayload, String> {
    if bytes.len() < 4 + 2 + 4 + 4 {
        return Err("Tamaño de bloque insuficiente para contener cabeceras válidas".to_string());
    }

    if &bytes[0..4] != INNER_MAGIC {
        return Err("Fallo de autenticación: Magic de payload inválido (clave incorrecta)".to_string());
    }

    let mut offset = 4;

    // Extensión de archivo
    let ext_len = u16::from_be_bytes(bytes[offset..offset + 2].try_into().unwrap()) as usize;
    offset += 2;
    if offset + ext_len > bytes.len() {
        return Err("Cabecera de extensión corrupta".to_string());
    }
    let ext_str = if ext_len > 0 {
        Some(String::from_utf8_lossy(&bytes[offset..offset + ext_len]).to_string())
    } else {
        None
    };
    offset += ext_len;

    // Datos principales
    if offset + 4 > bytes.len() {
        return Err("Cabecera de datos corrupta".to_string());
    }
    let data_len = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    if offset + data_len > bytes.len() {
        return Err("Longitud de datos excede el tamaño del bloque".to_string());
    }
    let payload = bytes[offset..offset + data_len].to_vec();
    offset += data_len;

    // Mensaje oculto
    if offset + 4 > bytes.len() {
        return Err("Cabecera de mensaje oculto corrupta".to_string());
    }
    let hidden_len = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    if offset + hidden_len > bytes.len() {
        return Err("Longitud de mensaje oculto excede el tamaño del bloque".to_string());
    }
    let hidden_message = if hidden_len > 0 {
        Some(String::from_utf8_lossy(&bytes[offset..offset + hidden_len]).to_string())
    } else {
        None
    };

    Ok(DecryptedPayload {
        payload,
        file_extension: ext_str,
        hidden_message,
        dimension: 0,
        num_decoys: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::derive_session_keys;

    #[test]
    fn test_pipeline_roundtrip() {
        let master = [0x44u8; 32];
        let salt = [0x55u8; 16];
        let nonce = [0x66u8; 16];
        let keys = derive_session_keys(&master, &salt, &nonce);

        let secret_data = b"Informacion ultra clasificada Caracol v6";
        let dim = 32;

        let encrypted = encrypt_block(secret_data, Some(".txt"), Some("TopSecret"), dim, &keys);
        assert_eq!(encrypted.len(), dim * dim);

        let decrypted = decrypt_block(&encrypted, dim, &keys).unwrap();
        assert_eq!(&decrypted.payload[..], secret_data);
        assert_eq!(decrypted.file_extension.as_deref(), Some(".txt"));
        assert_eq!(decrypted.hidden_message.as_deref(), Some("TopSecret"));
    }
}

