//! stego.rs - Inyección, extracción y análisis con Ancla de Sigilo de Conocimiento Cero (ZKS).
//! Permite ocultar la carga dentro de archivos anfitriones (PDF, PNG, JPG, etc.)
//! sin dejar firmas estáticas en texto plano.

use crate::crypto::{
    constant_time_eq, derive_session_keys, hmac_sha256, random_16, SecureKey,
};
use crate::engine::{decrypt_block, encrypt_block, DecoyLabyrinth, DecryptedPayload};
use super::detector::{detect_format, find_legitimate_eof, CarrierFormat};

/// Información resultante del análisis forense de un archivo anfitrión
pub struct AnalysisReport {
    pub format: CarrierFormat,
    pub file_size: usize,
    pub legitimate_eof: usize,
    pub payload_detected: bool,
    pub payload_offset: Option<usize>,
    pub dimension: Option<usize>,
    pub total_caracoles: Option<usize>,
}

/// Oculta un payload dentro de un archivo anfitrión utilizando una llave secreta
pub fn hide_in_carrier(
    carrier_data: &[u8],
    payload_data: &[u8],
    file_ext: Option<&str>,
    hidden_msg: Option<&str>,
    master_key: &SecureKey,
    min_dim: usize,
    num_decoys: usize,
    false_exits: usize,
) -> Result<Vec<u8>, String> {
    // 1. Localizar el final estructural legítimo del anfitrión
    let eof_offset = find_legitimate_eof(carrier_data);
    let carrier_prefix = &carrier_data[..eof_offset];

    // 2. Generar Salt y Nonce efímeros para esta operación
    let salt = random_16()?;
    let nonce = random_16()?;
    let session_keys = derive_session_keys(master_key.as_bytes(), &salt, &nonce);

    // 3. Calcular dimensión requerida para el caracol
    let required_len = payload_data.len() + file_ext.unwrap_or("").len() + hidden_msg.unwrap_or("").len() + 32;
    let dimension = crate::engine::spiral::SnailSpiral::calculate_dimension(required_len, min_dim);

    // 4. Cifrar el bloque verídico con el motor SPN
    let real_block = encrypt_block(payload_data, file_ext, hidden_msg, dimension, &session_keys);

    // 5. Construir el Laberinto Multi-Caracol con N señuelos completos y salidas falsas
    let labyrinth = DecoyLabyrinth::build(
        &real_block,
        dimension,
        num_decoys,
        false_exits,
        &session_keys.k_decoy,
        &salt,
    );

    // 6. Empaquetar el blob de carga Caracol:
    // [Salt (16B)] + [Nonce (16B)] + [Dim (2B)] + [Decoys (2B)] + [Bloques...]
    let mut blob = Vec::new();
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&(dimension as u16).to_be_bytes());
    blob.extend_from_slice(&(num_decoys as u16).to_be_bytes());
    for block in &labyrinth.blocks {
        blob.extend_from_slice(block);
    }

    // 7. Generar el Ancla de Sigilo con HMAC-SHA256 sobre el anfitrión + blob
    let mut hmac_input = Vec::with_capacity(carrier_prefix.len() + blob.len());
    hmac_input.extend_from_slice(carrier_prefix);
    hmac_input.extend_from_slice(&blob);
    let hmac_tag = hmac_sha256(&session_keys.k_mac, &hmac_input);

    // 8. Encriptar la longitud del blob mediante XOR con los primeros 4 bytes del tag HMAC
    let blob_len = blob.len() as u32;
    let len_bytes = blob_len.to_be_bytes();
    let len_enc: [u8; 4] = [
        len_bytes[0] ^ hmac_tag[0],
        len_bytes[1] ^ hmac_tag[1],
        len_bytes[2] ^ hmac_tag[2],
        len_bytes[3] ^ hmac_tag[3],
    ];

    // 9. Ensamblar el archivo final:
    // [Carrier Legítimo] + [Blob de Carga] + [HMAC Tag (32B)] + [Longitud Encriptada (4B)]
    let mut final_carrier = Vec::with_capacity(carrier_prefix.len() + blob.len() + 32 + 4);
    final_carrier.extend_from_slice(carrier_prefix);
    final_carrier.extend_from_slice(&blob);
    final_carrier.extend_from_slice(&hmac_tag);
    final_carrier.extend_from_slice(&len_enc);

    Ok(final_carrier)
}

/// Analiza un archivo en busca de una carga Caracol, verificando con la llave si se provee
pub fn analyze_carrier(carrier_data: &[u8], key: Option<&SecureKey>) -> AnalysisReport {
    let format = detect_format(carrier_data);
    let legitimate_eof = find_legitimate_eof(carrier_data);
    let file_size = carrier_data.len();

    let mut report = AnalysisReport {
        format,
        file_size,
        legitimate_eof,
        payload_detected: false,
        payload_offset: None,
        dimension: None,
        total_caracoles: None,
    };

    let master_key = match key {
        Some(k) => k,
        None => return report, // Sin llave, se mantiene sigiloso y no revela presencia
    };

    if let Some((offset, dim, total)) = verify_and_locate_payload(carrier_data, master_key) {
        report.payload_detected = true;
        report.payload_offset = Some(offset);
        report.dimension = Some(dim);
        report.total_caracoles = Some(total);
    }

    report
}

/// Extrae y descifra la carga oculta en un recipiente usando la llave secreta
pub fn extract_from_carrier(
    carrier_data: &[u8],
    master_key: &SecureKey,
) -> Result<DecryptedPayload, String> {
    if carrier_data.len() < 36 {
        return Err("El archivo es demasiado pequeño para contener una carga válida".to_string());
    }

    let tail_tag: [u8; 32] = carrier_data[carrier_data.len() - 36..carrier_data.len() - 4]
        .try_into()
        .unwrap();
    let len_enc: [u8; 4] = carrier_data[carrier_data.len() - 4..]
        .try_into()
        .unwrap();

    let blob_len_bytes: [u8; 4] = [
        len_enc[0] ^ tail_tag[0],
        len_enc[1] ^ tail_tag[1],
        len_enc[2] ^ tail_tag[2],
        len_enc[3] ^ tail_tag[3],
    ];
    let blob_len = u32::from_be_bytes(blob_len_bytes) as usize;

    if blob_len < 36 || blob_len > carrier_data.len() - 36 {
        return Err("Acceso denegado: No se detectó carga o la llave proporcionada es incorrecta".to_string());
    }

    let blob_offset = carrier_data.len() - 36 - blob_len;
    let blob = &carrier_data[blob_offset..blob_offset + blob_len];

    // Leer Salt y Nonce
    let salt: [u8; 16] = blob[0..16].try_into().unwrap();
    let nonce: [u8; 16] = blob[16..32].try_into().unwrap();

    let session_keys = derive_session_keys(master_key.as_bytes(), &salt, &nonce);

    // Verificar el Ancla de Sigilo con HMAC-SHA256
    let expected_tag = hmac_sha256(&session_keys.k_mac, &carrier_data[..carrier_data.len() - 36]);
    if !constant_time_eq(&tail_tag, &expected_tag) {
        return Err("Autenticación fallida: La llave es incorrecta o el archivo fue manipulado".to_string());
    }

    // Parsear parámetros del laberinto
    let dimension = u16::from_be_bytes(blob[32..34].try_into().unwrap()) as usize;
    let num_decoys = u16::from_be_bytes(blob[34..36].try_into().unwrap()) as usize;
    let block_size = dimension * dimension;
    let total_blocks = num_decoys + 1;

    let blocks_data = &blob[36..];
    if blocks_data.len() != total_blocks * block_size {
        return Err("Estructura interna del laberinto corrupta".to_string());
    }

    let mut blocks = Vec::with_capacity(total_blocks);
    for i in 0..total_blocks {
        let start = i * block_size;
        let end = start + block_size;
        blocks.push(blocks_data[start..end].to_vec());
    }

    // Extraer el caracol verídico entre los señuelos
    let real_block = DecoyLabyrinth::extract_real_block(&blocks, &session_keys.k_decoy, &salt)?;

    // Descifrar con el pipeline SPN
    let mut payload = decrypt_block(real_block, dimension, &session_keys)?;
    payload.dimension = dimension;
    payload.num_decoys = num_decoys;
    Ok(payload)
}

/// Función auxiliar para verificar matemáticamente la carga y retornar sus metadatos
fn verify_and_locate_payload(
    carrier_data: &[u8],
    master_key: &SecureKey,
) -> Option<(usize, usize, usize)> {
    if carrier_data.len() < 36 {
        return None;
    }

    let tail_tag: [u8; 32] = carrier_data[carrier_data.len() - 36..carrier_data.len() - 4].try_into().ok()?;
    let len_enc: [u8; 4] = carrier_data[carrier_data.len() - 4..].try_into().ok()?;

    let len_bytes = [
        len_enc[0] ^ tail_tag[0],
        len_enc[1] ^ tail_tag[1],
        len_enc[2] ^ tail_tag[2],
        len_enc[3] ^ tail_tag[3],
    ];
    let blob_len = u32::from_be_bytes(len_bytes) as usize;

    if blob_len < 36 || blob_len > carrier_data.len() - 36 {
        return None;
    }

    let blob_offset = carrier_data.len() - 36 - blob_len;
    let blob = &carrier_data[blob_offset..blob_offset + blob_len];

    let salt: [u8; 16] = blob[0..16].try_into().ok()?;
    let nonce: [u8; 16] = blob[16..32].try_into().ok()?;
    let session_keys = derive_session_keys(master_key.as_bytes(), &salt, &nonce);

    let expected_tag = hmac_sha256(&session_keys.k_mac, &carrier_data[..carrier_data.len() - 36]);
    if !constant_time_eq(&tail_tag, &expected_tag) {
        return None;
    }

    let dimension = u16::from_be_bytes(blob[32..34].try_into().ok()?) as usize;
    let num_decoys = u16::from_be_bytes(blob[34..36].try_into().ok()?) as usize;

    Some((blob_offset, dimension, num_decoys + 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_carrier_steganography_pdf() {
        let fake_pdf = b"%PDF-1.4\n1 0 obj<<>>endobj\nxref\n0 1\ntrailer<<>>\nstartxref\n50\n%%EOF\n";
        let secret = b"Mensaje confidencial incrustado en el PDF";
        let key = SecureKey::new([0x88u8; 32]);

        // 1. Ocultar en el PDF
        let protected_pdf = hide_in_carrier(fake_pdf, secret, Some(".txt"), None, &key, 16, 4, 16).unwrap();
        assert!(protected_pdf.len() > fake_pdf.len());

        // 2. Analizar sin llave -> No detecta
        let report_anon = analyze_carrier(&protected_pdf, None);
        assert!(!report_anon.payload_detected);

        // 3. Analizar con llave errónea -> No detecta
        let wrong_key = SecureKey::new([0x99u8; 32]);
        let report_wrong = analyze_carrier(&protected_pdf, Some(&wrong_key));
        assert!(!report_wrong.payload_detected);

        // 4. Analizar con la llave correcta -> Detecta y autentica
        let report_auth = analyze_carrier(&protected_pdf, Some(&key));
        assert!(report_auth.payload_detected);
        assert_eq!(report_auth.total_caracoles, Some(5)); // 1 real + 4 decoys

        // 5. Extraer y verificar contenido original
        let extracted = extract_from_carrier(&protected_pdf, &key).unwrap();
        assert_eq!(&extracted.payload[..], secret);
    }
}
