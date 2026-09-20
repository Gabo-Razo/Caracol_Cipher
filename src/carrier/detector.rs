//! detector.rs - Detección de tipos de archivo anfitrión (PDF, PNG, JPEG, ZIP, Binario)
//! y localización del final estructural legítimo (EOF) para inyección no destructiva.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierFormat {
    Pdf,
    Png,
    Jpeg,
    Zip,
    GenericBinary,
}

impl CarrierFormat {
    pub fn name(&self) -> &'static str {
        match self {
            CarrierFormat::Pdf => "Documento Adobe PDF",
            CarrierFormat::Png => "Imagen PNG",
            CarrierFormat::Jpeg => "Imagen JPEG",
            CarrierFormat::Zip => "Archivo Comprimido ZIP",
            CarrierFormat::GenericBinary => "Archivo Binario Genérico",
        }
    }
}

/// Detecta el tipo de recipiente analizando las firmas mágicas iniciales
pub fn detect_format(data: &[u8]) -> CarrierFormat {
    if data.starts_with(b"%PDF-") {
        CarrierFormat::Pdf
    } else if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        CarrierFormat::Png
    } else if data.starts_with(&[0xFF, 0xD8]) {
        CarrierFormat::Jpeg
    } else if data.starts_with(b"PK\x03\x04") {
        CarrierFormat::Zip
    } else {
        CarrierFormat::GenericBinary
    }
}

/// Encuentra el desplazamiento (offset) exacto del fin estructural legítimo del archivo anfitrión.
/// Cualquier dato inyectado a partir de este byte no alterará la visualización ni el funcionamiento del archivo.
pub fn find_legitimate_eof(data: &[u8]) -> usize {
    let format = detect_format(data);
    match format {
        CarrierFormat::Pdf => find_pdf_eof(data),
        CarrierFormat::Jpeg => find_jpeg_eoi(data),
        CarrierFormat::Png => find_png_iend(data),
        CarrierFormat::Zip | CarrierFormat::GenericBinary => data.len(),
    }
}

/// Localiza el último token '%%EOF' en un archivo PDF
fn find_pdf_eof(data: &[u8]) -> usize {
    let needle = b"%%EOF";
    // Buscar en los últimos 4096 bytes o todo el archivo si es menor
    let search_window = data.len().min(65536);
    let start_search = data.len() - search_window;

    let mut last_pos = None;
    for i in start_search..data.len().saturating_sub(needle.len()) {
        if &data[i..i + needle.len()] == needle {
            last_pos = Some(i + needle.len());
        }
    }

    if let Some(mut pos) = last_pos {
        // Consumir posibles retornos de carro o saltos de línea tras el %%EOF
        while pos < data.len() && (data[pos] == b'\r' || data[pos] == b'\n' || data[pos] == b' ') {
            pos += 1;
        }
        pos
    } else {
        data.len()
    }
}

/// Localiza el marcador EOI (End of Image: 0xFF 0xD9) de un archivo JPEG
fn find_jpeg_eoi(data: &[u8]) -> usize {
    for i in (1..data.len()).rev() {
        if data[i - 1] == 0xFF && data[i] == 0xD9 {
            return i + 1;
        }
    }
    data.len()
}

/// Localiza el final del bloque 'IEND' en un archivo PNG (después de sus 4 bytes de CRC)
fn find_png_iend(data: &[u8]) -> usize {
    let needle = b"IEND";
    for i in (0..data.len().saturating_sub(8)).rev() {
        if &data[i..i + 4] == needle {
            // El chunk IEND concluye tras 4 bytes de CRC posterior
            return (i + 4 + 4).min(data.len());
        }
    }
    data.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pdf_eof_detection() {
        let pdf_dummy = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\nxref\n0 1\ntrailer<<>>\nstartxref\n99\n%%EOF\n\n";
        let eof = find_legitimate_eof(pdf_dummy);
        assert_eq!(eof, pdf_dummy.len());
    }

    #[test]
    fn test_jpeg_eoi_detection() {
        let jpeg_dummy = vec![0xFF, 0xD8, 0x00, 0x11, 0x22, 0xFF, 0xD9, 0xAA, 0xBB];
        let eoi = find_legitimate_eof(&jpeg_dummy);
        assert_eq!(eoi, 7); // Justo después de 0xFF, 0xD9
    }
}
