//! commands.rs - Controladores de ejecución para cada subcomando del CLI.
//! Maneja lectura y escritura de archivos, presentación visual y resolución de llaves.

use std::fs;
use std::path::Path;
use crate::crypto::{pbkdf2_sha256, random_32, SecureKey};
use crate::carrier::{analyze_carrier, extract_from_carrier, hide_in_carrier};
use crate::format::{open_snail, seal_snail};

const KEY_HEADER: &str = "-----BEGIN CARACOL PRIVATE KEY-----";
const KEY_FOOTER: &str = "-----END CARACOL PRIVATE KEY-----";

/// Genera una nueva llave privada de 256 bits y la guarda en disco con permisos seguros
pub fn exec_keygen(out_path: &str) -> Result<(), String> {
    println!("\x1b[1;31m[CARACOL KEYGEN]\x1b[0m Generando llave privada de 256 bits...");

    let raw_bytes = random_32()?;
    let hex_key: String = raw_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let file_content = format!("{}\n{}\n{}\n", KEY_HEADER, hex_key, KEY_FOOTER);

    fs::write(out_path, file_content)
        .map_err(|e| format!("Error al escribir la llave en {}: {}", out_path, e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(out_path, fs::Permissions::from_mode(0o600));
    }

    println!("\x1b[1;31m[ÉXITO]\x1b[0m Llave privada generada exitosamente:");
    println!("   -> Archivo: \x1b[1m{}\x1b[0m", out_path);
    println!("   -> Permisos: 0600 (Solo lectura/escritura por el propietario)");
    println!("\x1b[1;31m[!] IMPORTANTE:\x1b[0m Mantén este archivo seguro. Sin él, es imposible descifrar tus datos.");

    Ok(())
}

/// Analiza un archivo anfitrión e inspecciona la presencia de carga Caracol con o sin llave
pub fn exec_analyze(target_path: &str, key_path: Option<&str>, passphrase: Option<&str>) -> Result<(), String> {
    let data = fs::read(target_path)
        .map_err(|e| format!("Error al abrir {}: {}", target_path, e))?;

    let key = resolve_optional_key(key_path, passphrase);

    println!("\x1b[1;31m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    println!("  \x1b[1;31mANALIZADOR FORENSE CARACOL CIPHER v6\x1b[0m");
    println!("\x1b[1;31m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    println!("  Archivo analizado  : \x1b[1m{}\x1b[0m", target_path);

    let report = analyze_carrier(&data, key.as_ref());

    println!("  Formato detectado  : {}", report.format.name());
    println!("  Tamaño total       : {} bytes ({:.2} KB)", report.file_size, report.file_size as f64 / 1024.0);
    println!("  Fin legítimo (EOF) : byte {}", report.legitimate_eof);

    if report.payload_detected {
        println!("\n  \x1b[1;31m[CARGA CARACOL DETECTADA Y AUTENTICADA]\x1b[0m");
        if let Some(offset) = report.payload_offset {
            println!("  Offset de inyección: byte {}", offset);
        }
        if let Some(dim) = report.dimension {
            println!("  Dimensión Matriz   : {}x{} ({} celdas/caracol)", dim, dim, dim * dim);
        }
        if let Some(total) = report.total_caracoles {
            println!("  Laberinto Caracol  : {} caracoles (1 Real + {} Señuelos Estructurales)", total, total - 1);
        }
        println!("  Estado             : Cifrado con llave privada verificada (HMAC OK)");
    } else if key.is_some() {
        println!("\n  \x1b[1;31m[i] RESULTADO:\x1b[0m No se detectó ninguna carga Caracol vinculada a esta llave.");
        println!("      (El archivo es un documento limpio o fue cifrado con otra clave distinta)");
    } else {
        println!("\n  \x1b[1;31m[i] MODO SIGILOSO ACTIVO:\x1b[0m No se detectó ninguna firma pública en texto plano.");
        println!("      Para verificar si contiene una carga oculta con conocimiento cero,");
        println!("      ejecute: \x1b[1mcaracol -a {} -k <tu_llave.key>\x1b[0m", target_path);
    }
    println!("\x1b[1;31m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");

    Ok(())
}

/// Oculta un archivo o secreto dentro de un archivo anfitrión
pub fn exec_hide(
    carrier_path: &str,
    input_path: Option<&str>,
    raw_text: Option<&str>,
    out_path: &str,
    key_path: Option<&str>,
    passphrase: Option<&str>,
    hidden_msg: Option<&str>,
    dimension: usize,
    decoys: usize,
    false_exits: usize,
    visual: bool,
) -> Result<(), String> {
    let carrier_data = fs::read(carrier_path)
        .map_err(|e| format!("Error al abrir recipiente {}: {}", carrier_path, e))?;

    let (input_data, input_name) = if let Some(text) = raw_text {
        (text.as_bytes().to_vec(), Some("secreto.txt".to_string()))
    } else if let Some(path) = input_path {
        let data = fs::read(path).map_err(|e| format!("Error al abrir archivo de entrada {}: {}", path, e))?;
        let fname = Path::new(path).file_name().and_then(|f| f.to_str()).map(|f| f.to_string());
        (data, fname)
    } else {
        return Err("Se debe proporcionar un archivo (-i) o texto directo (-t)".to_string());
    };

    let key = resolve_required_key(key_path, passphrase)?;

    if visual {
        crate::engine::render_encrypt_animation(dimension, decoys);
    }

    println!("\x1b[1;31m[CARACOL HIDE]\x1b[0m Inyectando payload en {}...", carrier_path);
    println!("   -> Datos a proteger  : {} bytes", input_data.len());
    println!("   -> Arquitectura      : Matriz {}x{} | {} Señuelos | {} Salidas falsas c/u", dimension, dimension, decoys, false_exits);

    let protected_data = hide_in_carrier(
        &carrier_data,
        &input_data,
        input_name.as_deref(),
        hidden_msg,
        &key,
        dimension,
        decoys,
        false_exits,
    )?;

    fs::write(out_path, protected_data)
        .map_err(|e| format!("Error al escribir {}: {}", out_path, e))?;

    println!("\x1b[1;31m[ÉXITO]\x1b[0m Archivo protegido generado en: \x1b[1m{}\x1b[0m", out_path);
    println!("   -> El archivo anfitrión sigue siendo totalmente funcional y compatible.");
    println!("   -> Nadie puede detectar la presencia de los datos sin tu llave privada.");

    Ok(())
}

/// Extrae y descifra la carga oculta dentro de un archivo anfitrión
pub fn exec_extract(
    input_path: &str,
    out_path: Option<&str>,
    key_path: Option<&str>,
    passphrase: Option<&str>,
    visual: bool,
) -> Result<(), String> {
    let data = fs::read(input_path)
        .map_err(|e| format!("Error al abrir {}: {}", input_path, e))?;

    let key = resolve_required_key(key_path, passphrase)?;

    println!("\x1b[1;31m[CARACOL EXTRACT]\x1b[0m Buscando y autenticando carga con tu llave...");

    let result = extract_from_carrier(&data, &key)?;

    if visual {
        crate::engine::render_decrypt_animation(result.dimension);
    }

    let final_out_path = match out_path {
        Some(p) => p.to_string(),
        None => {
            let candidate = if let Some(ref orig_name) = result.file_extension {
                if orig_name.starts_with('.') {
                    let stem = Path::new(input_path).file_stem().unwrap().to_str().unwrap();
                    format!("recuperado_{}{}", stem, orig_name)
                } else {
                    orig_name.clone()
                }
            } else {
                let stem = Path::new(input_path).file_stem().unwrap().to_str().unwrap();
                format!("recuperado_{}.bin", stem)
            };

            if Path::new(&candidate).exists() {
                format!("restaurado_{}", candidate)
            } else {
                candidate
            }
        }
    };

    fs::write(&final_out_path, &result.payload)
        .map_err(|e| format!("Error al guardar {}: {}", final_out_path, e))?;

    println!("\x1b[1;31m[ÉXITO]\x1b[0m Contenido descifrado y restaurado a su estado original:");
    println!("   -> Laberinto resuelto: {} caracoles analizados ({} señuelos neutralizados)", result.num_decoys + 1, result.num_decoys);
    println!("   -> Dimensión matriz  : {}x{}", result.dimension, result.dimension);
    println!("   -> Archivo generado  : \x1b[1m{}\x1b[0m ({} bytes)", final_out_path, result.payload.len());

    if let Ok(text) = std::str::from_utf8(&result.payload) {
        if text.chars().all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t') && text.len() <= 1000 {
            println!("   -> Contenido: \"\x1b[1;31m{}\x1b[0m\"", text);
        }
    }

    if let Some(msg) = result.hidden_message {
        println!("\n\x1b[1;31m[MENSAJE SECRETO OCULTO]:\x1b[0m {}", msg);
    }

    Ok(())
}

/// Sella un archivo en un contenedor autónomo .snail v6
pub fn exec_seal(
    input_path: Option<&str>,
    raw_text: Option<&str>,
    out_path: Option<&str>,
    key_path: Option<&str>,
    passphrase: Option<&str>,
    hidden_msg: Option<&str>,
    dimension: usize,
    decoys: usize,
    false_exits: usize,
    visual: bool,
) -> Result<(), String> {
    let (input_data, input_name, default_name) = if let Some(text) = raw_text {
        (text.as_bytes().to_vec(), Some("secreto.txt".to_string()), "secreto.snail".to_string())
    } else if let Some(path) = input_path {
        let data = fs::read(path).map_err(|e| format!("Error al abrir {}: {}", path, e))?;
        let fname = Path::new(path).file_name().and_then(|f| f.to_str()).map(|f| f.to_string());
        let def = format!("{}.snail", path);
        (data, fname, def)
    } else {
        return Err("Se debe proporcionar un archivo (-i) o texto directo (-t)".to_string());
    };

    let key = resolve_required_key(key_path, passphrase)?;
    let final_out = out_path.unwrap_or(&default_name);

    if visual {
        crate::engine::render_encrypt_animation(dimension, decoys);
    }

    println!("\x1b[1;31m[CARACOL SEAL]\x1b[0m Creando archivo autónomo .snail v6...");
    println!("   -> Datos a proteger  : {} bytes", input_data.len());
    println!("   -> Arquitectura      : Matriz {}x{} | {} Señuelos | {} Salidas falsas c/u", dimension, dimension, decoys, false_exits);

    let sealed = seal_snail(
        &input_data,
        input_name.as_deref(),
        hidden_msg,
        &key,
        dimension,
        decoys,
        false_exits,
    )?;

    fs::write(final_out, sealed)
        .map_err(|e| format!("Error al escribir {}: {}", final_out, e))?;

    println!("\x1b[1;31m[ÉXITO]\x1b[0m Archivo sellado: \x1b[1m{}\x1b[0m", final_out);

    Ok(())
}

/// Abre un archivo autónomo .snail v6
pub fn exec_open(
    input_path: &str,
    out_path: Option<&str>,
    key_path: Option<&str>,
    passphrase: Option<&str>,
    visual: bool,
) -> Result<(), String> {
    let data = fs::read(input_path)
        .map_err(|e| format!("Error al abrir {}: {}", input_path, e))?;

    let key = resolve_required_key(key_path, passphrase)?;

    println!("\x1b[1;31m[CARACOL OPEN]\x1b[0m Abriendo y verificando integridad del .snail...");

    let result = open_snail(&data, &key)?;

    if visual {
        crate::engine::render_decrypt_animation(result.dimension);
    }

    let final_out_path = match out_path {
        Some(p) => p.to_string(),
        None => {
            let candidate = if let Some(ref orig_name) = result.file_extension {
                if orig_name.starts_with('.') {
                    let stem = Path::new(input_path).file_stem().unwrap().to_str().unwrap();
                    let base = if stem.ends_with(".snail") { &stem[..stem.len() - 6] } else { stem };
                    format!("restaurado_{}{}", base, orig_name)
                } else {
                    orig_name.clone()
                }
            } else {
                let stem = Path::new(input_path).file_stem().unwrap().to_str().unwrap();
                format!("restaurado_{}.bin", stem)
            };

            if Path::new(&candidate).exists() {
                format!("restaurado_{}", candidate)
            } else {
                candidate
            }
        }
    };

    fs::write(&final_out_path, &result.payload)
        .map_err(|e| format!("Error al guardar {}: {}", final_out_path, e))?;

    println!("\x1b[1;31m[ÉXITO]\x1b[0m Archivo restaurado a su estado original: \x1b[1m{}\x1b[0m", final_out_path);
    println!("   -> Laberinto resuelto: {} caracoles analizados ({} señuelos neutralizados)", result.num_decoys + 1, result.num_decoys);
    println!("   -> Dimensión matriz  : {}x{}", result.dimension, result.dimension);

    if let Ok(text) = std::str::from_utf8(&result.payload) {
        if text.chars().all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t') && text.len() <= 1000 {
            println!("   -> Contenido: \"\x1b[1;31m{}\x1b[0m\"", text);
        }
    }

    if let Some(msg) = result.hidden_message {
        println!("\n\x1b[1;31m[MENSAJE SECRETO OCULTO]:\x1b[0m {}", msg);
    }

    Ok(())
}



/// Resuelve una llave obligatoria desde archivo o contraseña
fn resolve_required_key(key_path: Option<&str>, passphrase: Option<&str>) -> Result<SecureKey, String> {
    resolve_optional_key(key_path, passphrase)
        .ok_or_else(|| "Se requiere especificar una llave (-k <archivo.key>) o contraseña (-p <passphrase>)".to_string())
}

/// Resuelve una llave si fue proporcionada por bandera o existe una llave por defecto
fn resolve_optional_key(key_path: Option<&str>, passphrase: Option<&str>) -> Option<SecureKey> {
    // 1. Si se pasó una contraseña por -p
    if let Some(pass) = passphrase {
        let salt = b"caracol_v6_fixed_kdf_salt";
        let mut key_bytes = [0u8; 32];
        pbkdf2_sha256(pass.as_bytes(), salt, 100_000, &mut key_bytes);
        return Some(SecureKey::new(key_bytes));
    }

    // 2. Si se pasó una ruta por -k
    if let Some(path) = key_path {
        if let Ok(key) = load_key_from_file(path) {
            return Some(key);
        }
    }

    // 3. Revisar si existe ./caracol.key en el directorio local
    if Path::new("caracol.key").exists() {
        if let Ok(key) = load_key_from_file("caracol.key") {
            return Some(key);
        }
    }

    None
}

/// Carga y parsea una llave de 256 bits desde un archivo
fn load_key_from_file(path: &str) -> Result<SecureKey, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("No se pudo leer {}: {}", path, e))?;

    let lines: Vec<&str> = content.lines().map(|l| l.trim()).filter(|l| !l.is_empty()).collect();

    for line in lines {
        if line.starts_with("-----") {
            continue;
        }

        // Si es una cadena hexadecimal de 64 caracteres (32 bytes)
        if line.len() == 64 && line.chars().all(|c| c.is_ascii_hexdigit()) {
            let mut key = [0u8; 32];
            for i in 0..32 {
                key[i] = u8::from_str_radix(&line[i * 2..i * 2 + 2], 16).unwrap();
            }
            return Ok(SecureKey::new(key));
        }
    }

    // Si es binario puro de 32 bytes
    if let Ok(bin) = fs::read(path) {
        if bin.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bin);
            return Ok(SecureKey::new(key));
        }
    }

    Err(format!("Formato de llave inválido en {}", path))
}
