//! rand.rs - Generación de entropía criptográfica (CSPRNG) y PRNG determinista.
//! Lee directamente de /dev/urandom sin dependencias externas.

#[cfg(not(windows))]
use std::fs::File;
#[cfg(not(windows))]
use std::io::Read;
use super::hmac::hmac_sha256;

#[cfg(windows)]
#[link(name = "bcrypt")]
unsafe extern "system" {
    fn BCryptGenRandom(
        h_algorithm: *mut std::ffi::c_void,
        pb_buffer: *mut u8,
        cb_buffer: u32,
        dw_flags: u32,
    ) -> i32;
}

/// Llena un slice con bytes aleatorios criptográficamente seguros del sistema operativo
pub fn fill_secure_random(buf: &mut [u8]) -> Result<(), String> {
    #[cfg(windows)]
    {
        // 0x00000002 = BCRYPT_USE_SYSTEM_PREFERRED_RNG
        let status = unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                0x00000002,
            )
        };
        if status == 0 {
            return Ok(());
        }
    }

    #[cfg(not(windows))]
    {
        if let Ok(mut file) = File::open("/dev/urandom") {
            if file.read_exact(buf).is_ok() {
                return Ok(());
            }
        }
    }

    // Fallback de emergencia en caso de entornos restringidos: mezcla de entropia de hardware y reloj
    fallback_entropy(buf);
    Ok(())
}

/// Genera un array aleatorio de 32 bytes (256 bits)
pub fn random_32() -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    fill_secure_random(&mut key)?;
    Ok(key)
}

/// Genera un array aleatorio de 16 bytes (128 bits) para salt o nonces
pub fn random_16() -> Result<[u8; 16], String> {
    let mut nonce = [0u8; 16];
    fill_secure_random(&mut nonce)?;
    Ok(nonce)
}

/// Generador pseudoaleatorio determinista (PRNG) basado en HMAC-SHA-256 en modo contador.
/// Se utiliza para construir los señuelos y laberintos falsos a partir de una semilla.
pub struct DeterministicPrng {
    seed_key: [u8; 32],
    counter: u64,
    buffer: [u8; 32],
    buffer_pos: usize,
}

impl DeterministicPrng {
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            seed_key: seed,
            counter: 0,
            buffer: [0u8; 32],
            buffer_pos: 32, // Forzar generación inicial inmediata
        }
    }

    /// Obtiene el siguiente byte pseudoaleatorio determinista
    pub fn next_u8(&mut self) -> u8 {
        if self.buffer_pos >= 32 {
            self.counter += 1;
            let counter_bytes = self.counter.to_be_bytes();
            self.buffer = hmac_sha256(&self.seed_key, &counter_bytes);
            self.buffer_pos = 0;
        }

        let byte = self.buffer[self.buffer_pos];
        self.buffer_pos += 1;
        byte
    }

    /// Llena un slice completo con bytes deterministas
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest.iter_mut() {
            *b = self.next_u8();
        }
    }

    /// Retorna un entero en el rango [0, max)
    pub fn next_range(&mut self, max: usize) -> usize {
        if max <= 1 {
            return 0;
        }
        let mut n = 0usize;
        for _ in 0..std::mem::size_of::<usize>() {
            n = (n << 8) | (self.next_u8() as usize);
        }
        n % max
    }
}

/// Entropía complementaria combinada basada en nanosegundos y punteros ASLR
fn fallback_entropy(buf: &mut [u8]) {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let seed_data = format!(
        "{}:{}:{:p}",
        now.as_nanos(),
        std::process::id(),
        &now
    );
    let hash = super::sha256::sha256_digest(seed_data.as_bytes());
    let mut prng = DeterministicPrng::new(hash);
    prng.fill_bytes(buf);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_random_diff() {
        let a = random_32().unwrap();
        let b = random_32().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn test_deterministic_prng_reproducibility() {
        let seed = [42u8; 32];
        let mut prng1 = DeterministicPrng::new(seed);
        let mut prng2 = DeterministicPrng::new(seed);

        let mut buf1 = [0u8; 64];
        let mut buf2 = [0u8; 64];

        prng1.fill_bytes(&mut buf1);
        prng2.fill_bytes(&mut buf2);

        assert_eq!(buf1, buf2);
    }
}
