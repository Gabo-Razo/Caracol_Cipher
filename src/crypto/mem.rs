//! mem.rs - Seguridad en RAM y mitigación anti-forense.
//! Implementa destrucción forzada de memoria sensible en el Drop
//! usando operaciones volátiles para impedir que el compilador las optimice.

use std::ops::{Deref, DerefMut};

/// Sobrescribe una porción de memoria con ceros utilizando escrituras volátiles.
/// Esto garantiza que el compilador LLVM no elimine la operación como "código muerto".
pub fn zeroize_slice(slice: &mut [u8]) {
    unsafe {
        let ptr = slice.as_mut_ptr();
        for i in 0..slice.len() {
            std::ptr::write_volatile(ptr.add(i), 0u8);
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// Buffer dinámico seguro que se auto-destruye en memoria RAM cuando sale de contexto.
#[derive(Debug, Clone)]
pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    #[allow(dead_code)]
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn zeroed(size: usize) -> Self {
        Self {
            data: vec![0u8; size],
        }
    }

    #[allow(dead_code)]
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    #[allow(dead_code)]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    #[allow(dead_code)]
    pub fn into_vec(mut self) -> Vec<u8> {
        let vec = std::mem::take(&mut self.data);
        vec
    }
}

impl Deref for SecureBuffer {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl DerefMut for SecureBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        zeroize_slice(&mut self.data);
    }
}

/// Contenedor de clave secreta de 32 bytes con auto-destrucción forense en RAM.
#[derive(Clone)]
pub struct SecureKey {
    key: [u8; 32],
}

impl SecureKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

impl Drop for SecureKey {
    fn drop(&mut self) {
        zeroize_slice(&mut self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zeroize() {
        let mut secret = vec![0xAA; 16];
        zeroize_slice(&mut secret);
        assert_eq!(secret, vec![0u8; 16]);
    }
}
