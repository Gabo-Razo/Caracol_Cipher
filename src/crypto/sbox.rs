//! sbox.rs - Generación de S-Boxes dinámicas para la capa de Confusión (SPN).
//! Crea una permutación no lineal biyectiva a partir de la subclave usando Fisher-Yates.

use super::rand::DeterministicPrng;

/// Contenedor de la tabla de sustitución S-Box y su tabla inversa
pub struct DynamicSBox {
    forward: [u8; 256],
    inverse: [u8; 256],
}

impl DynamicSBox {
    /// Genera un par de S-Box (directa e inversa) a partir de una semilla criptográfica de 32 bytes
    pub fn new(seed_key: [u8; 32]) -> Self {
        let mut forward = [0u8; 256];
        for i in 0..256 {
            forward[i] = i as u8;
        }

        let mut prng = DeterministicPrng::new(seed_key);

        // Algoritmo Fisher-Yates para barajar uniformemente los 256 valores
        for i in (1..256).rev() {
            let j = prng.next_range(i + 1);
            forward.swap(i, j);
        }

        // Construcción de la tabla inversa para el descifrado exacto
        let mut inverse = [0u8; 256];
        for (i, &val) in forward.iter().enumerate() {
            inverse[val as usize] = i as u8;
        }

        Self { forward, inverse }
    }

    /// Aplica la sustitución no lineal hacia adelante sobre un buffer de bytes
    pub fn substitute(&self, data: &mut [u8]) {
        for b in data.iter_mut() {
            *b = self.forward[*b as usize];
        }
    }

    /// Revierte la sustitución no lineal utilizando la tabla inversa
    pub fn inv_substitute(&self, data: &mut [u8]) {
        for b in data.iter_mut() {
            *b = self.inverse[*b as usize];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbox_invertibility() {
        let seed = [0x55u8; 32];
        let sbox = DynamicSBox::new(seed);

        let original = b"Hola Mundo Caracol Criptografico 2026";
        let mut data = original.to_vec();

        // Aplicar sustitución
        sbox.substitute(&mut data);
        assert_ne!(&data[..], original);

        // Revertir sustitución
        sbox.inv_substitute(&mut data);
        assert_eq!(&data[..], original);
    }
}
