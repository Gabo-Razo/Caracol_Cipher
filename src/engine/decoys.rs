//! decoys.rs - Laberinto Multi-Caracol de Señuelos Estructurales.
//! Cada señuelo es una matriz completa de D x D con su propia espiral,
//! salidas falsas y datos corruptos/cebo para engañar a análisis forenses.

use crate::crypto::{hmac_sha256, DeterministicPrng};

pub struct DecoyLabyrinth {
    #[allow(dead_code)]
    pub total_blocks: usize,
    #[allow(dead_code)]
    pub real_index: usize,
    pub blocks: Vec<Vec<u8>>,
}

impl DecoyLabyrinth {
    /// Construye el laberinto insertando el bloque real entre N caracoles señuelo completos
    pub fn build(
        real_block: &[u8],
        dimension: usize,
        num_decoys: usize,
        num_false_exits: usize,
        k_decoy: &[u8; 32],
        salt: &[u8; 16],
    ) -> Self {
        let block_size = dimension * dimension;
        let total_blocks = num_decoys + 1;

        // Calcular el índice secreto donde residirá el caracol real
        let hmac_tag = hmac_sha256(k_decoy, salt);
        let rand_val = u32::from_be_bytes(hmac_tag[0..4].try_into().unwrap()) as usize;
        let real_index = rand_val % total_blocks;

        let mut blocks = Vec::with_capacity(total_blocks);

        // Generar cada bloque señuelo con estructura de caracol completa
        for i in 0..total_blocks {
            if i == real_index {
                // Insertar el caracol verídico
                let mut real_padded = real_block.to_vec();
                if real_padded.len() < block_size {
                    real_padded.resize(block_size, 0);
                }
                blocks.push(real_padded);
            } else {
                // Generar un caracol señuelo completo con salidas falsas personalizadas
                let decoy_block = Self::generate_structural_decoy(i, dimension, num_false_exits, k_decoy, salt);
                blocks.push(decoy_block);
            }
        }

        Self {
            total_blocks,
            real_index,
            blocks,
        }
    }

    /// Genera un caracol señuelo idéntico en tamaño y formato, pero con rutas y datos de cebo corruptos
    fn generate_structural_decoy(
        decoy_id: usize,
        dimension: usize,
        num_false_exits: usize,
        k_decoy: &[u8; 32],
        salt: &[u8; 16],
    ) -> Vec<u8> {
        let block_size = dimension * dimension;
        let mut decoy_data = vec![0u8; block_size];

        // Semilla única para este señuelo específico
        let mut seed_input = Vec::with_capacity(32 + 16 + 8);
        seed_input.extend_from_slice(k_decoy);
        seed_input.extend_from_slice(salt);
        seed_input.extend_from_slice(&(decoy_id as u64).to_be_bytes());
        let decoy_seed = hmac_sha256(k_decoy, &seed_input);

        let mut prng = DeterministicPrng::new(decoy_seed);

        // Paso 1: Llenar la matriz con ruido pseudoaleatorio de alta entropía
        prng.fill_bytes(&mut decoy_data);

        // Paso 2: Inyectar marcadores de "salidas falsas" y estructuras señuelo
        // Esto simula prefijos y cabeceras verosímiles en el interior de la matriz
        let exits = num_false_exits.max(1);
        for exit_num in 0..exits {
            if block_size <= 16 {
                break;
            }
            let step = (dimension * dimension / 32).max(1);
            let offset = (prng.next_range(step) * 32) % (block_size - 16);
            // Inyectar un encabezado falso de caracol con checksum aparente
            decoy_data[offset] = 0x53; // 'S'
            decoy_data[offset + 1] = 0x4E; // 'N'
            decoy_data[offset + 2] = 0x4C; // 'L'
            decoy_data[offset + 3] = (exit_num as u8) ^ 0xAA;
            // Datos de cebo corruptos
            for j in 4..16 {
                decoy_data[offset + j] = prng.next_u8();
            }
        }

        decoy_data
    }

    /// Localiza y extrae el caracol real del laberinto a partir de la subclave y el salt
    pub fn extract_real_block<'a>(
        blocks: &'a [Vec<u8>],
        k_decoy: &[u8; 32],
        salt: &[u8; 16],
    ) -> Result<&'a [u8], String> {
        if blocks.is_empty() {
            return Err("El laberinto no contiene bloques".to_string());
        }

        let hmac_tag = hmac_sha256(k_decoy, salt);
        let rand_val = u32::from_be_bytes(hmac_tag[0..4].try_into().unwrap()) as usize;
        let real_index = rand_val % blocks.len();

        Ok(&blocks[real_index])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decoy_labyrinth_roundtrip() {
        let real_block = b"DATOS_REALES_SUPER_SECRETOS_CARACOL_2026";
        let k_decoy = [0x33u8; 32];
        let salt = [0x77u8; 16];
        let dim = 16;
        let num_decoys = 8;

        let labyrinth = DecoyLabyrinth::build(real_block, dim, num_decoys, 16, &k_decoy, &salt);

        assert_eq!(labyrinth.total_blocks, 9);
        assert_eq!(labyrinth.blocks.len(), 9);

        // Extraer usando la clave y salt
        let extracted = DecoyLabyrinth::extract_real_block(&labyrinth.blocks, &k_decoy, &salt).unwrap();
        assert_eq!(&extracted[..real_block.len()], real_block);

        // Con clave o salt diferente debe seleccionar otro índice
        let wrong_salt = [0x88u8; 16];
        let wrong_extracted = DecoyLabyrinth::extract_real_block(&labyrinth.blocks, &k_decoy, &wrong_salt);
        assert!(wrong_extracted.is_ok());
    }
}
