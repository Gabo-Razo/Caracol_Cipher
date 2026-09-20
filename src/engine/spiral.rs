//! spiral.rs - Motor geométrico Caracol: cálculo de cuadrícula 2D, recorrido en espiral
//! y mutaciones de ruta gobernadas por la subclave de sesión (K_spiral).

/// Estructura que gestiona la geometría de la matriz y el recorrido en espiral
pub struct SnailSpiral {
    #[allow(dead_code)]
    pub dimension: usize,
    pub total_cells: usize,
    pub path: Vec<usize>,
}

impl SnailSpiral {
    /// Calcula la dimensión mínima necesaria para alojar los datos y construye la ruta mutada por la clave
    pub fn new(data_len: usize, min_dim: usize, key_spiral: &[u8; 32]) -> Self {
        let dimension = Self::calculate_dimension(data_len, min_dim);
        let total_cells = dimension * dimension;
        let mut path = Self::generate_flat_spiral(dimension);

        // Mutar la trayectoria geométrica utilizando los bits de la clave de espiral
        Self::mutate_path(&mut path, total_cells, key_spiral);

        Self {
            dimension,
            total_cells,
            path,
        }
    }

    /// Determina la dimensión N x N requerida (redondeada a múltiplos pares)
    pub fn calculate_dimension(needed_bytes: usize, min_dim: usize) -> usize {
        let mut dim = min_dim.max(16);
        while dim * dim < needed_bytes {
            dim += 16;
        }
        dim
    }

    /// Genera la espiral base en sentido horario (de afuera hacia adentro)
    /// Retorna un vector con los índices planos de la matriz en el orden de visita.
    fn generate_flat_spiral(dim: usize) -> Vec<usize> {
        let mut path = Vec::with_capacity(dim * dim);
        let mut top = 0;
        let mut bottom = dim.saturating_sub(1);
        let mut left = 0;
        let mut right = dim.saturating_sub(1);

        while top <= bottom && left <= right {
            // 1. Moverse hacia la derecha a lo largo del borde superior
            for col in left..=right {
                path.push(top * dim + col);
            }
            top += 1;

            // 2. Moverse hacia abajo a lo largo del borde derecho
            for row in top..=bottom {
                path.push(row * dim + right);
            }
            if right == 0 {
                break;
            }
            right -= 1;

            // 3. Moverse hacia la izquierda a lo largo del borde inferior
            if top <= bottom {
                for col in (left..=right).rev() {
                    path.push(bottom * dim + col);
                }
                if bottom == 0 {
                    break;
                }
                bottom -= 1;
            }

            // 4. Moverse hacia arriba a lo largo del borde izquierdo
            if left <= right {
                for row in (top..=bottom).rev() {
                    path.push(row * dim + left);
                }
                left += 1;
            }
        }

        path
    }

    /// Aplica mutaciones deterministas a la espiral usando la clave (rotaciones e inversiones)
    fn mutate_path(path: &mut [usize], total_cells: usize, key_spiral: &[u8; 32]) {
        let len = path.len();
        if len == 0 {
            return;
        }

        for (round, &byte) in key_spiral.iter().enumerate() {
            // Cada byte de la clave determina la magnitud y dirección de rotación
            let rot_amount = ((byte as usize) * (total_cells / 32)) % len;
            if byte % 2 == 0 {
                path.rotate_left(rot_amount);
            } else {
                path.rotate_right(rot_amount);
            }

            // Cada 4 rondas, si el byte tiene alta entropía, invierte segmentos de la trayectoria
            if round % 4 == 3 && byte > 127 {
                let mid = len / 2;
                path[..mid].reverse();
                path[mid..].reverse();
            }
        }
    }

    /// Permuta los bytes del plano siguiendo el camino del caracol
    pub fn transpose(&self, input: &[u8]) -> Vec<u8> {
        let mut output = vec![0u8; self.total_cells];
        for (i, &source_idx) in self.path.iter().enumerate() {
            if source_idx < input.len() {
                output[i] = input[source_idx];
            }
        }
        output
    }

    /// Reinvierte la permutación restaurando los bytes a su posición original
    pub fn inv_transpose(&self, input: &[u8]) -> Vec<u8> {
        let mut output = vec![0u8; self.total_cells];
        for (i, &source_idx) in self.path.iter().enumerate() {
            if i < input.len() && source_idx < output.len() {
                output[source_idx] = input[i];
            }
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spiral_reversibility() {
        let key = [0x99u8; 32];
        let dim = 32;
        let spiral = SnailSpiral::new(dim * dim, dim, &key);

        // Crear datos de prueba secuenciales
        let mut original = vec![0u8; dim * dim];
        for (i, b) in original.iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }

        // Permutar
        let permuted = spiral.transpose(&original);
        assert_ne!(permuted, original);

        // Des-permutar
        let restored = spiral.inv_transpose(&permuted);
        assert_eq!(restored, original);
    }
}
