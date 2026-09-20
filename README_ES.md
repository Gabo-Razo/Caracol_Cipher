# Caracol Cipher v6.0

```text
         .----.   @   @         .--------.
        / .-"-.`.  \v/         /        /|
        | | '\ \ \_/ )  --->  +--------+ |
      ,-\ `-.' /.'  /         |  [__]  | /
     '---`----'----'          +--------+'
```

[English](README.md) | [Español](README_ES.md)

> Herramienta CLI para cifrado geométrico SPN 2D y esteganografía sigilosa con conocimiento cero.
> Rust nativo puro (`std`). Cero dependencias externas. Binarios precompilados para Linux, Windows y ARM64.

`caracol` permite cifrar cualquier tipo de archivo en contenedores autónomos `.snail` o inyectarlos de forma invisible dentro de documentos portadores (PDF, PNG, JPG, ZIP) sin corromper el documento original ni alertar a los visores del sistema.

---

## Instalación

### Instalador automático en una línea (Linux / ARM64 / Raspberry Pi)
Detecta tu sistema operativo, arquitectura y tipo de librería C (glibc o musl), y descarga el binario correcto:

```bash
curl -fsSL https://raw.githubusercontent.com/Gabo-Razo/Caracol_Cipher/main/install.sh | bash
```

### Binarios Precompilados (Releases)
Binarios standalone despojados de símbolos (`stripped`). No requieren instalar Rust ni librerías externas:

| Plataforma / Arquitectura | Binario | Tamaño | Notas |
| :--- | :--- | :--- | :--- |
| **Linux x86_64** | [`caracol-linux-x86_64`](https://github.com/Gabo-Razo/Caracol_Cipher/releases/latest/download/caracol-linux-x86_64) | 430 KB | GLIBC (Ubuntu, Debian, Kali, Fedora, Arch) |
| **Linux x86_64 (Estático)** | [`caracol-linux-x86_64-musl`](https://github.com/Gabo-Razo/Caracol_Cipher/releases/latest/download/caracol-linux-x86_64-musl) | 517 KB | MUSL estático. Corre en cualquier Linux / Alpine / Docker |
| **Linux ARM64** | [`caracol-linux-aarch64`](https://github.com/Gabo-Razo/Caracol_Cipher/releases/latest/download/caracol-linux-aarch64) | 389 KB | Raspberry Pi 4/5, AWS Graviton, servidores ARM |
| **Windows x86_64** | [`caracol-windows-x86_64.exe`](https://github.com/Gabo-Razo/Caracol_Cipher/releases/latest/download/caracol-windows-x86_64.exe) | 386 KB | Windows 10/11 x64 (usa CSPRNG Win32 `BCryptGenRandom`) |

Sumas de verificación disponibles en [`SHA256SUMS.txt`](https://github.com/Gabo-Razo/Caracol_Cipher/releases/latest/download/SHA256SUMS.txt).

---

## Inicio Rápido

```bash
# 1. Generar una llave privada de 256 bits (permisos seguros 0600)
caracol keygen -o secreta.key

# 2. Cifrar un archivo confidencial en un contenedor .snail
caracol seal -i balance.xlsx -o archivo.snail -k secreta.key -v

# 3. Ocultar un documento Word dentro de un PDF legítimo (el PDF abre con normalidad)
caracol hide -c informe_publico.pdf -i contrato.docx -o entregable.pdf -k secreta.key -v

# 4. Extraer y restaurar el documento original idéntico
caracol extract -i entregable.pdf -k secreta.key -v
```

---

## Capacidades Principales

* **Esteganografía Sigilosa (`hide` / `extract`)**:
  Inyecta la carga cifrada después de las marcas de fin de archivo legítimas (PDF `%%EOF`, PNG `IEND`, JPEG `EOI`). Visores como Adobe Acrobat o visores de imágenes abren el documento normalmente.
* **Ancla con Conocimiento Cero (*Zero-Knowledge Anchor*)**:
  Si un tercero analiza el archivo con `caracol -a documento.pdf` sin tener la llave, el sistema reporta un documento limpio. Solo pasando `-k secreta.key` se valida el HMAC del ancla y se revela la existencia de la carga.
* **Laberinto de Señuelos (`--decoys`, `--false-exits`)**:
  Genera matrices falsas con rutas señuelo y trampas de datos cebo para dificultar y desviar cualquier análisis forense.
* **Descifrado con Auto-Resolución**:
  El destinatario únicamente necesita su llave (`-k`) o contraseña (`-p`). No requiere saber la dimensión de la matriz ni cuántos señuelos se usaron; el contenedor se resuelve en tiempo constante.
* **Seguridad en Memoria RAM**:
  Las llaves y buffers en texto plano se destruyen forzadamente al salir del scope mediante `write_volatile` para evitar volcados forenses de memoria (`/proc/$PID/mem`).
* **Cero Crates Externos**:
  100% Rust nativo (`std`). Incluye implementaciones propias y limpias de SHA-256, HMAC, HKDF, PBKDF2 (100k rondas) y CSPRNG por sistema operativo.

---

## Tabla de Banderas (Flags)

| Bandera | Nombre Largo | Subcomandos | Descripción |
| :--- | :--- | :--- | :--- |
| `-k` | `--key <ruta.key>` | Todos | Archivo de llave privada de 256 bits |
| `-p` | `--passphrase <txt>`| Todos | Contraseña alternativa (derivada con PBKDF2 a 100k rondas) |
| `-i` | `--in <archivo>` | `seal`, `hide`, `extract`, `open` | Archivo de entrada a cifrar o contenedor a abrir |
| `-t` | `--text <texto>` | `seal`, `hide` | Texto directo a cifrar (sin archivo previo) |
| `-o` | `--out <archivo>`| Todos | Ruta del archivo de salida |
| `-c` | `--carrier <doc>`| `hide` | Archivo anfitrión legítimo (PDF, PNG, JPG, ZIP) |
| `-m` | `--message <txt>`| `seal`, `hide` | Mensaje secreto secundario visible solo al descifrar |
| `-v` | `--visual` | Todos | Muestra animación interactiva en terminal (rojo ANSI) |
| `--dim` | `--dim <N>` | `seal`, `hide` | Dimensión de matriz NxN por caracol (defecto: 128) |
| `--decoys` | `--decoys <N>` | `seal`, `hide` | Cantidad de caracoles señuelo en el laberinto (defecto: 8) |
| `--false-exits` | `--exits <N>` | `seal`, `hide` | Salidas falsas y trampas por señuelo (defecto: 16) |

---

## Ejemplos de Uso

### Arquitectura de Laberinto Personalizada
Genera laberintos masivos para almacenamiento de alta seguridad:
```bash
caracol seal -i datos.zip -o seguro.snail -p "MiPassword123" \
    --dim 256 \
    --decoys 32 \
    --false-exits 64 \
    -v
```
Para abrirlo, solo necesitas la contraseña:
```bash
caracol open -i seguro.snail -p "MiPassword123" -v
```

### Análisis Forense Sigiloso (`-a`)
```bash
# Sin llave: reporta documento limpio sin firmas
caracol -a entregable.pdf

# Con llave correcta: autentica el HMAC y muestra los datos del contenedor
caracol -a entregable.pdf -k secreta.key
```

### Anidamiento Matrioshka (Denegación Plausible)
1. Cifrar archivo confidencial: `caracol seal -t "Semilla Secreta" -o capa1.snail -p "Clave1"`
2. Ocultar `capa1.snail` en un Excel: `caracol hide -c libro.xlsx -i capa1.snail -o libro_mod.xlsx -p "Clave2"`
3. Ocultar `libro_mod.xlsx` en una imagen PNG: `caracol hide -c foto.png -i libro_mod.xlsx -o final.png -p "Clave3"`

Bajo coacción, entregar `Clave3` solo revela un archivo de Excel legítimo y funcional, sin forma matemática de sospechar que dentro existe otro contenedor `.snail`.

---

## Licencia

GNU General Public License v3.0 ([GPL-3.0](LICENSE)).
Cualquier modificación o trabajo derivado debe permanecer como código abierto bajo la misma licencia GPL-3.0.
