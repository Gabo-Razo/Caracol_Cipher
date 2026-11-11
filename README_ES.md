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

## Inicio Rápido (30 Segundos)

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
  Si un tercero analiza el archivo con `caracol -a documento.pdf` sin tener la llave, el sistema reporta un documento limpio. Solo pasando `-k secreta.key` o `-p password` se valida el HMAC del ancla y se revela la existencia de la carga.
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
| `-k` | `--key <ruta.key>` | Todos | Archivo de llave privada de 256 bits (máxima seguridad CSPRNG) |
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

## Guía Práctica y Casos Didácticos

Esta sección está organizada para demostraciones técnicas, talleres y clases de criptografía práctica.

### 1. Métodos de Autenticación: Llave (`-k`) vs Contraseña (`-p`)

Caracol Cipher ofrece dos modelos de acceso independientes:

| Característica | Archivo de Llave (`-k clave.key`) | Contraseña (`-p "mi_clave"`) |
| :--- | :--- | :--- |
| **Origen de Entropía** | CSPRNG puro de 256 bits (`/dev/urandom` o `BCryptGenRandom`) | Texto plano derivado mediante PBKDF2 |
| **Rondas de Hash** | Directo de hardware/OS (2^256 combinaciones) | 100,000 iteraciones de HMAC-SHA256 con salt único |
| **Resistencia Forense** | Inmune a ataques de diccionario y fuerza bruta | Resistente contra aceleradores GPU/ASIC por coste PBKDF2 |
| **Caso de Uso Recomendado** | Infraestructura crítica, copias de seguridad, agentes | Operaciones rápidas en campo, intercambio verbal de claves |

#### Ejemplo con Archivo de Llave (`-k`):
```bash
# Paso 1: Generar archivo de llave privada
caracol keygen -o operacion.key

# Paso 2: Cifrar usando la llave
caracol seal -i reporte.pdf -o paquete.snail -k operacion.key -v

# Paso 3: Abrir usando la llave
caracol open -i paquete.snail -k operacion.key -v
```

#### Ejemplo con Contraseña Rápida (`-p`):
```bash
# Cifrar directamente con contraseña (no requiere generar archivo previo)
caracol seal -t "Credenciales de contingencia" -o backup.snail -p "MiPasswordRobusto!2026" -v

# Abrir directamente con la misma contraseña
caracol open -i backup.snail -p "MiPasswordRobusto!2026" -v
```

---

### 2. Modalidades de Carga: Texto, Archivos y Mensaje Secreto en Cabecera

#### A. Cifrado Directo de Texto (`-t`):
No necesitas crear un archivo de texto en disco. El texto cifrado se protege dentro del laberinto y al abrirlo se muestra en consola:
```bash
caracol seal -t "Coordenadas: 19.4326,-99.1332 | Canal 440MHz" -o coords.snail -p "ClaveAlpha" -v
caracol open -i coords.snail -p "ClaveAlpha" -v
```

#### B. Cifrado de Archivos Binarios Arbitrarios (`-i`):
Admite cualquier formato binario (`.docx`, `.xlsx`, `.gr`, `.zip`, `.pdf`, `.tar.gz`, etc.). Preserva el nombre y extensión originales:
```bash
caracol seal -i contrato_confidencial.docx -o contrato.snail -k operacion.key -v
caracol open -i contrato.snail -k operacion.key -v
# Restaura automaticamente el archivo 'contrato_confidencial.docx' intacto
```

#### C. Doble Carga: Archivo Principal + Mensaje Secreto en Cabecera (`-m`):
Permite incluir una carga principal (archivo o texto) y adjuntar simultáneamente un mensaje secreto que se revela de forma destacada al descifrar:
```bash
caracol seal -i base_datos.sqlite \
    -m "AVISO: Esta base de datos expira en 24 horas. Destruir despues de leer." \
    -o base.snail \
    -p "ClaveDeAccesoSegura" -v

# Al abrir:
caracol open -i base.snail -p "ClaveDeAccesoSegura" -v
```
Salida en consola:
```text
[ÉXITO] Archivo restaurado a su estado original: base_datos.sqlite
[MENSAJE SECRETO OCULTO]: AVISO: Esta base de datos expira en 24 horas. Destruir despues de leer.
```

---

### 3. Esteganografía en Documentos Legítimos (`hide` / `extract`)

Inyecta cargas cifradas dentro de documentos existentes (PDF, PNG, JPG, ZIP). El archivo resultante mantiene su aspecto, funcionalidad y tamaño percibido normales:

```bash
# Inyectar una hoja de calculo (balance.xlsx) dentro de un PDF corporativo legitimo
caracol hide -c manual_publico.pdf -i balance.xlsx -o manual_distribuible.pdf -k operacion.key -v

# Opcional: Agregar mensaje secreto en cabecera esteganografica
caracol hide -c foto_oficina.png -t "Canal alterno: radio 144.200 MHz" \
    -m "Contacto de enlace en sitio seguro" \
    -o foto_compartida.png -p "ClaveCampo" -v
```

#### Cómo extraer el contenido oculto:
```bash
# Extraer restaurando el nombre y extension originales
caracol extract -i manual_distribuible.pdf -k operacion.key -v

# Extraer indicando un nombre de salida personalizado
caracol extract -i manual_distribuible.pdf -o balance_recuperado.xlsx -k operacion.key -v
```

---

### 4. Inspección Forense con Conocimiento Cero (`-a`)

Demostración en clase de cómo reacciona un analista con herramientas forenses frente al Ancla ZKS:

```bash
# 1. Un tercero o analista forense inspecciona el PDF distribuido:
caracol -a manual_distribuible.pdf
```
Salida:
```text
  Archivo analizado  : manual_distribuible.pdf
  Formato detectado  : Documento Adobe PDF
  Tamaño total       : 184520 bytes (180.20 KB)
  Fin legitimo (EOF) : byte 184520
  [i] MODO SIGILOSO ACTIVO: No se detecto ninguna firma publica en texto plano.
```

```bash
# 2. El destinatario legitimo inspecciona con su llave privada o contrasena:
caracol -a manual_distribuible.pdf -k operacion.key
```
Salida:
```text
  [CARGA CARACOL DETECTADA Y AUTENTICADA]
  Offset de inyeccion: byte 184520
  Dimension Matriz   : 128x128 (16384 celdas/caracol)
  Laberinto Caracol  : 9 caracoles (1 Real + 8 Señuelos Estructurales)
  Estado             : Cifrado con llave privada verificada (HMAC OK)
```

---

### 5. Laboratorio Avanzado: Anidamiento Matrioshka Multicapa (Denegación Plausible)

Este ejercicio demuestra la técnica de capas esteganográficas anidadas para escenarios de coacción o inspección hostil.

```text
[PDF Publico: contrato.pdf]
     └── Oculta [PNG: diagrama.png] (Clave 3)
              └── Oculta [XLSX: contabilidad.xlsx] (Clave 2)
                       └── Oculta [SNAIL: nivel1.snail] (Clave 1)
                                └── Contiene [TXT: coordenadas_reales.txt]
```

#### Paso 1: Crear el núcleo secreto
```bash
caracol seal -t "OBJETIVO: Servidor central IP 10.0.0.50 | Credenciales: admin/root_key" \
    -m "Nivel de seguridad Alpha: Solo para el comandante de mision" \
    -o nivel1.snail \
    -p "Clave1_UltraSecreta" -v
```

#### Paso 2: Ocultar el contenedor en una hoja de cálculo señuelo
```bash
# Ocultamos nivel1.snail dentro de un Excel real
caracol hide -c contabilidad.xlsx -i nivel1.snail -o contabilidad_auditada.xlsx -p "Clave2_Finanzas" -v
```

#### Paso 3: Ocultar el Excel dentro de una imagen PNG señuelo
```bash
# Ocultamos contabilidad_auditada.xlsx dentro de diagrama.png
caracol hide -c diagrama.png -i contabilidad_auditada.xlsx -o diagrama_final.png -p "Clave3_Marketing" -v
```

#### Paso 4: Ocultar la imagen PNG dentro de un PDF oficial público
```bash
# Ocultamos diagrama_final.png dentro de informe_legal.pdf
caracol hide -c informe_legal.pdf -i diagrama_final.png -o informe_distribuible.pdf -p "Clave4_Publica" -v
```

#### Procedimiento de extracción inversa en el aula:
1. **Bajo coacción en el Nivel 4**: Entregas `Clave4_Publica`. El examinador extrae `diagrama_final.png`, una imagen PNG válida y visible. El examinador cree que ha obtenido el contenido secreto.
   ```bash
   caracol extract -i informe_distribuible.pdf -p "Clave4_Publica" -v
   ```
2. **Si el examinador sospecha y exige Nivel 3**: Entregas `Clave3_Marketing`. El examinador extrae `contabilidad_auditada.xlsx`, una hoja de cálculo Excel funcional con fórmulas y números creíbles.
   ```bash
   caracol extract -i diagrama_final.png -p "Clave3_Marketing" -v
   ```
3. **El receptor real con acceso completo continúa**:
   ```bash
   caracol extract -i contabilidad_auditada.xlsx -p "Clave2_Finanzas" -v
   # Obtiene nivel1.snail

   caracol open -i nivel1.snail -p "Clave1_UltraSecreta" -v
   # Revela las coordenadas y el mensaje secreto de mision
   ```

---

### 6. Arquitectura del Laberinto y Auto-Resolución

Puedes ajustar la complejidad de cada contenedor mediante banderas de geometría:

```bash
caracol seal -i archivo.zip -o bunker.snail -p "ClaveBunker" \
    --dim 256 \
    --decoys 32 \
    --false-exits 64 \
    -v
```
* **`--dim 256`**: Matriz NxN de 256x256 posiciones (65,536 celdas de permutación por cada caracol).
* **`--decoys 32`**: 32 matrices señuelo idénticas en estructura al caracol real.
* **`--false-exits 64`**: 64 salidas trampa con cabeceras falsas por cada señuelo (2,048 rutas señuelo).

#### El principio de Auto-Resolución:
Para descifrar **NUNCA necesitas pasar `--dim`, `--decoys` ni `--false-exits`**. El destinatario solo ejecuta:
```bash
caracol open -i bunker.snail -p "ClaveBunker" -v
```
El motor criptográfico utiliza la llave de derivación para ubicar la trayectoria geométrica exacta en tiempo constante O(1), resolviendo el laberinto de forma instantánea.

---

## Licencia

GNU General Public License v3.0 ([GPL-3.0](LICENSE)).
Cualquier modificación o trabajo derivado debe permanecer como código abierto bajo la misma licencia GPL-3.0.
