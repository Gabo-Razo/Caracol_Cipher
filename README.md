# Caracol Cipher v6.0

```text
         .----.   @   @         .--------.
        / .-"-.`.  \v/         /        /|
        | | '\ \ \_/ )  --->  +--------+ |
      ,-\ `-.' /.'  /         |  [__]  | /
     '---`----'----'          +--------+'
```

[English](README.md) | [Español](README_ES.md)

> Standalone CLI for 2D SPN spiral encryption and zero-knowledge steganography.
> Pure Rust. Zero dependencies. Single-binary releases for Linux, Windows, and ARM64.

`caracol` lets you encrypt arbitrary files into standalone `.snail` containers or inject them invisibly into carrier documents (PDF, PNG, JPG, ZIP) without breaking carrier formatting or triggering standard file scanners.

---

## Install

### One-line installer (Linux / ARM64 / Raspberry Pi)
Detects OS, architecture, and libc (glibc vs musl), then downloads and installs the binary:

```bash
curl -fsSL https://raw.githubusercontent.com/Gabo-Razo/Caracol_Cipher/main/install.sh | bash
```

### Precompiled Binaries (Releases)
Standalone, stripped binaries. No Rust toolchain or external libraries needed:

| Platform / Arch | Binary | Size | Notes |
| :--- | :--- | :--- | :--- |
| **Linux x86_64** | [`caracol-linux-x86_64`](https://github.com/Gabo-Razo/Caracol_Cipher/releases/latest/download/caracol-linux-x86_64) | 430 KB | GLIBC (Ubuntu, Debian, Kali, Fedora, Arch) |
| **Linux x86_64 (Static)** | [`caracol-linux-x86_64-musl`](https://github.com/Gabo-Razo/Caracol_Cipher/releases/latest/download/caracol-linux-x86_64-musl) | 517 KB | MUSL static. Runs on any Linux distro / Alpine / Docker |
| **Linux ARM64** | [`caracol-linux-aarch64`](https://github.com/Gabo-Razo/Caracol_Cipher/releases/latest/download/caracol-linux-aarch64) | 389 KB | Raspberry Pi 4/5, AWS Graviton, ARM servers |
| **Windows x86_64** | [`caracol-windows-x86_64.exe`](https://github.com/Gabo-Razo/Caracol_Cipher/releases/latest/download/caracol-windows-x86_64.exe) | 386 KB | Windows 10/11 x64 (uses native `BCryptGenRandom`) |

Checksums available in [`SHA256SUMS.txt`](https://github.com/Gabo-Razo/Caracol_Cipher/releases/latest/download/SHA256SUMS.txt).

---

## Quickstart (30 Seconds)

```bash
# 1. Generate a 256-bit private key (permissions 0600)
caracol keygen -o secret.key

# 2. Seal a confidential file into a .snail vault
caracol seal -i budget.xlsx -o vault.snail -k secret.key -v

# 3. Hide a Word doc inside a legitimate PDF (carrier opens normally)
caracol hide -c public_report.pdf -i contract.docx -o distributed.pdf -k secret.key -v

# 4. Extract and restore the hidden file
caracol extract -i distributed.pdf -k secret.key -v
```

---

## Core Capabilities

* **Carrier Steganography (`hide` / `extract`)**:
  Appends ciphertext after legitimate file markers (PDF `%%EOF`, PNG `IEND`, JPEG `EOI`). Viewers and office suites open the carrier document normally without showing errors.
* **Zero-Knowledge Stealth Anchor**:
  Third parties running `caracol -a distributed.pdf` without your key will see a clean file with zero detected signatures. Only providing `-k secret.key` or `-p password` validates the HMAC anchor and reveals the payload.
* **Decoy Labyrinths (`--decoys`, `--false-exits`)**:
  Generates fake structural snail matrices with decoy paths and corrupted honey-tokens to misdirect forensic analysis.
* **Auto-Resolving Decryption**:
  The recipient only needs the key (`-k`) or passphrase (`-p`). Matrix dimensions, decoy counts, and original file names are resolved automatically in constant time.
* **Anti-Forensic Memory Security**:
  All cryptographic keys and plaintext buffers are wiped on drop using `write_volatile` compiler fences to resist RAM dumping (`/proc/$PID/mem`).
* **Zero External Crates**:
  100% native Rust `std`. Includes self-contained implementations of SHA-256, HMAC, HKDF, PBKDF2 (100k rounds), and OS-level CSPRNG.

---

## Flags Cheatsheet

| Flag | Long Flag | Commands | Description |
| :--- | :--- | :--- | :--- |
| `-k` | `--key <path.key>` | All | 256-bit private key file (CSPRNG hardware entropy) |
| `-p` | `--passphrase <text>`| All | Alternative passphrase (PBKDF2 derived at 100k rounds) |
| `-i` | `--in <file>` | `seal`, `hide`, `extract`, `open` | Input file to encrypt or container to open |
| `-t` | `--text <text>` | `seal`, `hide` | Encrypt inline text directly |
| `-o` | `--out <file>` | All | Output file path |
| `-c` | `--carrier <doc>` | `hide` | Carrier document (PDF, PNG, JPG, ZIP) |
| `-m` | `--message <text>`| `seal`, `hide` | Secondary secret message shown only on decryption |
| `-v` | `--visual` | All | Terminal ASCII animation (ANSI red) |
| `--dim` | `--dim <N>` | `seal`, `hide` | Matrix dimension per snail (default: 128) |
| `--decoys` | `--decoys <N>` | `seal`, `hide` | Number of decoy snails in labyrinth (default: 8) |
| `--false-exits` | `--exits <N>` | `seal`, `hide` | Decoy exits per trap (default: 16) |

---

## Practical Field Guide & Pedagogical Labs

This guide is structured for workshops, security lectures, and tactical demonstrations.

### 1. Authentication Models: Key File (`-k`) vs Passphrase (`-p`)

Caracol Cipher provides two independent access mechanisms:

| Feature | Key File (`-k secret.key`) | Passphrase (`-p "password"`) |
| :--- | :--- | :--- |
| **Entropy Source** | Pure 256-bit CSPRNG (`/dev/urandom` or `BCryptGenRandom`) | Plaintext password stretched via PBKDF2 |
| **Hash Rounds** | Direct OS entropy (2^256 combinations) | 100,000 rounds of HMAC-SHA256 with unique salt |
| **Forensic Resistance** | Immune to dictionary and rainbow table attacks | GPU/ASIC resistant due to PBKDF2 iteration cost |
| **Recommended Use** | Critical infrastructure, backups, automated pipelines | Rapid field exchange, memorable passwords |

#### Workflow with Key File (`-k`):
```bash
# Step 1: Generate 256-bit private key
caracol keygen -o deploy.key

# Step 2: Seal payload with key
caracol seal -i report.pdf -o vault.snail -k deploy.key -v

# Step 3: Open vault with key
caracol open -i vault.snail -k deploy.key -v
```

#### Workflow with Fast Passphrase (`-p`):
```bash
# Seal text payload directly with a passphrase (no file pre-generation needed)
caracol seal -t "Emergency access token: ABCD-1234-EFGH" -o token.snail -p "StrongPassphrase!2026" -v

# Open vault with passphrase
caracol open -i token.snail -p "StrongPassphrase!2026" -v
```

---

### 2. Payload Types: Inline Text, Files, and Dual Header Message

#### A. Direct Inline Text (`-t`):
No temporary disk files needed. When decrypted, the text is printed directly to the console:
```bash
caracol seal -t "Coordinates: 19.4326,-99.1332 | Channel: 440MHz" -o target.snail -p "SecretOps" -v
caracol open -i target.snail -p "SecretOps" -v
```

#### B. Arbitrary Binary Files (`-i`):
Accepts any file type (`.docx`, `.xlsx`, `.gr`, `.zip`, `.pdf`, `.tar.gz`, etc.). Preserves original name and format byte-for-byte:
```bash
caracol seal -i sensitive_contracts.docx -o contracts.snail -k deploy.key -v
caracol open -i contracts.snail -k deploy.key -v
# Automatically restores 'sensitive_contracts.docx'
```

#### C. Dual Payload: Primary File + Secret Header Message (`-m`):
Attach a secondary text note to any file payload. The message is revealed distinctly upon decryption:
```bash
caracol seal -i database.sqlite \
    -m "NOTICE: This database expires in 24 hours. Destroy after extraction." \
    -o database.snail \
    -p "DBAccessSecret" -v

# On decrypt:
caracol open -i database.snail -p "DBAccessSecret" -v
```
Output:
```text
[ÉXITO] Archivo restaurado a su estado original: database.sqlite
[MENSAJE SECRETO OCULTO]: NOTICE: This database expires in 24 hours. Destroy after extraction.
```

---

### 3. Carrier Document Steganography (`hide` / `extract`)

Inject encrypted payloads into existing host documents (PDF, PNG, JPG, ZIP). The host file remains completely valid and visual appearance is unaltered:

```bash
# Inject Excel sheet into a legitimate corporate PDF
caracol hide -c annual_report.pdf -i secrets.xlsx -o distributed_report.pdf -k deploy.key -v

# Inject sensitive text + secret alert into an image
caracol hide -c diagram.png -t "Root token: secret_778899" \
    -m "Contact backup node if primary fails" \
    -o shared_diagram.png -p "FieldPassword" -v
```

#### Extracting the hidden payload:
```bash
# Restore with original filename and extension automatically
caracol extract -i distributed_report.pdf -k deploy.key -v

# Or specify a custom output filename
caracol extract -i distributed_report.pdf -o recovered_balance.xlsx -k deploy.key -v
```

---

### 4. Zero-Knowledge Stealth Inspection (`-a`)

Demonstrate to students how forensic inspection tools react to the ZKS Anchor:

```bash
# 1. Third party or forensic auditor inspects carrier document:
caracol -a distributed_report.pdf
```
Output:
```text
  Archivo analizado  : distributed_report.pdf
  Formato detectado  : Documento Adobe PDF
  Tamaño total       : 184520 bytes (180.20 KB)
  Fin legitimo (EOF) : byte 184520
  [i] MODO SIGILOSO ACTIVO: No se detecto ninguna firma publica en texto plano.
```

```bash
# 2. Legitimate recipient audits file with key or passphrase:
caracol -a distributed_report.pdf -k deploy.key
```
Output:
```text
  [CARGA CARACOL DETECTADA Y AUTENTICADA]
  Offset de inyeccion: byte 184520
  Dimension Matriz   : 128x128 (16384 celdas/caracol)
  Laberinto Caracol  : 9 caracoles (1 Real + 8 Señuelos Estructurales)
  Estado             : Cifrado con llave privada verificada (HMAC OK)
```

---

### 5. Advanced Lab: Multi-Layer Matrioshka Nesting (Plausible Deniability)

This exercise demonstrates nested steganographic vaults for hostile interrogation or coercion scenarios.

```text
[Public PDF: legal_contract.pdf]
     └── Hides [PNG: chart.png] (Password 4)
              └── Hides [XLSX: accounting.xlsx] (Password 3)
                       └── Hides [SNAIL: layer1.snail] (Password 2)
                                └── Contains [TXT: root_seeds.txt] (Password 1)
```

#### Step 1: Create secret core vault
```bash
caracol seal -t "TARGET: Core Server 10.0.0.50 | Creds: admin/root_key" \
    -m "Alpha Cleared: For operational commander eyes only" \
    -o layer1.snail \
    -p "Pass1_DeepVault" -v
```

#### Step 2: Hide container into decoy Excel spreadsheet
```bash
caracol hide -c accounting.xlsx -i layer1.snail -o accounting_signed.xlsx -p "Pass2_Finance" -v
```

#### Step 3: Hide Excel file into decoy PNG image
```bash
caracol hide -c chart.png -i accounting_signed.xlsx -o chart_final.png -p "Pass3_Marketing" -v
```

#### Step 4: Hide PNG image into official public PDF
```bash
caracol hide -c legal_contract.pdf -i chart_final.png -o contract_distributed.pdf -p "Pass4_Public" -v
```

#### Live Reverse Unpacking in Class:
1. **Under Coercion at Level 4**: Surrender `Pass4_Public`. The examiner extracts `chart_final.png`, a completely valid, viewable image. The examiner assumes the payload was seized.
   ```bash
   caracol extract -i contract_distributed.pdf -p "Pass4_Public" -v
   ```
2. **If Examiner Demands Level 3**: Surrender `Pass3_Marketing`. The examiner extracts `accounting_signed.xlsx`, a functional Excel spreadsheet with realistic formulas and tables.
   ```bash
   caracol extract -i chart_final.png -p "Pass3_Marketing" -v
   ```
3. **The Authorized Recipient continues to the Core**:
   ```bash
   caracol extract -i accounting_signed.xlsx -p "Pass2_Finance" -v
   # Extracts layer1.snail

   caracol open -i layer1.snail -p "Pass1_DeepVault" -v
   # Reveals root seeds and secret operational message
   ```

---

### 6. Decoy Labyrinth Engineering & Auto-Resolving Decryption

Adjust the labyrinth complexity with structural flags:

```bash
caracol seal -i private_archive.zip -o fortress.snail -p "BunkerAccess" \
    --dim 256 \
    --decoys 32 \
    --false-exits 64 \
    -v
```
* **`--dim 256`**: 256x256 matrix per snail (65,536 permutation cells).
* **`--decoys 32`**: 32 decoy snail matrices identical in geometric structure.
* **`--false-exits 64`**: 64 false exits per decoy (2,048 total decoy traps).

#### Auto-Resolving Decryption:
To decrypt, you **NEVER need to pass `--dim`, `--decoys`, or `--false-exits`**. The recipient only runs:
```bash
caracol open -i fortress.snail -p "BunkerAccess" -v
```
The cryptographic engine resolves the labyrinth trajectory in constant time O(1) using only the master key.

---

## License

GNU General Public License v3.0 ([GPL-3.0](LICENSE)).
Any modifications or derivative works must remain open source under GPL-3.0.
