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

## Quickstart

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
  Third parties running `caracol -a distributed.pdf` without your key will see a clean file with zero detected signatures. Only providing `-k secret.key` validates the HMAC anchor and reveals the payload.
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
| `-k` | `--key <path.key>` | All | 256-bit private key file |
| `-p` | `--passphrase <text>`| All | Alternative passphrase (derived with PBKDF2) |
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

## Examples

### Custom Labyrinth Architecture
Generate massive matrix dimensions and decoy counts for high-security archival:
```bash
caracol seal -i private.zip -o secure.snail -p "YourPassword" \
    --dim 256 \
    --decoys 32 \
    --false-exits 64 \
    -v
```
To decrypt, you still only need the passphrase:
```bash
caracol open -i secure.snail -p "YourPassword" -v
```

### Stealth Forensic Audit (`-a`)
```bash
# Without key: shows clean document
caracol -a distributed.pdf

# With key: validates HMAC and shows payload info
caracol -a distributed.pdf -k secret.key
```

### Multi-layer Matrioshka (Plausible Deniability)
1. Seal sensitive payload: `caracol seal -t "Secret Seed" -o layer1.snail -p "Pass1"`
2. Hide `layer1.snail` into a decoy Excel sheet: `caracol hide -c sheet.xlsx -i layer1.snail -o sheet_mod.xlsx -p "Pass2"`
3. Hide `sheet_mod.xlsx` into a PNG image: `caracol hide -c avatar.png -i sheet_mod.xlsx -o final.png -p "Pass3"`

If coerced, revealing `Pass3` extracts a valid, functional Excel spreadsheet without revealing the internal `.snail` vault.

---

## License

GNU General Public License v3.0 ([GPL-3.0](LICENSE)).
Any modifications or derivative works must remain open source under GPL-3.0.
