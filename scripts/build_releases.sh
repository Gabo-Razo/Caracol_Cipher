#!/usr/bin/env bash
set -euo pipefail

VERSION="6.0"
DIST_DIR="dist"

echo "[*] Iniciando compilacion de releases para Caracol Cipher v${VERSION}..."
mkdir -p "${DIST_DIR}"

# 1. Linux x86_64 (glibc - Kali Linux / Debian / Ubuntu / Fedora)
echo "[*] Compilando target: x86_64-unknown-linux-gnu..."
cargo build --release --target x86_64-unknown-linux-gnu
cp target/x86_64-unknown-linux-gnu/release/caracol_cipher "${DIST_DIR}/caracol-v${VERSION}-linux-x86_64"
strip "${DIST_DIR}/caracol-v${VERSION}-linux-x86_64"
cp "${DIST_DIR}/caracol-v${VERSION}-linux-x86_64" "${DIST_DIR}/caracol-linux-x86_64"

# 2. Linux x86_64 Universal Estatico (musl - Alpine / Docker / Cualquier Linux sin glibc)
echo "[*] Compilando target: x86_64-unknown-linux-musl..."
cargo build --release --target x86_64-unknown-linux-musl
cp target/x86_64-unknown-linux-musl/release/caracol_cipher "${DIST_DIR}/caracol-v${VERSION}-linux-x86_64-musl"
strip "${DIST_DIR}/caracol-v${VERSION}-linux-x86_64-musl"
cp "${DIST_DIR}/caracol-v${VERSION}-linux-x86_64-musl" "${DIST_DIR}/caracol-linux-x86_64-musl"

# 3. Windows x86_64 (.exe nativo)
echo "[*] Compilando target: x86_64-pc-windows-gnu..."
cargo build --release --target x86_64-pc-windows-gnu
cp target/x86_64-pc-windows-gnu/release/caracol_cipher.exe "${DIST_DIR}/caracol-v${VERSION}-windows-x86_64.exe"
x86_64-w64-mingw32-strip "${DIST_DIR}/caracol-v${VERSION}-windows-x86_64.exe"
cp "${DIST_DIR}/caracol-v${VERSION}-windows-x86_64.exe" "${DIST_DIR}/caracol-windows-x86_64.exe"

# 4. Linux ARM64 / AArch64 (Raspberry Pi 4/5, servidores ARM, Cloud)
echo "[*] Compilando target: aarch64-unknown-linux-gnu..."
cargo build --release --target aarch64-unknown-linux-gnu
cp target/aarch64-unknown-linux-gnu/release/caracol_cipher "${DIST_DIR}/caracol-v${VERSION}-linux-aarch64"
aarch64-linux-gnu-strip "${DIST_DIR}/caracol-v${VERSION}-linux-aarch64"
cp "${DIST_DIR}/caracol-v${VERSION}-linux-aarch64" "${DIST_DIR}/caracol-linux-aarch64"

# 5. Generar sumas de verificacion SHA-256
echo "[*] Calculando sumas de verificacion SHA-256..."
(cd "${DIST_DIR}" && sha256sum caracol-* > SHA256SUMS.txt)

echo "[OK] Todos los binarios fueron generados exitosamente en la carpeta '${DIST_DIR}/':"
ls -lh "${DIST_DIR}"
