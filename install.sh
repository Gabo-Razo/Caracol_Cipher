#!/usr/bin/env bash
set -euo pipefail

REPO="Gabo-Razo/Caracol_Cipher"
INSTALL_DIR="/usr/local/bin"
FALLBACK_DIR="${HOME}/.local/bin"

echo "[*] Detectando sistema operativo y arquitectura de hardware..."

# 1. Detectar Sistema Operativo
OS="$(uname -s)"
case "${OS}" in
    Linux*)     PLATFORM="linux" ;;
    *)
        echo "[!] Sistema no soportado por este script automatico: ${OS}"
        echo "    Por favor descarga el binario manualmente desde:"
        echo "    https://github.com/${REPO}/releases"
        exit 1
        ;;
esac

# 2. Detectar Arquitectura
ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64|amd64)
        TARGET_ARCH="x86_64"
        ;;
    aarch64|arm64)
        TARGET_ARCH="aarch64"
        ;;
    *)
        echo "[!] Arquitectura no soportada: ${ARCH}"
        exit 1
        ;;
esac

# 3. Detectar si es Linux basado en musl (Alpine, Void, Docker minimal) o glibc (Kali, Debian, Ubuntu)
IS_MUSL=0
if [ "${PLATFORM}" = "linux" ]; then
    if [ -f /etc/alpine-release ]; then
        IS_MUSL=1
    elif ldd /bin/ls 2>&1 | grep -qi "musl"; then
        IS_MUSL=1
    fi
fi

# 4. Determinar nombre exacto del binario de release
if [ "${TARGET_ARCH}" = "x86_64" ]; then
    if [ "${IS_MUSL}" -eq 1 ]; then
        BINARY_FILE="caracol-linux-x86_64-musl"
        echo "[*] Detectado: Linux x86_64 (Estatico MUSL)"
    else
        BINARY_FILE="caracol-linux-x86_64"
        echo "[*] Detectado: Linux x86_64 (GLIBC - Kali / Debian / Ubuntu)"
    fi
elif [ "${TARGET_ARCH}" = "aarch64" ]; then
    BINARY_FILE="caracol-linux-aarch64"
    echo "[*] Detectado: Linux ARM64 / AArch64 (Raspberry Pi / Servidor Cloud)"
fi

DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${BINARY_FILE}"

echo "[*] Descargando binario optimizado desde:"
echo "    ${DOWNLOAD_URL}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

if command -v curl >/dev/null 2>&1; then
    curl -fsSL "${DOWNLOAD_URL}" -o "${TMP_DIR}/caracol" || {
        echo "[!] Error al descargar con curl. Revisa tu conexion a internet o la URL."
        exit 1
    }
elif command -v wget >/dev/null 2>&1; then
    wget -q "${DOWNLOAD_URL}" -O "${TMP_DIR}/caracol" || {
        echo "[!] Error al descargar con wget. Revisa tu conexion a internet o la URL."
        exit 1
    }
else
    echo "[!] Se requiere curl o wget para continuar con la instalacion."
    exit 1
fi

chmod +x "${TMP_DIR}/caracol"

# 5. Instalar en /usr/local/bin o ~/.local/bin
TARGET_PATH=""
if [ -w "${INSTALL_DIR}" ]; then
    mv "${TMP_DIR}/caracol" "${INSTALL_DIR}/caracol"
    TARGET_PATH="${INSTALL_DIR}/caracol"
elif command -v sudo >/dev/null 2>&1 && [ -t 0 ]; then
    echo "[*] Solicitando privilegios sudo para instalar en ${INSTALL_DIR}..."
    sudo mv "${TMP_DIR}/caracol" "${INSTALL_DIR}/caracol"
    TARGET_PATH="${INSTALL_DIR}/caracol"
else
    mkdir -p "${FALLBACK_DIR}"
    mv "${TMP_DIR}/caracol" "${FALLBACK_DIR}/caracol"
    TARGET_PATH="${FALLBACK_DIR}/caracol"
    echo "[i] Instalado en ${TARGET_PATH} (sin privilegios sudo)."
    if [[ ":$PATH:" != *":${FALLBACK_DIR}:"* ]]; then
        echo "[i] Asegurate de agregar ${FALLBACK_DIR} a tu variable PATH:"
        echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
fi

echo "[OK] Caracol Cipher instalado exitosamente en: ${TARGET_PATH}"
echo "[*] Verificando version y dependencias..."
"${TARGET_PATH}" --help | head -n 12
