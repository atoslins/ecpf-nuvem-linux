#!/usr/bin/env bash
# Instala o e-CPF em nuvem no Linux: compila, copia o binário e o módulo, e regista o módulo
# PKCS#11 no p11-kit, no Chrome (NSS) e no Assinador Serpro. Tudo no utilizador, sem sudo.
#
#   ./instalar.sh
#
# Reversível com ./desinstalar.sh. Não mexe em nada de sistema.
set -euo pipefail
cd "$(dirname "$0")"

BIN="$HOME/.local/bin"
LIB="$HOME/.local/lib"
SO_FONTE="target/release/libcertisign_p11.so"
SO="$LIB/libcertisign_p11.so"
NSSDB="$HOME/.pki/nssdb"

echo "1/5  A compilar (release)…"
cargo build --release --quiet

echo "2/5  A copiar binário e módulo…"
mkdir -p "$BIN" "$LIB"
install -m 0755 target/release/certisign-nuvemd "$BIN/certisign-nuvemd"
install -m 0755 "$SO_FONTE" "$SO"

echo "3/5  A registar no p11-kit…"
mkdir -p "$HOME/.config/pkcs11/modules"
cat > "$HOME/.config/pkcs11/modules/certisign-nuvem.module" <<MOD
module: $SO
MOD

echo "4/5  A registar no Chrome (NSS)…"
if command -v modutil >/dev/null; then
  mkdir -p "$NSSDB"
  if [ ! -f "$NSSDB/cert9.db" ] && command -v certutil >/dev/null; then
    certutil -N -d "sql:$NSSDB" --empty-password
  fi
  if modutil -dbdir "sql:$NSSDB" -list 2>/dev/null | grep -q "Certisign nuvem"; then
    echo "     já estava registado."
  else
    printf '\n' | modutil -dbdir "sql:$NSSDB" -add "Certisign nuvem" -libfile "$SO" -force
  fi
else
  echo "     modutil não encontrado (pacote nss); pulei o Chrome."
fi

echo "5/5  A registar no Assinador Serpro…"
mkdir -p "$HOME/.signer"
DRV="$HOME/.signer/drivers.properties"
touch "$DRV"
if grep -q "libcertisign_p11" "$DRV"; then
  echo "     já estava no drivers.properties."
else
  echo "Certisign=$SO" >> "$DRV"
fi

echo
echo "Instalado. Serviço do daemon:"
echo "  systemctl --user enable --now certisign-nuvemd   # depois de criar a config"
echo "Config de exemplo em: config.exemplo.toml"
