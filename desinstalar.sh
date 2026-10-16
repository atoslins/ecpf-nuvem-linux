#!/usr/bin/env bash
# Desfaz o instalar.sh. Não apaga a config nem o chaveiro.
set -euo pipefail
SO="$HOME/.local/lib/libcertisign_p11.so"
NSSDB="$HOME/.pki/nssdb"
systemctl --user disable --now certisign-nuvemd 2>/dev/null || true
if command -v modutil >/dev/null; then
  printf '\n' | modutil -dbdir "sql:$NSSDB" -delete "Certisign nuvem" -force 2>/dev/null || true
fi
sed -i '/libcertisign_p11/d' "$HOME/.signer/drivers.properties" 2>/dev/null || true
rm -f "$HOME/.config/pkcs11/modules/certisign-nuvem.module"
rm -f "$SO" "$HOME/.local/bin/certisign-nuvemd"
echo "Removido (config e chaveiro ficaram)."
