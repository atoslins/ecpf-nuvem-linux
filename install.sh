#!/usr/bin/env bash
# Instalador interativo do e-CPF A3 em nuvem (Certisign) no Linux.
# Rode de um clone:   ./install.sh
# Ou direto do curl:  curl -fsSL https://raw.githubusercontent.com/atoslins/ecpf-nuvem-linux/main/install.sh | bash
set -euo pipefail

REPO="atoslins/ecpf-nuvem-linux"
APP_DIR="${ECPF_DIR:-$HOME/.local/share/ecpf-nuvem-linux}"
BIN="$HOME/.local/bin"; LIB="$HOME/.local/lib"; NSSDB="$HOME/.pki/nssdb"
CFG="$HOME/.config/certisign-nuvem/config.toml"

# ---- cores / helpers ----
if [ -t 1 ]; then B=$'\e[1m';D=$'\e[2m';R=$'\e[31m';G=$'\e[32m';Y=$'\e[33m';C=$'\e[36m';Z=$'\e[0m'
else B=;D=;R=;G=;Y=;C=;Z=; fi
info(){ printf '  %s %s\n' "${C}›${Z}" "$*"; }
ok(){ printf '  %s %s\n' "${G}✓${Z}" "$*"; }
warn(){ printf '  %s %s\n' "${Y}!${Z}" "$*"; }
die(){ printf '\n  %s %s\n\n' "${R}✗${Z}" "$*" >&2; exit 1; }
passo(){ printf '\n%s\n' "${B}$*${Z}"; }
tem_tty(){ { : </dev/tty; } 2>/dev/null; }   # /dev/tty realmente utilizável?
pergunta(){ # $1=texto $2=padrão -> ecoa resposta
  local resp=""; printf '  %s %s' "${C}?${Z}" "$1"; [ -n "${2:-}" ] && printf ' [%s]' "$2"; printf ': '
  if tem_tty; then read -r resp </dev/tty || true; else printf '(sem terminal, usando padrão)\n'; fi
  printf '%s' "${resp:-${2:-}}"; }
confirma(){ local r=""; printf '  %s %s [s/N]: ' "${C}?${Z}" "$1"
  if tem_tty; then read -r r </dev/tty || true; else printf 'não\n'; fi; [[ "${r,,}" == s* ]]; }

banner(){ printf '\n%s\n' "${B}${C}  e-CPF A3 em nuvem — Certisign no Linux${Z}"
  printf '%s\n' "${D}  daemon + módulo PKCS#11 · assina documentos e faz login por certificado${Z}"; }

# ---- 1. bootstrap: se não for um clone, clona ----
if [ ! -f "Cargo.toml" ] || ! grep -q 'members.*daemon' Cargo.toml 2>/dev/null; then
  banner; passo "1/8  Baixando o código"
  command -v git >/dev/null || die "git não encontrado."
  if [ -d "$APP_DIR/.git" ]; then
    info "Atualizando $APP_DIR"; git -C "$APP_DIR" pull --ff-only -q || warn "não atualizou (seguindo com o que tem)"
  else
    info "Clonando em $APP_DIR"
    if command -v gh >/dev/null && gh auth status >/dev/null 2>&1; then
      gh repo clone "$REPO" "$APP_DIR" -- -q || die "falha ao clonar (gh)."
    else
      git clone -q "https://github.com/$REPO.git" "$APP_DIR" || die "falha ao clonar. Faça login: gh auth login"
    fi
  fi
  cd "$APP_DIR"; ok "código em $APP_DIR"
else
  APP_DIR="$(pwd)"; banner
fi

# ---- 2. dependências ----
passo "2/8  Conferindo dependências"
faltou=0
checa(){ if command -v "$1" >/dev/null; then ok "$1"; else warn "falta ${B}$1${Z} — $2"; faltou=1; fi; }
checa cargo   "instale o Rust (ex.: mise use -g rust  ou  rustup)"
checa certutil "pacote nss (ex.: sudo pacman -S nss)"
checa pk12util "pacote nss"
checa modutil  "pacote nss"
if command -v zenity >/dev/null || command -v pinentry-gnome3 >/dev/null; then ok "janela de senha (zenity/pinentry)"
else warn "falta ${B}zenity${Z} (pop-up do e-Token) — sudo pacman -S zenity"; faltou=1; fi
[ "$faltou" = 1 ] && die "Instale o que faltou acima e rode de novo."

# ---- 3. compilar ----
passo "3/8  Compilando (release) — pode levar 1-2 min na 1ª vez"
_log="$(mktemp)"
cargo build --release -q >"$_log" 2>&1 || { cat "$_log"; rm -f "$_log"; die "falha ao compilar."; }
rm -f "$_log"
ok "binário e módulo prontos"

# ---- 4. instalar binário + módulo (install = inode novo; seguro com Chrome aberto) ----
passo "4/8  Instalando"
mkdir -p "$BIN" "$LIB"
install -m 0755 target/release/certisign-nuvemd "$BIN/certisign-nuvemd"
install -m 0755 target/release/libcertisign_p11.so "$LIB/libcertisign_p11.so"
ok "certisign-nuvemd em $BIN"; ok "módulo em $LIB"
case ":$PATH:" in *":$BIN:"*) :;; *) warn "$BIN não está no PATH — adicione no seu shell";; esac

# ---- 5. registrar no p11-kit / Chrome / Serpro ----
passo "5/8  Registrando no p11-kit, Chrome e Serpro"
mkdir -p "$HOME/.config/pkcs11/modules"
printf 'module: %s\n' "$LIB/libcertisign_p11.so" > "$HOME/.config/pkcs11/modules/certisign-nuvem.module"
ok "p11-kit"
if command -v modutil >/dev/null; then
  mkdir -p "$NSSDB"
  [ -f "$NSSDB/cert9.db" ] || certutil -N -d "sql:$NSSDB" --empty-password
  if modutil -dbdir "sql:$NSSDB" -list 2>/dev/null | grep -q "Certisign nuvem"; then ok "Chrome (já registrado)"
  else printf '\n' | modutil -dbdir "sql:$NSSDB" -add "Certisign nuvem" -libfile "$LIB/libcertisign_p11.so" -force >/dev/null 2>&1 && ok "Chrome (NSS)"; fi
fi
mkdir -p "$HOME/.signer"; touch "$HOME/.signer/drivers.properties"
grep -q libcertisign_p11 "$HOME/.signer/drivers.properties" || echo "Certisign=$LIB/libcertisign_p11.so" >> "$HOME/.signer/drivers.properties"
ok "Assinador Serpro"

# ---- 6. configuração da conta ----
passo "6/8  Configuração da conta"
mkdir -p "$(dirname "$CFG")"
if [ -f "$CFG" ] && grep -q '^email' "$CFG" && ! grep -q 'voce@exemplo' "$CFG"; then
  ok "config já existe ($CFG)"
else
  padrao_email="$(git config --get user.email 2>/dev/null || true)"
  email="$(pergunta "E-mail de login da sua conta Certisign" "$padrao_email")"
  [ -n "$email" ] || die "e-mail é obrigatório."
  cat > "$CFG" <<TOML
remoteid_url = "remoteidcertisign.com.br"
email = "$email"
TOML
  ok "config escrita em $CFG"
fi

# ---- 7. segredos no chaveiro (você digita; nada é salvo em arquivo) ----
passo "7/8  Senha e PIN (vão para o chaveiro do sistema)"
tem_segredo(){ secret-tool lookup servico certisign-nuvem campo "$1" >/dev/null 2>&1; }
if tem_segredo senha; then ok "senha já guardada"
else info "Digite a senha da sua conta Certisign:"; "$BIN/certisign-nuvemd" --guardar-senha; fi
if tem_segredo pin; then ok "PIN já guardado"
else info "Digite o PIN do seu certificado:"; "$BIN/certisign-nuvemd" --guardar-pin; fi

# ---- 8. registrar dispositivo + subir o serviço ----
passo "8/8  Registrando o dispositivo e subindo o serviço"
if confirma "Registrar este PC e buscar o certificado agora?"; then
  "$BIN/certisign-nuvemd" --registrar || warn "registro falhou (confira e-mail/senha); dá pra tentar depois."
fi
mkdir -p "$HOME/.config/systemd/user"
install -m 0644 certisign-nuvemd.service "$HOME/.config/systemd/user/certisign-nuvemd.service"
systemctl --user daemon-reload
systemctl --user enable --now certisign-nuvemd >/dev/null 2>&1 || true
if systemctl --user is-active --quiet certisign-nuvemd; then ok "serviço certisign-nuvemd ativo (sobe no login)"
else warn "o serviço não subiu; veja: journalctl --user -u certisign-nuvemd"; fi

# ---- fim ----
printf '\n%s\n' "${B}${G}  Tudo pronto.${Z}"
cat <<FIM
  ${D}• Teste a assinatura:${Z}  certisign-nuvemd --assinar-teste
  ${D}• No Chrome:${Z}            chrome://settings/certificates  (token "Certisign nuvem")
  ${D}• Trocar a conta/cert:${Z}  veja o README.md (seção "Trocar o certificado")

FIM
