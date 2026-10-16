# e-CPF A3 em nuvem (Certisign) no Linux

Usa o e-CPF A3 em nuvem da Certisign (remoteID) nativo no Linux — assina documentos (Assinador
Serpro, PJeOffice) e faz login por certificado em sites (Chrome, gov.br), sem Windows. Funciona:
assinatura validada contra a chave pública e login no gov.br OK.

Reimplementação própria em Rust do protocolo da nuvem (feita por engenharia reversa do desktopID
da Certisign). A chave privada nunca sai da nuvem; só o hash do documento é enviado.

## Como funciona

```
Chrome / Serpro / PJeOffice ──PKCS#11──> libcertisign_p11.so ──socket Unix──> certisign-nuvemd ──HTTPS──> nuvem Certisign
```

- **`certisign-nuvemd`** (daemon, serviço systemd do usuário): fala com a nuvem (login, registra o
  dispositivo, busca o certificado, abre a sessão de assinatura e manda o hash). A sessão fica só
  em memória; a senha e o PIN ficam no chaveiro do sistema. Ocioso (~11 MB, 0% CPU) até alguém pedir.
- **`libcertisign_p11.so`** (módulo PKCS#11, sobre o `native-pkcs11` do Google): roda dentro do
  Chrome/Java e só conversa com o daemon pelo socket. Sem rede nem segredo.
- **2º fator**: ao assinar, o daemon abre uma janela pedindo o código do **e-Token** (6 dígitos do
  app no celular). O código muda a cada ~30s, por isso é pedido na hora.

## Instalar

Precisa de: Rust (cargo), `nss` (certutil/pk12util/modutil) e `zenity` (ou `pinentry-gnome3`).

```bash
./instalar.sh     # compila (release), instala binário + módulo, registra no p11-kit, Chrome e Serpro
```

Depois, uma vez, configure a conta:

```bash
mkdir -p ~/.config/certisign-nuvem
cp config.exemplo.toml ~/.config/certisign-nuvem/config.toml
$EDITOR ~/.config/certisign-nuvem/config.toml      # ponha seu e-mail de login

certisign-nuvemd --guardar-senha                   # senha da conta Certisign (vai pro chaveiro)
certisign-nuvemd --guardar-pin                      # PIN do certificado (vai pro chaveiro)

certisign-nuvemd --registrar                        # registra este PC e busca o certificado (confere)
systemctl --user enable --now certisign-nuvemd      # sobe o serviço e deixa no boot
```

Teste rápido de assinatura (pede o e-Token numa janela):

```bash
certisign-nuvemd --assinar-teste
```

No Chrome, o certificado aparece em `chrome://settings/certificates` como o token **"Certisign nuvem"**.

## Trocar o certificado / a conta

O sistema usa uma conta Certisign (o `email` da config) e o certificado dela. Para trocar:

```bash
systemctl --user stop certisign-nuvemd
$EDITOR ~/.config/certisign-nuvem/config.toml       # novo e-mail
certisign-nuvemd --guardar-senha                     # nova senha
certisign-nuvemd --guardar-pin                        # novo PIN
rm -f ~/.config/certisign-nuvem/estado.json          # esquece o dispositivo antigo (re-registra)
systemctl --user start certisign-nuvemd
```

A chave do dispositivo fica em `~/.config/certisign-nuvem/dispositivo.pem` (gerada uma vez; apague
junto se quiser um dispositivo totalmente novo).

## Desinstalar

```bash
./desinstalar.sh                                      # tira os registros (mantém config e chaveiro)
systemctl --user disable --now certisign-nuvemd
```

## Avisos

- **Nunca** sobrescreva `~/.local/lib/libcertisign_p11.so` com `cp` enquanto o Chrome/Serpro o tem
  carregado — trunca a biblioteca mapeada e derruba o processo (SIGSEGV). O `instalar.sh` usa
  `install` (inode novo); o programa só pega a versão nova ao reabrir.
- A senha e o PIN ficam no chaveiro (Secret Service), nunca em arquivo. Remover:
  `secret-tool clear servico certisign-nuvem campo senha` (e `campo pin`).
- Para o módulo mostrar o certificado, o daemon precisa estar rodando.

## Comandos do daemon

| Comando | O que faz |
|---|---|
| `certisign-nuvemd` | sobe o daemon e serve o socket (é o que o serviço roda) |
| `--guardar-senha` / `--guardar-pin` | guardam os segredos no chaveiro |
| `--registrar` | registra o dispositivo e busca o certificado (diagnóstico) |
| `--testar-login` | só prova o login |
| `--assinar-teste [--otp 123456]` | assina um texto de teste e mostra a assinatura |
