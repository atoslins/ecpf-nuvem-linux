# e-CPF A3 em nuvem (Certisign) no Linux

Use o e-CPF A3 em nuvem da Certisign nativamente no Linux. Com ele você assina documentos no Assinador Serpro e no PJeOffice e faz login por certificado digital em sites como o gov.br, usando o Chrome ou o Firefox. Não precisa de Windows nem de máquina virtual.

É uma implementação própria em Rust do protocolo da nuvem remoteID da Certisign, feita por engenharia reversa do aplicativo desktopID. A chave privada nunca sai da nuvem. O programa envia apenas o hash do documento para a assinatura, e o segundo fator continua sendo o e-Token do seu celular.

Para quem procura: e-CPF em nuvem no Linux, certificado digital A3 na nuvem no Linux, Certisign no Linux, assinar com e-CPF no Linux, desktopID no Linux, login no gov.br por certificado no Linux, módulo PKCS#11 do e-CPF em nuvem.

## Status

Funciona de ponta a ponta na conta real:

* Assinatura de documento com a assinatura validada contra a chave pública do certificado.
* Login por certificado no gov.br.
* Certificado visível no Chrome e disponível para o Assinador Serpro.

## Como funciona

```
Chrome / Firefox / Assinador Serpro / PJeOffice
        |  (padrão PKCS#11)
libcertisign_p11.so        (módulo, sem rede, sem segredo)
        |  (socket Unix)
certisign-nuvemd           (daemon: login, certificado, assinatura)
        |  (HTTPS)
Nuvem Certisign            (a chave privada mora aqui)
```

* **certisign-nuvemd** é o daemon, um serviço do usuário no systemd. Ele fala com a nuvem (login, registro do dispositivo, busca do certificado e assinatura do hash). A sessão fica só em memória. A senha e o PIN ficam no chaveiro do sistema. Em repouso usa cerca de 11 MB e 0 por cento de CPU.
* **libcertisign_p11.so** é o módulo PKCS#11, construído sobre o native-pkcs11 do Google. Ele roda dentro do Chrome e do Java e só conversa com o daemon pelo socket. Não tem rede nem segredo.
* **Segundo fator**: ao assinar, o daemon abre uma janela pedindo o código do e-Token (seis dígitos do aplicativo no celular). O código muda a cada 30 segundos, por isso é pedido na hora.

## Instalação

Em um comando, direto no terminal:

```bash
curl -fsSL https://raw.githubusercontent.com/atoslins/ecpf-nuvem-linux/main/install.sh | bash
```

Ou a partir de um clone:

```bash
git clone https://github.com/atoslins/ecpf-nuvem-linux.git
cd ecpf-nuvem-linux
./install.sh
```

O instalador é interativo. Ele confere as dependências, compila, instala, registra o módulo no p11-kit, no Chrome e no Assinador Serpro, pergunta o seu e-mail, guarda a senha e o PIN no chaveiro, registra o dispositivo e sobe o serviço. Rodar de novo é seguro, serve inclusive para atualizar.

Dependências: Rust (cargo), o pacote nss (certutil, pk12util, modutil) e o zenity ou o pinentry-gnome3. O instalador avisa o que estiver faltando.

Teste rápido de assinatura, que abre a janela do e-Token:

```bash
certisign-nuvemd --assinar-teste
```

No Chrome, o certificado aparece em `chrome://settings/certificates`, na aba "Seus certificados", como o token "Certisign nuvem". Para o módulo mostrar o certificado, o daemon precisa estar rodando.

## Trocar o certificado ou a conta

O sistema usa uma conta Certisign, definida pelo e-mail na configuração, e o certificado dela. Para trocar:

```bash
systemctl --user stop certisign-nuvemd
$EDITOR ~/.config/certisign-nuvem/config.toml      # novo e-mail
certisign-nuvemd --guardar-senha                    # nova senha
certisign-nuvemd --guardar-pin                       # novo PIN
rm -f ~/.config/certisign-nuvem/estado.json          # esquece o dispositivo antigo
systemctl --user start certisign-nuvemd
```

A chave do dispositivo fica em `~/.config/certisign-nuvem/dispositivo.pem`, gerada uma vez. Apague junto se quiser um dispositivo totalmente novo.

## Segurança

* A senha e o PIN ficam no chaveiro do sistema (Secret Service), nunca em arquivo. Para remover: `secret-tool clear servico certisign-nuvem campo senha` e o mesmo para `campo pin`.
* A chave privada do certificado permanece na nuvem. Só o hash do documento é enviado.
* Nunca sobrescreva `~/.local/lib/libcertisign_p11.so` com `cp` enquanto o Chrome ou o Serpro estiverem com ele carregado. Isso trunca a biblioteca em uso e derruba o processo. O instalador usa `install`, que cria um arquivo novo; o programa só carrega a versão nova ao reabrir.

## Comandos do daemon

| Comando | O que faz |
|---|---|
| `certisign-nuvemd` | sobe o daemon e serve o socket, é o que o serviço executa |
| `certisign-nuvemd --guardar-senha` | guarda a senha da conta no chaveiro |
| `certisign-nuvemd --guardar-pin` | guarda o PIN do certificado no chaveiro |
| `certisign-nuvemd --registrar` | registra o dispositivo e busca o certificado |
| `certisign-nuvemd --testar-login` | só prova o login |
| `certisign-nuvemd --assinar-teste` | assina um texto de teste e mostra a assinatura |

## Desinstalar

```bash
systemctl --user disable --now certisign-nuvemd
./desinstalar.sh
```

## Aviso

Projeto independente, sem qualquer vínculo com a Certisign ou com o Serpro. É uma implementação própria do protocolo, feita por engenharia reversa para fins de interoperabilidade, de modo que o titular use o próprio certificado em Linux. As marcas citadas pertencem aos seus respectivos donos.

## Licença

MIT. Veja o arquivo [LICENSE](LICENSE).
