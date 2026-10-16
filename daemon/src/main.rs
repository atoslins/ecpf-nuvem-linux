//! `certisign-nuvemd` — daemon do e-CPF A3 em nuvem da Certisign no Linux.
//!
//! Sem argumentos: faz login (senha do chaveiro) e serve o socket Unix para o módulo PKCS#11.
//! `--testar-login`: só prova o login com a conta real (pede confirmação no celular do dono).
//! `guardar-senha` / `guardar-pin`: guardam o segredo no chaveiro (lido sem eco).

mod config;
mod keyring;
mod dispositivo;
mod estado;
mod nuvem;
mod prompt;
mod servidor;
mod sessao;

use anyhow::{Context, Result};
use clap::Parser;
use std::sync::Arc;
use tokio::sync::Mutex;

use config::Config;
use sessao::Sessao;

#[derive(Parser, Debug)]
#[command(name = "certisign-nuvemd", version, about = "Daemon do e-CPF em nuvem (Certisign) no Linux")]
struct Args {
    /// Só testa o login na nuvem e sai (usa a conta real; confirme no celular quando pedir).
    #[arg(long)]
    testar_login: bool,

    /// Loga, registra este dispositivo (/create) e busca o certificado; mostra o resultado e sai.
    #[arg(long)]
    registrar: bool,

    /// Teste de assinatura: assina um texto e imprime hash/assinatura/cert p/ validar. Usa o PIN do
    /// chaveiro e pede o código do e-Token (vazio = usar push no celular).
    #[arg(long)]
    assinar_teste: bool,

    /// Texto a assinar no `--assinar-teste` (padrão: uma frase de teste).
    #[arg(long)]
    mensagem: Option<String>,

    /// Código do e-Token (6 dígitos) para o `--assinar-teste`. Se omitido, pergunta na hora.
    #[arg(long)]
    otp: Option<String>,

    /// Guarda a senha de login no chaveiro (lida sem eco) e sai.
    #[arg(long)]
    guardar_senha: bool,

    /// Guarda o PIN do certificado no chaveiro (lido sem eco) e sai.
    #[arg(long)]
    guardar_pin: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();

    if args.guardar_senha {
        let senha = rpassword::prompt_password("Senha de login da Certisign: ")
            .context("falha ao ler a senha")?;
        keyring::gravar("senha", &senha)?;
        println!("Senha guardada no chaveiro.");
        return Ok(());
    }
    if args.guardar_pin {
        let pin = rpassword::prompt_password("PIN do certificado: ").context("falha ao ler o PIN")?;
        keyring::gravar("pin", &pin)?;
        println!("PIN guardado no chaveiro.");
        return Ok(());
    }

    let cfg = Config::carregar()?;

    if args.testar_login {
        return testar_login(cfg).await;
    }

    if args.registrar {
        return registrar(cfg).await;
    }

    if args.assinar_teste {
        return assinar_teste(cfg, args.mensagem, args.otp).await;
    }

    // Modo daemon: login + servir o socket.
    let senha = obter_senha()?;
    let mut sessao = Sessao::nova(cfg)?;
    sessao.entrar(&senha).await.context("login falhou ao iniciar o daemon")?;
    tracing::info!("login ok; a servir o socket");
    let sessao = Arc::new(Mutex::new(sessao));
    servidor::servir(sessao).await
}

async fn testar_login(cfg: Config) -> Result<()> {
    let senha = obter_senha()?;
    let mut sessao = Sessao::nova(cfg)?;
    sessao.entrar(&senha).await.context("o login foi recusado")?;
    let est = sessao.estado();
    println!("Login OK. Utilizador: {}", est.nome.unwrap_or_else(|| "(sem nome)".into()));
    println!("Dica: rode sem argumentos para subir o daemon e o socket.");
    Ok(())
}

async fn registrar(cfg: Config) -> Result<()> {
    let formato = cfg.formato_chave.clone();
    let senha = obter_senha()?;
    let mut sessao = Sessao::nova(cfg)?;
    sessao.entrar(&senha).await.context("o login foi recusado")?;
    println!("Login OK.");
    println!("Registrando o dispositivo (/create, formato da chave: {formato})…");
    let code = sessao.registrar_dispositivo().await.context("registro do dispositivo falhou")?;
    println!("Dispositivo registrado. installationCode: {code}");
    println!("Buscando o certificado (carteira)…");
    let c = sessao.obter_certificados().await.context("busca do certificado falhou")?;
    println!(
        "Certificado obtido: {} bytes (DER); cadeia com {} certificado(s).",
        c.utilizador_der.len(),
        c.cadeia_der.len()
    );
    Ok(())
}

async fn assinar_teste(cfg: Config, mensagem: Option<String>, otp_arg: Option<String>) -> Result<()> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use sha2::{Digest, Sha256};

    let msg = mensagem.unwrap_or_else(|| "certisign-nuvem: teste de assinatura".to_string());
    let hash = Sha256::digest(msg.as_bytes());
    let hash_b64 = STANDARD.encode(hash);

    let senha = obter_senha()?;
    let pin = obter_pin()?;
    // OTP do e-Token: por argumento (--otp) ou perguntado na hora. Efémero; nunca vai ao chaveiro.
    let otp = match otp_arg {
        Some(o) => o.trim().to_string(),
        None => {
            print!("Código do e-Token (6 dígitos): ");
            std::io::Write::flush(&mut std::io::stdout()).ok();
            let mut s = String::new();
            std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut s).ok();
            s.trim().to_string()
        }
    };

    let mut sessao = Sessao::nova(cfg)?;
    sessao.entrar(&senha).await.context("o login foi recusado")?;
    let certs = sessao.obter_certificados().await.context("não obtive o certificado")?;

    if otp.is_empty() {
        println!("Sem OTP: vou disparar o PUSH. Aprove no seu iPhone quando chegar…");
    }
    let assinatura_b64 = sessao
        .assinar(&hash_b64, "SHA256", &pin, &otp)
        .await
        .context("a assinatura falhou")?;

    let cert_b64 = STANDARD.encode(&certs.utilizador_der);
    println!("\n==== RESULTADO DA ASSINATURA ====");
    println!("MENSAGEM: {msg}");
    println!("HASH_B64: {hash_b64}");
    println!("ASSINATURA_B64: {assinatura_b64}");
    println!("CERT_DER_B64: {cert_b64}");
    println!("==== FIM ====");
    Ok(())
}

/// Senha do chaveiro; se não houver, pede na hora (sem eco).
fn obter_senha() -> Result<String> {
    if let Some(s) = keyring::ler("senha")? {
        return Ok(s);
    }
    rpassword::prompt_password("Senha de login da Certisign: ").context("falha ao ler a senha")
}

/// PIN do chaveiro; se não houver, pede na hora (sem eco).
fn obter_pin() -> Result<String> {
    if let Some(p) = keyring::ler("pin")? {
        return Ok(p);
    }
    rpassword::prompt_password("PIN do e-CPF: ").context("falha ao ler o PIN")
}
