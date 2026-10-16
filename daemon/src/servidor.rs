//! Servidor do socket Unix: uma linha de JSON por pedido, uma por resposta.
//! Só o dono do socket (permissão 0600) fala com o daemon.

use anyhow::{Context, Result};
use certisign_nuvem_core::{caminho_socket, Pedido, Resposta};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

use crate::sessao::Sessao;

pub async fn servir(sessao: Arc<Mutex<Sessao>>) -> Result<()> {
    let caminho = caminho_socket();
    let _ = std::fs::remove_file(&caminho); // limpa socket órfão de uma execução anterior
    let listener = UnixListener::bind(&caminho)
        .with_context(|| format!("não consegui abrir o socket {}", caminho.display()))?;
    std::fs::set_permissions(&caminho, std::fs::Permissions::from_mode(0o600))
        .context("não consegui travar a permissão do socket")?;
    tracing::info!("escutando em {}", caminho.display());

    loop {
        let (stream, _) = listener.accept().await.context("falha ao aceitar conexão")?;
        let sessao = sessao.clone();
        tokio::spawn(async move {
            if let Err(e) = atender(stream, sessao).await {
                tracing::warn!("conexão terminou com erro: {e:#}");
            }
        });
    }
}

async fn atender(stream: UnixStream, sessao: Arc<Mutex<Sessao>>) -> Result<()> {
    let (leitura, mut escrita) = stream.into_split();
    let mut linhas = BufReader::new(leitura).lines();
    while let Some(linha) = linhas.next_line().await? {
        if linha.trim().is_empty() {
            continue;
        }
        let resposta = match serde_json::from_str::<Pedido>(&linha) {
            Ok(p) => processar(p, &sessao).await,
            Err(e) => Resposta::Erro { mensagem: format!("pedido inválido: {e}") },
        };
        let mut saida = serde_json::to_string(&resposta)?;
        saida.push('\n');
        escrita.write_all(saida.as_bytes()).await?;
        escrita.flush().await?;
    }
    Ok(())
}

async fn processar(pedido: Pedido, sessao: &Arc<Mutex<Sessao>>) -> Resposta {
    let mut s = sessao.lock().await;
    match pedido {
        Pedido::Estado => Resposta::Estado(s.estado()),
        Pedido::Certificados => match s.obter_certificados().await {
            Ok(c) => Resposta::Certificados(c),
            Err(e) => Resposta::Erro { mensagem: format!("{e:#}") },
        },
        Pedido::Assinar { hash_b64, algoritmo } => {
            tracing::info!("Assinar pedido: algoritmo={algoritmo} tam_hash_b64={}", hash_b64.len());
            // PIN do chaveiro (guardado com `--guardar-pin`); o OTP é pedido na hora (muda a cada ~30s).
            let pin = crate::keyring::ler("pin").ok().flatten().unwrap_or_default();
            let otp = match crate::prompt::pedir_otp().await {
                Ok(o) => o,
                Err(e) => return Resposta::Erro { mensagem: format!("{e:#}") },
            };
            match s.assinar(&hash_b64, &algoritmo, &pin, &otp).await {
                Ok(assinatura_b64) => Resposta::Assinatura { assinatura_b64 },
                Err(e) => Resposta::Erro { mensagem: format!("{e:#}") },
            }
        }
    }
}
