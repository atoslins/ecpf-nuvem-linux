//! Pedido do código do e-Token na hora de assinar (o OTP muda a cada ~30s, então não dá para
//! guardar no chaveiro: tem de ser pedido no momento). Usa uma janela do desktop (`zenity`, e
//! cai para `pinentry-gnome3`). Precisa do ambiente gráfico (WAYLAND_DISPLAY/DISPLAY) — quando o
//! daemon roda como serviço de usuário, o `systemctl --user import-environment` resolve.

use anyhow::{bail, Result};
use tokio::process::Command;

/// Abre uma janela pedindo o código do e-Token (6 dígitos). Devolve o texto; erro se cancelado.
pub async fn pedir_otp() -> Result<String> {
    // 1ª opção: zenity (GTK, funciona no Wayland).
    if tem("zenity") {
        let saida = Command::new("zenity")
            .args([
                "--entry",
                "--title=Assinatura e-CPF (nuvem Certisign)",
                "--text=Código do e-Token (6 dígitos) para assinar:",
                "--hide-text",
            ])
            .output()
            .await;
        if let Ok(s) = saida {
            if s.status.success() {
                let otp = String::from_utf8_lossy(&s.stdout).trim().to_string();
                if otp.is_empty() {
                    bail!("código do e-Token vazio");
                }
                return Ok(otp);
            }
            // zenity devolve !=0 quando o usuário cancela/fecha.
            bail!("assinatura cancelada (sem código do e-Token)");
        }
    }

    // 2ª opção: pinentry-gnome3 (protocolo Assuan simples).
    if tem("pinentry-gnome3") {
        return pinentry().await;
    }

    bail!("não há zenity/pinentry para pedir o código do e-Token (ou falta o ambiente gráfico)")
}

fn tem(programa: &str) -> bool {
    std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {programa}"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Fala o protocolo Assuan mínimo com o pinentry para ler uma linha secreta.
async fn pinentry() -> Result<String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let mut filho = Command::new("pinentry-gnome3")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    let mut ein = filho.stdin.take().unwrap();
    let mut eout = BufReader::new(filho.stdout.take().unwrap()).lines();
    // Lê o "OK" inicial.
    let _ = eout.next_line().await?;
    for cmd in [
        "SETTITLE Assinatura e-CPF\n",
        "SETPROMPT e-Token:\n",
        "SETDESC Código do e-Token (6 dígitos) para assinar\n",
        "GETPIN\n",
    ] {
        ein.write_all(cmd.as_bytes()).await?;
        ein.flush().await?;
        if cmd == "GETPIN\n" {
            // A resposta do GETPIN vem como linhas "D <valor>" e depois "OK".
            let mut otp = String::new();
            while let Some(linha) = eout.next_line().await? {
                if let Some(v) = linha.strip_prefix("D ") {
                    otp = v.trim().to_string();
                } else if linha.starts_with("OK") {
                    break;
                } else if linha.starts_with("ERR") {
                    bail!("assinatura cancelada no pinentry");
                }
            }
            if otp.is_empty() {
                bail!("código do e-Token vazio");
            }
            return Ok(otp);
        }
        // Consome o "OK" de cada comando de setup.
        let _ = eout.next_line().await?;
    }
    bail!("pinentry não devolveu o código")
}
