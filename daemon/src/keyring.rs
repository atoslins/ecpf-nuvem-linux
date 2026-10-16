//! Segredos (senha, PIN) no chaveiro do sistema, via `secret-tool` (Secret Service).
//! Nunca gravamos segredo em arquivo. Em último caso, o `--testar-login` pede na hora.

use anyhow::{bail, Context, Result};
use std::process::Command;

const SERVICO: &str = "certisign-nuvem";

/// Lê um segredo (`campo` = "senha" ou "pin"). `Ok(None)` se não existe no chaveiro.
pub fn ler(campo: &str) -> Result<Option<String>> {
    let saida = Command::new("secret-tool")
        .args(["lookup", "servico", SERVICO, "campo", campo])
        .output()
        .context("falha ao executar secret-tool (está instalado?)")?;
    if saida.status.success() {
        let v = String::from_utf8_lossy(&saida.stdout).trim_end_matches('\n').to_string();
        if v.is_empty() {
            Ok(None)
        } else {
            Ok(Some(v))
        }
    } else {
        // secret-tool devolve !=0 quando a chave não existe.
        Ok(None)
    }
}

/// Grava um segredo no chaveiro.
pub fn gravar(campo: &str, valor: &str) -> Result<()> {
    use std::io::Write;
    use std::process::Stdio;
    let rotulo = format!("Certisign nuvem ({campo})");
    let mut filho = Command::new("secret-tool")
        .args(["store", "--label", &rotulo, "servico", SERVICO, "campo", campo])
        .stdin(Stdio::piped())
        .spawn()
        .context("falha ao executar secret-tool store")?;
    filho
        .stdin
        .as_mut()
        .context("sem stdin no secret-tool")?
        .write_all(valor.as_bytes())?;
    let status = filho.wait()?;
    if !status.success() {
        bail!("secret-tool store falhou");
    }
    Ok(())
}
