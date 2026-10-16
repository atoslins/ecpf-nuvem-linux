//! Estado persistente do daemon: o `codigoDesktop` devolvido pelo registro no remoteID.
//! Guardado em `~/.config/certisign-nuvem/estado.json`. Não é segredo (é um id de dispositivo).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Estado {
    /// `codigoDesktop` deste dispositivo (do registro no remoteID). Vazio = ainda não registrado.
    /// É o id usado na URL da carteira/statusCelular e no `desktopCode` da assinatura.
    #[serde(default)]
    pub codigo_desktop: String,
    /// `serialNumber` do certificado (hex minúsculo), derivado do `keyName` da carteira. Usado na
    /// assinatura (tokensessao/requestHashSessionSignature).
    #[serde(default)]
    pub serial_number: String,
    /// `issue` do certificado (DN do emissor), derivado do `keyName` da carteira.
    #[serde(default)]
    pub issue: String,
    /// Campo legado do caminho antigo (certinext `/create`). Não é mais usado; mantido só para
    /// não quebrar a leitura de um estado.json velho.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub installation_code: String,
}

impl Estado {
    fn caminho() -> PathBuf {
        let base = std::env::var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".config")
            });
        base.join("certisign-nuvem").join("estado.json")
    }

    pub fn carregar() -> Estado {
        let caminho = Self::caminho();
        std::fs::read_to_string(&caminho)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn salvar(&self) -> Result<()> {
        let caminho = Self::caminho();
        if let Some(dir) = caminho.parent() {
            std::fs::create_dir_all(dir).ok();
        }
        let txt = serde_json::to_string_pretty(self).context("serializando estado")?;
        std::fs::write(&caminho, txt).with_context(|| format!("gravando {}", caminho.display()))?;
        Ok(())
    }

    pub fn registrado(&self) -> bool {
        !self.codigo_desktop.is_empty()
    }
}
