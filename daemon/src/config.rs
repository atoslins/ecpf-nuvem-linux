//! Configuração do daemon: `~/.config/certisign-nuvem/config.toml`.
//!
//! Os campos saem do que a engenharia reversa achou (ver NOTAS, "desktopID — nuvem"):
//! endereços da nuvem + dados do PC registado. Nada de segredo aqui — senha e PIN ficam no
//! chaveiro (ver `keyring`).

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Host base da nuvem (ex.: "remoteidcertisign.com.br"), sem "https://".
    pub remoteid_url: String,
    /// E-mail de login da conta Certisign.
    pub email: String,
    /// `urlAcesso` enviado no login (identifica a origem; vem do config do desktopID).
    #[serde(default = "url_acesso_padrao")]
    pub url_acesso: String,
    /// Código deste PC. Agora vem do `/create` (installationCode) e fica no estado; opcional aqui.
    #[serde(default)]
    pub desktop_code: String,
    /// Número de série do certificado. Agora vem da carteira; opcional aqui.
    #[serde(default)]
    pub serial_number: String,
    /// Nome da aplicação enviado no `tokensessao`.
    #[serde(default = "nome_app_padrao")]
    pub nome_aplicacao_desktop: String,
    /// Campo `issue` do `tokensessao`/assinatura (emissor/identificador da sessão).
    #[serde(default)]
    pub issue: String,

    // --- Registro do dispositivo (/create no certinext) ---
    /// Host do certinext (sem esquema).
    #[serde(default = "certinext_url_padrao")]
    pub certinext_url: String,
    /// Base path do certinext.
    #[serde(default = "certinext_base_padrao")]
    pub certinext_base: String,
    /// Dados da máquina enviados no `/create`.
    #[serde(default = "hostname_padrao")]
    pub installation_name: String,
    #[serde(default = "so_padrao")]
    pub operational_system: String,
    #[serde(default = "user_padrao")]
    pub user_name: String,
    #[serde(default)]
    pub domain_name: String,
    /// Formato da chave pública no `/create`: "pem" (SPKI PEM) ou "b64der" (base64 do DER).
    #[serde(default = "formato_chave_padrao")]
    pub formato_chave: String,
}

fn url_acesso_padrao() -> String {
    String::new()
}
fn nome_app_padrao() -> String {
    "certisign-nuvem (Linux)".to_string()
}
fn certinext_url_padrao() -> String {
    "certinext.certisign.com.br".to_string()
}
fn certinext_base_padrao() -> String {
    "/CertisignerServices".to_string()
}
fn hostname_padrao() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "linux".to_string())
}
fn so_padrao() -> String {
    "Linux".to_string()
}
fn user_padrao() -> String {
    std::env::var("USER").unwrap_or_else(|_| "user".to_string())
}
fn formato_chave_padrao() -> String {
    "pem".to_string()
}

impl Config {
    pub fn caminho() -> PathBuf {
        let base = std::env::var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".config")
            });
        base.join("certisign-nuvem").join("config.toml")
    }

    pub fn carregar() -> Result<Config> {
        let caminho = Self::caminho();
        let texto = std::fs::read_to_string(&caminho)
            .with_context(|| format!("não achei a config em {}", caminho.display()))?;
        let cfg: Config = toml::from_str(&texto)
            .with_context(|| format!("config inválida em {}", caminho.display()))?;
        Ok(cfg)
    }

    /// Base com esquema, ex.: "https://remoteidcertisign.com.br".
    pub fn base_url(&self) -> String {
        format!("https://{}", self.remoteid_url.trim_end_matches('/'))
    }

    /// Base do certinext com `/desktop`, ex.: "https://certinext.certisign.com.br/CertisignerServices/desktop".
    pub fn certinext_desktop_url(&self) -> String {
        let base = if self.certinext_base.is_empty() { "/CertisignerServices" } else { &self.certinext_base };
        format!(
            "https://{}/{}/desktop",
            self.certinext_url.trim_end_matches('/'),
            base.trim_start_matches('/').trim_end_matches('/'),
        )
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn le_toml_minimo_e_aplica_padroes() {
        let t = r#"
            remoteid_url = "remoteidcertisign.com.br"
            email = "fulano@exemplo.com"
            desktop_code = "ABC123"
            serial_number = "0A1B2C"
        "#;
        let cfg: Config = toml::from_str(t).unwrap();
        assert_eq!(cfg.url_acesso, "");
        assert_eq!(cfg.base_url(), "https://remoteidcertisign.com.br");
        assert!(cfg.nome_aplicacao_desktop.contains("Linux"));
    }

    #[test]
    fn certinext_url_montada_certo() {
        let t = r#"
            remoteid_url = "remoteidcertisign.com.br"
            email = "fulano@exemplo.com"
        "#;
        let cfg: Config = toml::from_str(t).unwrap();
        assert_eq!(
            cfg.certinext_desktop_url(),
            "https://certinext.certisign.com.br/CertisignerServices/desktop"
        );
        assert_eq!(cfg.formato_chave, "pem");
    }
}
