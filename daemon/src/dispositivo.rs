//! Chave RSA-2048 do dispositivo. O desktopID gera uma chave por PC (container CNG
//! `desktopID.<id>`), manda a pública no `/create` e guarda a privada localmente (nunca sai).
//! Aqui fazemos o equivalente no Linux: gerar uma vez, persistir a privada em arquivo 0600,
//! e expor a pública nos formatos que o `/create` pode querer (PEM SPKI ou base64 do DER).

use anyhow::{Context, Result};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::path::PathBuf;

pub struct Dispositivo {
    pub chave: RsaPrivateKey,
}

impl Dispositivo {
    fn caminho() -> PathBuf {
        let base = std::env::var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".config")
            });
        base.join("certisign-nuvem").join("dispositivo.pem")
    }

    /// Carrega a chave do dispositivo; gera e persiste (0600) na primeira vez.
    pub fn carregar_ou_gerar() -> Result<Dispositivo> {
        let caminho = Self::caminho();
        if caminho.exists() {
            let pem = std::fs::read_to_string(&caminho)
                .with_context(|| format!("lendo {}", caminho.display()))?;
            let chave = RsaPrivateKey::from_pkcs8_pem(&pem)
                .context("chave do dispositivo inválida")?;
            return Ok(Dispositivo { chave });
        }
        let mut rng = rand::thread_rng();
        let chave = RsaPrivateKey::new(&mut rng, 2048).context("gerando RSA-2048")?;
        if let Some(dir) = caminho.parent() {
            std::fs::create_dir_all(dir).ok();
        }
        let pem = chave.to_pkcs8_pem(LineEnding::LF).context("serializando a chave")?;
        std::fs::write(&caminho, pem.as_bytes()).with_context(|| format!("gravando {}", caminho.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&caminho, std::fs::Permissions::from_mode(0o600)).ok();
        }
        Ok(Dispositivo { chave })
    }

    fn publica(&self) -> RsaPublicKey {
        RsaPublicKey::from(&self.chave)
    }

    /// Pública como PEM SubjectPublicKeyInfo (`-----BEGIN PUBLIC KEY-----`).
    pub fn publica_pem(&self) -> Result<String> {
        Ok(self.publica().to_public_key_pem(LineEnding::LF)?)
    }

    /// Pública como base64 do DER SubjectPublicKeyInfo, uma linha (sem cabeçalhos PEM).
    pub fn publica_b64_der(&self) -> Result<String> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let der = self.publica().to_public_key_der()?;
        Ok(STANDARD.encode(der.as_bytes()))
    }

    /// Base64 da assinatura RSA-2048 (PKCS#1 v1.5 + SHA-256) da chave do dispositivo sobre `dados`.
    /// É o bloco que vai depois de `"Bearer "` no `Authorization` das chamadas autenticadas pelo
    /// dispositivo. O que entra em `dados` depende do endpoint:
    ///  - carteira/statusCelular: os bytes do **valor do `momento`** (provado 16/10: o servidor
    ///    recusa a assinatura do corpo inteiro e aceita só o valor do momento);
    ///  - tokensessao/requestHashSessionSignature: os bytes **do corpo JSON serializado** (conforme
    ///    a RE da DLL do provider — a confirmar no 1º teste real).
    /// Quem chama decide, e assina exatamente os bytes que envia.
    pub fn assinar_bytes(&self, dados: &[u8]) -> Result<String> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use rsa::Pkcs1v15Sign;
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(dados);
        let sig = self
            .chave
            .sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
            .context("falha ao assinar para o Bearer")?;
        Ok(STANDARD.encode(sig))
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn gera_e_exporta_publica() {
        // chave pequena só pro teste ser rápido não dá (precisa 2048 p/ pkcs8); usa a real uma vez.
        let mut rng = rand::thread_rng();
        let chave = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let d = Dispositivo { chave };
        assert!(d.publica_pem().unwrap().contains("BEGIN PUBLIC KEY"));
        assert!(!d.publica_b64_der().unwrap().contains("BEGIN"));
    }
}
