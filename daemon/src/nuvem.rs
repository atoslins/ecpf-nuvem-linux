//! Cliente HTTPS da nuvem remoteID da Certisign.
//!
//! Endpoints e corpos vêm da engenharia reversa (NOTAS, "desktopID — nuvem", itens a–e),
//! auditada em 12/10. Dois pontos continuam "a confirmar no tráfego real" e estão marcados
//! com CONFIRMAR: o TTL do sessionToken e o padding RSA exato. A conta real só é usada com o dono.

use anyhow::{anyhow, bail, Context, Result};
use certisign_nuvem_core::Certificados;
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;

use crate::config::Config;

pub struct Nuvem {
    http: reqwest::Client,
    base: String,
}

/// Dados da conta após o login (`/api/manager/usuarios/login/usrsenha`).
#[derive(Debug, Clone)]
pub struct Login {
    pub user_id: String,
    pub org_id: String,
    pub nome: String,
    pub token_gestor: String,
}

#[derive(Debug, Deserialize)]
struct RespLogin {
    #[serde(default)]
    id: Option<serde_json::Value>,
    #[serde(default, rename = "organizacaoId")]
    organizacao_id: Option<serde_json::Value>,
    #[serde(default)]
    nome: Option<String>,
    #[serde(default)]
    token: Option<String>,
}

/// Converte um campo numérico/string do JSON em String (ids da Certisign vêm como número).
fn val_para_str(v: Option<serde_json::Value>) -> Option<String> {
    match v {
        Some(serde_json::Value::String(s)) => Some(s),
        Some(serde_json::Value::Number(n)) => Some(n.to_string()),
        _ => None,
    }
}

impl Nuvem {
    pub fn nova(cfg: &Config) -> Result<Nuvem> {
        let http = reqwest::Client::builder()
            .user_agent("desktopID_Provider")
            .timeout(Duration::from_secs(30))
            // O desktopID mantém o JSESSIONID entre login/registro/carteira (visto na captura).
            .cookie_store(true)
            .build()
            .context("não consegui montar o cliente HTTPS")?;
        Ok(Nuvem { http, base: cfg.base_url() })
    }

    /// Login por e-mail+senha. Devolve o id do utilizador, o nome e o token Bearer de gestão.
    pub async fn login(&self, cfg: &Config, senha: &str) -> Result<Login> {
        let url = format!("{}/api/manager/usuarios/login/usrsenha", self.base);
        let corpo = json!({ "email": cfg.email, "urlAcesso": cfg.url_acesso, "senha": senha });
        let resp = self.http.post(&url).json(&corpo).send().await
            .context("falha de rede no login")?;
        let status = resp.status();
        let texto = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!("login recusado (HTTP {status}): {}", recorte(&texto));
        }
        let r: RespLogin = serde_json::from_str(&texto)
            .with_context(|| format!("resposta de login inesperada: {}", recorte(&texto)))?;
        let token = r.token.ok_or_else(|| anyhow!("login sem token na resposta"))?;
        let user_id = val_para_str(r.id).ok_or_else(|| anyhow!("login sem id na resposta"))?;
        let org_id = val_para_str(r.organizacao_id).unwrap_or_else(|| "0".to_string());
        Ok(Login { user_id, org_id, nome: r.nome.unwrap_or_default(), token_gestor: token })
    }

    /// Registra este dispositivo no remoteID e devolve o `codigoDesktop`.
    ///
    /// Endpoint real (provado na captura): `POST /api/manager/desktopid/usuario/<userId>/organizacao/<orgId>`
    /// com `Authorization: Bearer <token do login>` e corpo em português:
    /// `{chavePublica (PEM), dominioRede, nomeDesktop, nomeUsuarioLocal, sistemaOperacional}`.
    /// Responde 201 com `{id, codigoDesktop, ...}`. (O caminho antigo `<certinext>/desktop/create`
    /// era um beco sem saída: devolvia um código que a carteira não reconhecia.)
    pub async fn criar_dispositivo(&self, cfg: &Config, login: &Login, public_key_pem: &str)
        -> Result<String>
    {
        let url = format!(
            "{}/api/manager/desktopid/usuario/{}/organizacao/{}",
            self.base, login.user_id, login.org_id
        );
        let dominio = if cfg.domain_name.trim().is_empty() { "Local" } else { cfg.domain_name.trim() };
        let corpo = json!({
            "chavePublica": public_key_pem,
            "dominioRede": dominio,
            "nomeDesktop": cfg.installation_name,
            "nomeUsuarioLocal": cfg.user_name,
            "sistemaOperacional": cfg.operational_system,
        });
        let resp = self.http.post(&url)
            .bearer_auth(&login.token_gestor)
            .json(&corpo)
            .send().await.context("falha de rede ao registrar o dispositivo")?;
        let status = resp.status();
        let texto = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!("registro do dispositivo recusado (HTTP {status}): {}", recorte(&texto));
        }
        let v: serde_json::Value = serde_json::from_str(&texto)
            .with_context(|| format!("registro com resposta inesperada: {}", recorte(&texto)))?;
        v.get("codigoDesktop").and_then(|c| c.as_str()).map(str::to_string)
            .ok_or_else(|| anyhow!("registro sem codigoDesktop: {}", recorte(&texto)))
    }

    /// Certificado do utilizador + cadeia: `POST /api/manager/desktopid/<codigoDesktop>/carteira`.
    /// A URL usa o `codigoDesktop` (não o userId) e o `Authorization` é a assinatura do dispositivo
    /// sobre o `momento` (não o token do login) — ambos provados na captura.
    pub async fn carteira(&self, codigo_desktop: &str, momento: &str, bearer: &str)
        -> Result<(Certificados, String)>
    {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let url = format!("{}/api/manager/desktopid/{}/carteira", self.base, codigo_desktop);
        let resp = self.http.post(&url)
            .header("Authorization", format!("Bearer {bearer}"))
            .json(&json!({ "momento": momento }))
            .send().await.context("falha de rede ao buscar a carteira")?;
        let status = resp.status();
        let texto = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!("carteira recusada (HTTP {status}): {}", recorte(&texto));
        }
        // Depuração opcional: grava a resposta crua para inspecionar a estrutura (cadeia etc).
        if let Ok(caminho) = std::env::var("CERTISIGN_DUMP_CARTEIRA") {
            let _ = std::fs::write(&caminho, &texto);
        }
        let v: serde_json::Value = serde_json::from_str(&texto)
            .with_context(|| format!("carteira inesperada: {}", recorte(&texto)))?;
        let item0 = v.get("certificados").and_then(|c| c.as_array()).and_then(|a| a.first())
            .ok_or_else(|| anyhow!("carteira sem certificado do utilizador"))?;
        let util = extrai_der_b64(item0)
            .ok_or_else(|| anyhow!("carteira sem base64 do certificado"))?;
        let util = STANDARD.decode(util.trim()).context("certificado não é base64 válido")?;
        // `keyName` = "<serialNumber hex>;<DN do emissor>" — base para a assinatura.
        let key_name = item0.get("keyName").and_then(|k| k.as_str()).unwrap_or("").to_string();
        let mut cadeia = Vec::new();
        if let Some(arr) = v.get("hierarchies").and_then(|c| c.as_array()) {
            for h in arr {
                if let Some(b64) = extrai_der_b64(h) {
                    if let Ok(der) = STANDARD.decode(b64.trim()) {
                        cadeia.push(der);
                    }
                }
            }
        }
        Ok((Certificados { utilizador_der: util, cadeia_der: cadeia }, key_name))
    }

    /// Abre uma sessão de assinatura: `POST /api/signature/tokensessao`.
    /// `corpo` = JSON já serializado (`desktopCode, pin, otp, push, nomeAplicacaoDesktop,
    /// serialNumber, issue`); `bearer` = assinatura do dispositivo sobre ESSE corpo. Com `push:true`
    /// o servidor dispara o e-Token; pela RE da DLL a resposta só vem após a aprovação. Devolve o
    /// `sessionToken` (campo `token`).
    pub async fn token_sessao(&self, corpo: &str, bearer: &str) -> Result<String> {
        let url = format!("{}/api/signature/tokensessao", self.base);
        let resp = self.http.post(&url)
            .header("Authorization", format!("Bearer {bearer}"))
            .header("Content-Type", "application/json")
            .body(corpo.to_string())
            .send().await.context("falha de rede no tokensessao")?;
        let status = resp.status();
        let texto = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!("tokensessao recusado (HTTP {status}): {}", recorte(&texto));
        }
        let v: serde_json::Value = serde_json::from_str(&texto)
            .with_context(|| format!("tokensessao inesperado: {}", recorte(&texto)))?;
        if status_bool(&v) == Some(false) {
            let msg = v.get("message").and_then(|m| m.as_str()).unwrap_or("");
            bail!("tokensessao recusado: {}", if msg.is_empty() { recorte(&texto) } else { msg.to_string() });
        }
        v.get("token").and_then(|t| t.as_str()).map(str::to_string)
            .ok_or_else(|| anyhow!("tokensessao sem token: {}", recorte(&texto)))
    }

    /// Consulta de aprovação do e-Token: `POST /api/manager/desktopid/<codigoDesktop>/statusCelular`.
    /// Mesma autenticação da carteira (assinatura do dispositivo sobre o `momento`, aqui em ms).
    /// ATENÇÃO: na captura (fora de um fluxo de assinatura) a resposta foi
    /// `{usuarioPossuiCodigoPush: true}` — isso é "o usuário tem push", NÃO "aprovou". O campo de
    /// aprovação de verdade só aparece durante uma assinatura; a confirmar quando atacarmos o C_Sign.
    /// A carteira (buscar certificado) não passa por aqui.
    pub async fn status_celular(&self, codigo_desktop: &str, momento: &str, bearer: &str)
        -> Result<bool>
    {
        let url = format!("{}/api/manager/desktopid/{}/statusCelular", self.base, codigo_desktop);
        let resp = self.http.post(&url)
            .header("Authorization", format!("Bearer {bearer}"))
            .json(&json!({ "momento": momento }))
            .send().await.context("falha de rede no statusCelular")?;
        if !resp.status().is_success() {
            return Ok(false);
        }
        let v: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
        Ok(aprovado(&v))
    }

    /// Assina o digest via sessão: `POST /api/signature/requestHashSessionSignature`.
    /// `corpo` = JSON já serializado (`desktopCode, sessionToken, issue, serialNumber, algorithm,
    /// hashArray:[{id:0, hash}]`); `bearer` = assinatura do dispositivo sobre ESSE corpo. Entra o
    /// digest base64, sai a assinatura base64 (`idArray[0].signatureBase64`); o padding é da nuvem.
    pub async fn assinar_sessao(&self, corpo: &str, bearer: &str) -> Result<String> {
        let url = format!("{}/api/signature/requestHashSessionSignature", self.base);
        let resp = self.http.post(&url)
            .header("Authorization", format!("Bearer {bearer}"))
            .header("Content-Type", "application/json")
            .body(corpo.to_string())
            .send().await.context("falha de rede na assinatura")?;
        let status = resp.status();
        let texto = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!("assinatura recusada (HTTP {status}): {}", recorte(&texto));
        }
        let v: serde_json::Value = serde_json::from_str(&texto)
            .with_context(|| format!("assinatura inesperada: {}", recorte(&texto)))?;
        if status_bool(&v) == Some(false) {
            let msg = v.get("message").and_then(|m| m.as_str()).unwrap_or("");
            bail!("assinatura recusada: {}", if msg.is_empty() { recorte(&texto) } else { msg.to_string() });
        }
        v.get("idArray").and_then(|a| a.as_array()).and_then(|a| a.first())
            .and_then(|e| e.get("signatureBase64")).and_then(|s| s.as_str())
            .map(str::to_string)
            .ok_or_else(|| anyhow!("assinatura sem signatureBase64: {}", recorte(&texto)))
    }
}

/// Lê o campo `status` tolerando bool ou string ("true"/"false"). `None` se ausente/indefinido.
fn status_bool(v: &serde_json::Value) -> Option<bool> {
    match v.get("status") {
        Some(serde_json::Value::Bool(b)) => Some(*b),
        Some(serde_json::Value::String(s)) => match s.trim().to_ascii_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// Um item da carteira pode ser string base64 direta ou objeto com campo "base64"/"certificado".
fn extrai_der_b64(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Object(_) => v.get("base64").or_else(|| v.get("certificado"))
            .and_then(|x| x.as_str()).map(str::to_string),
        _ => None,
    }
}

/// Lê um status de aprovação tolerando os nomes/representações vistos no binário.
fn aprovado(v: &serde_json::Value) -> bool {
    for chave in ["status", "aprovado", "approved", "done"] {
        match v.get(chave) {
            Some(serde_json::Value::Bool(b)) => return *b,
            Some(serde_json::Value::String(s)) => {
                let s = s.trim().to_ascii_lowercase();
                if s == "true" || s == "aprovado" || s == "ok" {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// Corta um corpo de resposta para log/erro (não vaza um dump gigante).
fn recorte(s: &str) -> String {
    let s = s.trim();
    if s.len() > 300 {
        format!("{}…", &s[..300])
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn aprovado_aceita_variantes() {
        assert!(aprovado(&json!({"status": true})));
        assert!(aprovado(&json!({"status": "true"})));
        assert!(aprovado(&json!({"aprovado": "ok"})));
        assert!(!aprovado(&json!({"status": false})));
        assert!(!aprovado(&json!({"outra": "coisa"})));
    }

    #[test]
    fn extrai_der_de_string_e_objeto() {
        assert_eq!(extrai_der_b64(&json!("QUJD")).as_deref(), Some("QUJD"));
        assert_eq!(extrai_der_b64(&json!({"base64": "QUJD"})).as_deref(), Some("QUJD"));
        assert_eq!(extrai_der_b64(&json!({"certificado": "QUJD"})).as_deref(), Some("QUJD"));
        assert_eq!(extrai_der_b64(&json!(42)), None);
    }

    #[test]
    fn recorte_limita_tamanho() {
        let g = "x".repeat(400);
        assert!(recorte(&g).len() <= 304);
    }
}
