//! Estado vivo do daemon: a sessão logada e o certificado em cache.
//! O `sessionToken` de cada assinatura é efémero e NÃO fica guardado aqui entre assinaturas
//! (recriado a cada pedido), tal como no desktopID original.

use anyhow::{anyhow, Result};
use certisign_nuvem_core::{Certificados, EstadoSessao};
use std::time::Duration;

use crate::config::Config;
use crate::dispositivo::Dispositivo;
use crate::estado::Estado;
use crate::nuvem::{Login, Nuvem};

pub struct Sessao {
    pub cfg: Config,
    pub nuvem: Nuvem,
    pub login: Option<Login>,
    pub certificados: Option<Certificados>,
    /// Quantas vezes pollar o e-Token e com que intervalo (loop de ~60 s, como no binário).
    pub tentativas_etoken: u32,
    pub intervalo_etoken: Duration,
}

impl Sessao {
    pub fn nova(cfg: Config) -> Result<Sessao> {
        let nuvem = Nuvem::nova(&cfg)?;
        Ok(Sessao {
            cfg,
            nuvem,
            login: None,
            certificados: None,
            tentativas_etoken: 60,
            intervalo_etoken: Duration::from_secs(1),
        })
    }

    pub fn estado(&self) -> EstadoSessao {
        EstadoSessao {
            logado: self.login.is_some(),
            nome: self.login.as_ref().map(|l| l.nome.clone()),
            aprovado: false,
        }
    }

    pub async fn entrar(&mut self, senha: &str) -> Result<()> {
        let login = self.nuvem.login(&self.cfg, senha).await?;
        self.login = Some(login);
        Ok(())
    }

    /// Garante que este dispositivo está registrado no remoteID. Gera a chave do dispositivo na
    /// 1ª vez, registra a pública (PEM) e guarda o `codigoDesktop`. Idempotente: não repete se já
    /// feito. Devolve o `codigoDesktop` (usado na URL da carteira/statusCelular).
    pub async fn registrar_dispositivo(&mut self) -> Result<String> {
        let mut estado = Estado::carregar();
        if estado.registrado() {
            return Ok(estado.codigo_desktop);
        }
        let login = self.login.as_ref().ok_or_else(|| anyhow!("sem sessão: faça login"))?.clone();
        let disp = Dispositivo::carregar_ou_gerar()?;
        // O registro no remoteID quer a pública em PEM (SPKI).
        let public_key = disp.publica_pem()?;
        let codigo = self.nuvem.criar_dispositivo(&self.cfg, &login, &public_key).await?;
        estado.codigo_desktop = codigo.clone();
        estado.salvar()?;
        Ok(codigo)
    }

    pub async fn obter_certificados(&mut self) -> Result<Certificados> {
        // A carteira exige o dispositivo registrado; registra na 1ª vez.
        let codigo = self.registrar_dispositivo().await?;
        if self.certificados.is_none() {
            let disp = Dispositivo::carregar_ou_gerar()?;
            let momento = momento_segundos(); // carteira: assina o VALOR do momento
            let bearer = disp.assinar_bytes(momento.as_bytes())?;
            let (certs, key_name) = self.nuvem.carteira(&codigo, &momento, &bearer).await?;
            // `keyName` = "<serialNumber hex>;<DN do emissor>". Guarda os dois para a assinatura.
            if let Some((serial, issue)) = key_name.split_once(';') {
                let mut est = Estado::carregar();
                est.serial_number = serial.trim().to_string();
                est.issue = issue.trim().to_string();
                let _ = est.salvar();
            }
            self.certificados = Some(certs);
        }
        Ok(self.certificados.clone().unwrap())
    }

    /// Fluxo de assinatura (caminho remoteid, sessão): 1) `tokensessao` abre a sessão e dispara o
    /// e-Token (push:true) ou valida o `otp`; devolve o `sessionToken`. 2) `requestHashSessionSignature`
    /// manda o hash e devolve a assinatura. As duas são autenticadas por `Bearer` = assinatura do
    /// dispositivo sobre o corpo JSON serializado. Sem `otp` → usa push; com `otp` → push:false.
    pub async fn assinar(&mut self, hash_b64: &str, algoritmo: &str, pin: &str, otp: &str)
        -> Result<String>
    {
        // Garante dispositivo registrado + certificado + serialNumber/issue no estado.
        self.obter_certificados().await?;
        let est = Estado::carregar();
        if est.codigo_desktop.is_empty() {
            return Err(anyhow!("dispositivo não registrado"));
        }
        if est.serial_number.is_empty() || est.issue.is_empty() {
            return Err(anyhow!("serialNumber/issue ausentes — rode a carteira antes"));
        }
        let disp = Dispositivo::carregar_ou_gerar()?;
        let push = otp.trim().is_empty(); // sem OTP → aprovar pelo push no celular

        // 1) tokensessao → sessionToken.
        // O corpo ENVIADO vai no formato "bonito" do desktopID (render_desktopid). Mas o Bearer NÃO
        // assina o corpo: assina a CONCATENAÇÃO DOS VALORES (sem chaves/aspas/pontuação), em ordem de
        // chave — é o que a DLL faz em FUN_180110080 (provado: na carteira isso = só o momento).
        let ts_val = serde_json::json!({
            "desktopCode": est.codigo_desktop,
            "pin": pin,
            "otp": otp,
            "push": push,
            "nomeAplicacaoDesktop": "",
            "serialNumber": est.serial_number,
            "issue": est.issue,
        });
        let corpo_ts = render_desktopid(&ts_val);
        let bearer_ts = disp.assinar_bytes(concat_valores(&ts_val).as_bytes())?;
        let session_token = self.nuvem.token_sessao(&corpo_ts, &bearer_ts).await?;

        // 2) requestHashSessionSignature → assinatura (mesmo esquema de Bearer).
        let as_val = serde_json::json!({
            "desktopCode": est.codigo_desktop,
            "sessionToken": session_token,
            "issue": est.issue,
            "serialNumber": est.serial_number,
            "algorithm": algoritmo,
            "hashArray": [ { "id": 0, "hash": hash_b64 } ],
        });
        let corpo_as = render_desktopid(&as_val);
        let bearer_as = disp.assinar_bytes(concat_valores(&as_val).as_bytes())?;
        self.nuvem.assinar_sessao(&corpo_as, &bearer_as).await
    }
}

/// Concatena os VALORES de um JSON (recursivo, em ordem de chave), sem chaves, aspas, separadores
/// nem pontuação — reproduz FUN_180110080 do desktopID_Provider. É sobre ESTA string que o Bearer
/// do tokensessao/requestHashSessionSignature assina (provado: na carteira = só o valor do momento).
/// Strings entram cruas; números em decimal; booleanos e null NÃO entram (a DLL pula `push:false`).
fn concat_valores(v: &serde_json::Value) -> String {
    fn vai(v: &serde_json::Value, out: &mut String) {
        match v {
            serde_json::Value::Object(m) => for (_k, val) in m { vai(val, out); },
            serde_json::Value::Array(a) => for val in a { vai(val, out); },
            serde_json::Value::String(s) => out.push_str(s),
            serde_json::Value::Number(n) => out.push_str(&n.to_string()),
            serde_json::Value::Bool(_) | serde_json::Value::Null => {}
        }
    }
    let mut s = String::new();
    vai(v, &mut s);
    s
}

/// `momento` em epoch de SEGUNDOS (usado na carteira).
fn momento_segundos() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .to_string()
}

/// Serializa um `serde_json::Value` no formato EXATO do desktopID (visto na captura do tokensessao):
/// indentado com TAB, separador `" : "` (espaço antes e depois do `:`), chaves ordenadas, e contêiner
/// (objeto/array) começa em nova linha após o `:`. É sobre ESTES bytes que o servidor verifica a
/// assinatura do Bearer — assinar o JSON compacto é recusado ("Código de autorização inválida").
fn render_desktopid(v: &serde_json::Value) -> String {
    fn escalar(v: &serde_json::Value) -> String {
        match v {
            // usa o escaping JSON do serde (devolve a string já com aspas)
            serde_json::Value::String(_) => v.to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Null => "null".to_string(),
            _ => String::new(),
        }
    }
    fn tab(n: usize) -> String { "\t".repeat(n) }
    fn container(v: &serde_json::Value, d: usize) -> String {
        match v {
            serde_json::Value::Object(m) => {
                // serde_json::Map (sem feature preserve_order) itera em ordem de chave.
                let partes: Vec<String> = m.iter().map(|(k, val)| {
                    let repr = if val.is_object() || val.is_array() {
                        format!("\n{}{}", tab(d + 1), container(val, d + 1))
                    } else {
                        escalar(val)
                    };
                    format!("{}\"{}\" : {}", tab(d + 1), k, repr)
                }).collect();
                format!("{{\n{}\n{}}}", partes.join(",\n"), tab(d))
            }
            serde_json::Value::Array(a) => {
                let partes: Vec<String> = a.iter().map(|val| {
                    let repr = if val.is_object() || val.is_array() {
                        container(val, d + 1)
                    } else {
                        escalar(val)
                    };
                    format!("{}{}", tab(d + 1), repr)
                }).collect();
                format!("[\n{}\n{}]", partes.join(",\n"), tab(d))
            }
            _ => escalar(v),
        }
    }
    container(v, 0)
}

#[cfg(test)]
mod testes {
    use super::render_desktopid;

    #[test]
    fn formato_tokensessao_bate_com_a_captura() {
        // Mesma ESTRUTURA/ordem do corpo real capturado (valores fictícios).
        let v = serde_json::json!({
            "desktopCode": "ABC",
            "pin": "senha",
            "otp": "123456",
            "push": false,
            "nomeAplicacaoDesktop": "",
            "serialNumber": "deadbeef",
            "issue": "CN=X",
        });
        let esperado = "{\n\t\"desktopCode\" : \"ABC\",\n\t\"issue\" : \"CN=X\",\n\t\"nomeAplicacaoDesktop\" : \"\",\n\t\"otp\" : \"123456\",\n\t\"pin\" : \"senha\",\n\t\"push\" : false,\n\t\"serialNumber\" : \"deadbeef\"\n}";
        assert_eq!(render_desktopid(&v), esperado);
    }

    #[test]
    fn formato_array_aninhado_do_requesthash() {
        let v = serde_json::json!({
            "algorithm": "SHA256",
            "hashArray": [ { "id": 0, "hash": "AAAA" } ],
        });
        let esperado = "{\n\t\"algorithm\" : \"SHA256\",\n\t\"hashArray\" : \n\t[\n\t\t{\n\t\t\t\"hash\" : \"AAAA\",\n\t\t\t\"id\" : 0\n\t\t}\n\t]\n}";
        assert_eq!(render_desktopid(&v), esperado);
    }
}
