//! Tipos partilhados pelo daemon e pelo módulo PKCS#11.
//!
//! O módulo (`libcertisign_p11.so`) roda dentro do Chrome e do Java e NÃO fala com a rede:
//! ele só conversa com o daemon por um socket Unix, trocando linhas de JSON (uma por mensagem).
//! O daemon é quem fala com a nuvem da Certisign. Este crate define essas mensagens.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Caminho do socket Unix do daemon: `$XDG_RUNTIME_DIR/certisign-nuvem.sock`.
/// Sem `XDG_RUNTIME_DIR`, cai para `/run/user/<uid>` e, por fim, `/tmp`.
pub fn caminho_socket() -> PathBuf {
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir).join("certisign-nuvem.sock");
        }
    }
    let uid = unsafe { libc_getuid() };
    let run = PathBuf::from(format!("/run/user/{uid}"));
    if run.is_dir() {
        return run.join("certisign-nuvem.sock");
    }
    std::env::temp_dir().join(format!("certisign-nuvem-{uid}.sock"))
}

// Evita uma dependência só para ler o uid.
extern "C" {
    #[link_name = "getuid"]
    fn libc_getuid() -> u32;
}

/// Pedido do módulo para o daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Pedido {
    /// Estado da sessão (logado? e-Token aprovado?).
    Estado,
    /// Certificado do utilizador + cadeia de ACs (DER).
    Certificados,
    /// Assina um digest já pronto. `hash_b64` é o digest em base64; `algoritmo` ex.: "SHA256".
    Assinar { hash_b64: String, algoritmo: String },
}

/// Resposta do daemon para o módulo.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resposta {
    Estado(EstadoSessao),
    Certificados(Certificados),
    /// Assinatura em base64 (o padding RSA é aplicado pela nuvem).
    Assinatura { assinatura_b64: String },
    Erro { mensagem: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EstadoSessao {
    pub logado: bool,
    pub nome: Option<String>,
    pub aprovado: bool,
}

/// Certificado do utilizador + cadeia, todos DER (bytes crus, não base64).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificados {
    pub utilizador_der: Vec<u8>,
    pub cadeia_der: Vec<Vec<u8>>,
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn socket_respeita_xdg() {
        std::env::set_var("XDG_RUNTIME_DIR", "/run/user/1234");
        assert_eq!(caminho_socket(), PathBuf::from("/run/user/1234/certisign-nuvem.sock"));
    }

    #[test]
    fn pedido_assinar_ida_e_volta() {
        let p = Pedido::Assinar { hash_b64: "YWJj".into(), algoritmo: "SHA256".into() };
        let linha = serde_json::to_string(&p).unwrap();
        assert!(linha.contains("\"op\":\"assinar\""));
        let de: Pedido = serde_json::from_str(&linha).unwrap();
        matches!(de, Pedido::Assinar { .. });
    }

    #[test]
    fn resposta_erro_ida_e_volta() {
        let r = Resposta::Erro { mensagem: "sem sessão".into() };
        let linha = serde_json::to_string(&r).unwrap();
        let de: Resposta = serde_json::from_str(&linha).unwrap();
        matches!(de, Resposta::Erro { .. });
    }
}
