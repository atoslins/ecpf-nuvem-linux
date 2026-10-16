//! Cliente do socket Unix do daemon. O módulo roda dentro do Chrome e do Java e NÃO fala com a
//! rede: ele só troca uma linha de JSON com o daemon. Síncrono de propósito (sem tokio).

use certisign_nuvem_core::{caminho_socket, Certificados, Pedido, Resposta};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

type Erro = Box<dyn std::error::Error>;

fn conversa(pedido: &Pedido) -> Result<Resposta, Erro> {
    let caminho = caminho_socket();
    let stream = UnixStream::connect(&caminho)
        .map_err(|e| format!("daemon fora do ar ({}): {e}", caminho.display()))?;
    // A assinatura espera a aprovação no celular; dá folga no tempo.
    stream.set_read_timeout(Some(Duration::from_secs(120)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut escrita = stream.try_clone()?;
    let mut linha = serde_json::to_string(pedido)?;
    linha.push('\n');
    escrita.write_all(linha.as_bytes())?;
    escrita.flush()?;
    let mut leitor = BufReader::new(stream);
    let mut resp = String::new();
    leitor.read_line(&mut resp)?;
    if resp.trim().is_empty() {
        return Err("daemon fechou sem responder".into());
    }
    Ok(serde_json::from_str(resp.trim())?)
}

pub fn certificados() -> Result<Certificados, Erro> {
    match conversa(&Pedido::Certificados)? {
        Resposta::Certificados(c) => Ok(c),
        Resposta::Erro { mensagem } => Err(mensagem.into()),
        _ => Err("resposta inesperada do daemon".into()),
    }
}

pub fn assinar(hash_b64: String, algoritmo: String) -> Result<Vec<u8>, Erro> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    match conversa(&Pedido::Assinar { hash_b64, algoritmo })? {
        Resposta::Assinatura { assinatura_b64 } => Ok(STANDARD.decode(assinatura_b64.trim())?),
        Resposta::Erro { mensagem } => Err(mensagem.into()),
        _ => Err("resposta inesperada do daemon".into()),
    }
}

#[cfg(test)]
mod testes {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    #[test]
    fn assinar_vai_e_volta_pelo_socket() {
        // isola o socket num diretório temporário só deste teste
        let dir = std::env::temp_dir().join(format!("certisign-teste-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("XDG_RUNTIME_DIR", &dir);
        let caminho = caminho_socket();
        let _ = std::fs::remove_file(&caminho);
        let ouvinte = UnixListener::bind(&caminho).unwrap();

        // daemon falso: lê um pedido Assinar e devolve uma assinatura canônica (base64 de "assinado").
        let t = std::thread::spawn(move || {
            let (stream, _) = ouvinte.accept().unwrap();
            let mut leitor = BufReader::new(stream.try_clone().unwrap());
            let mut linha = String::new();
            leitor.read_line(&mut linha).unwrap();
            let pedido: Pedido = serde_json::from_str(linha.trim()).unwrap();
            assert!(matches!(pedido, Pedido::Assinar { .. }));
            let mut escrita = stream;
            let r = Resposta::Assinatura { assinatura_b64: "YXNzaW5hZG8=".into() };
            let mut s = serde_json::to_string(&r).unwrap();
            s.push('\n');
            escrita.write_all(s.as_bytes()).unwrap();
            escrita.flush().unwrap();
        });

        let sig = assinar("aGFzaA==".into(), "SHA256".into()).unwrap();
        assert_eq!(sig, b"assinado");
        t.join().unwrap();
        let _ = std::fs::remove_file(&caminho);
    }
}
