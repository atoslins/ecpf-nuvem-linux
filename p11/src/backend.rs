//! Implementação do `Backend` do native-pkcs11 como cliente fino do daemon.
//! Um token, um certificado (o do utilizador) + a cadeia como certificados extra. A chave privada
//! não existe aqui: `sign` manda o digest ao daemon, que fala com a nuvem.

use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD, Engine};
use native_pkcs11_traits::{
    Backend, Certificate, KeyAlgorithm, KeySearchOptions, PrivateKey, PublicKey, SignatureAlgorithm,
};
use sha2::Digest;

use crate::cliente;

type Erro = Box<dyn std::error::Error>;
type Resultado<T> = std::result::Result<T, Erro>;

/// Id estável partilhado pelo certificado e pela chave (CKA_ID): SHA-1 do DER do certificado.
fn id_de(der: &[u8]) -> Vec<u8> {
    use sha1::Sha1;
    let mut h = Sha1::new();
    h.update(der);
    h.finalize().to_vec()
}

/// Extrai a chave pública RSA no formato PKCS#1 `RSAPublicKey` (SEQUENCE {modulus, exponent}) de um
/// certificado DER. É isto que o native-pkcs11 espera em `PublicKey::to_der()` (para tirar
/// CKA_MODULUS/CKA_PUBLIC_EXPONENT) — NÃO a SubjectPublicKeyInfo inteira.
fn rsa_pub_de(der: &[u8]) -> Resultado<Vec<u8>> {
    use der::Decode;
    let cert = x509_cert::Certificate::from_der(der).map_err(|e| format!("cert inválido: {e}"))?;
    let spki = cert.tbs_certificate.subject_public_key_info;
    // O conteúdo do BIT STRING da SPKI é o RSAPublicKey DER.
    let bits = spki
        .subject_public_key
        .as_bytes()
        .ok_or("chave pública com bits não alinhados")?;
    Ok(bits.to_vec())
}

#[derive(Debug)]
pub struct ChavePublica {
    id: Vec<u8>,
    rsa_der: Vec<u8>,
}

impl PublicKey for ChavePublica {
    fn id(&self) -> Vec<u8> {
        self.id.clone()
    }
    fn label(&self) -> String {
        "e-CPF (nuvem Certisign)".into()
    }
    fn to_der(&self) -> Vec<u8> {
        self.rsa_der.clone()
    }
    fn verify(&self, _alg: &SignatureAlgorithm, _data: &[u8], _sig: &[u8]) -> Resultado<()> {
        // Verificação não é feita pelo token; cabe a quem valida a assinatura.
        Err("verify não suportado pelo módulo em nuvem".into())
    }
    fn delete(self: Box<Self>) {}
    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::Rsa
    }
}

#[derive(Debug)]
pub struct Certificado {
    id: Vec<u8>,
    der: Vec<u8>,
    chave_pub: ChavePublica,
}

impl Certificado {
    fn novo(der: Vec<u8>) -> Resultado<Certificado> {
        let id = id_de(&der);
        let rsa_der = rsa_pub_de(&der)?;
        Ok(Certificado { id: id.clone(), der, chave_pub: ChavePublica { id, rsa_der } })
    }
}

impl Certificate for Certificado {
    fn id(&self) -> Vec<u8> {
        self.id.clone()
    }
    fn label(&self) -> String {
        "e-CPF (nuvem Certisign)".into()
    }
    fn to_der(&self) -> Vec<u8> {
        self.der.clone()
    }
    fn public_key(&self) -> &dyn PublicKey {
        &self.chave_pub
    }
    fn delete(self: Box<Self>) {}
}

pub struct ChavePrivada {
    id: Vec<u8>,
}

impl PrivateKey for ChavePrivada {
    fn id(&self) -> Vec<u8> {
        self.id.clone()
    }
    fn label(&self) -> String {
        "e-CPF (nuvem Certisign)".into()
    }
    fn delete(&self) {}
    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::Rsa
    }
    /// Aplica o digest conforme o mecanismo e manda ao daemon; a nuvem faz o padding PKCS#1 v1.5.
    fn sign(&self, algorithm: &SignatureAlgorithm, data: &[u8]) -> Resultado<Vec<u8>> {
        let (digest, alg_nuvem) = digest_para_nuvem(algorithm, data)?;
        let hash_b64 = STANDARD.encode(digest);
        cliente::assinar(hash_b64, alg_nuvem)
    }
}

/// Converte (mecanismo PKCS#11, dados) no (digest, nome de algoritmo) que a nuvem espera.
/// Variantes de hash: calculamos o digest aqui. `Raw`: os dados já são o que vai assinar.
/// CONFIRMAR no tráfego: o rótulo exato do algoritmo e o caminho Raw.
fn digest_para_nuvem(algorithm: &SignatureAlgorithm, data: &[u8]) -> Resultado<(Vec<u8>, String)> {
    use SignatureAlgorithm::*;
    match algorithm {
        RsaPkcs1v15Sha256 => Ok((sha2::Sha256::digest(data).to_vec(), "SHA256".into())),
        RsaPkcs1v15Sha384 => Ok((sha2::Sha384::digest(data).to_vec(), "SHA384".into())),
        RsaPkcs1v15Sha512 => Ok((sha2::Sha512::digest(data).to_vec(), "SHA512".into())),
        RsaPkcs1v15Sha1 => {
            use sha1::{Digest as _, Sha1};
            Ok((Sha1::digest(data).to_vec(), "SHA1".into()))
        }
        // Chrome/NSS no login por certificado (TLS client auth) manda via CKM_RSA_PKCS o
        // DigestInfo PKCS#1 já montado. A nuvem assina hash+algoritmo (ela é que monta o
        // DigestInfo), então extraímos o hash daqui e mandamos o nome certo. Se não for um
        // DigestInfo conhecido, cai no "RAW" (assina os bytes como vierem).
        RsaRaw | RsaPkcs1v15Raw => match extrai_digestinfo(data) {
            Some((alg, hash)) => Ok((hash, alg)),
            None => Ok((data.to_vec(), "RAW".into())),
        },
        RsaPss { .. } => Err("RSA-PSS não suportado por esta nuvem".into()),
        Ecdsa => Err("ECDSA não se aplica a este certificado (RSA)".into()),
    }
}

/// Se `data` for um DigestInfo PKCS#1 conhecido (o que o NSS manda no `CKM_RSA_PKCS` do TLS client
/// auth), devolve (nome do algoritmo, hash cru) para a nuvem remontar o DigestInfo e assinar certo.
fn extrai_digestinfo(data: &[u8]) -> Option<(String, Vec<u8>)> {
    // prefixo DER do DigestInfo  ->  (nome do algoritmo, tamanho do hash)
    const TABELA: &[(&[u8], &str, usize)] = &[
        (&[0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20], "SHA256", 32),
        (&[0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30], "SHA384", 48),
        (&[0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40], "SHA512", 64),
        (&[0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x05,0x00,0x04,0x14], "SHA1", 20),
    ];
    for (prefixo, nome, tam) in TABELA {
        if data.len() == prefixo.len() + tam && data.starts_with(prefixo) {
            return Some((nome.to_string(), data[prefixo.len()..].to_vec()));
        }
    }
    None
}

pub struct BackendNuvem;

impl Backend for BackendNuvem {
    fn name(&self) -> String {
        "Certisign nuvem".into()
    }

    fn find_all_certificates(&self) -> Resultado<Vec<Box<dyn Certificate>>> {
        let c = cliente::certificados()?;
        let mut v: Vec<Box<dyn Certificate>> = Vec::new();
        v.push(Box::new(Certificado::novo(c.utilizador_der)?));
        for der in c.cadeia_der {
            if let Ok(cert) = Certificado::novo(der) {
                v.push(Box::new(cert));
            }
        }
        Ok(v)
    }

    fn find_private_key(&self, query: KeySearchOptions) -> Resultado<Option<Arc<dyn PrivateKey>>> {
        let c = cliente::certificados()?;
        let id = id_de(&c.utilizador_der);
        let casa = match query {
            KeySearchOptions::Id(q) => q == id,
            KeySearchOptions::Label(_) => true,
        };
        Ok(if casa { Some(Arc::new(ChavePrivada { id })) } else { None })
    }

    fn find_public_key(&self, query: KeySearchOptions) -> Resultado<Option<Box<dyn PublicKey>>> {
        let c = cliente::certificados()?;
        let cert = Certificado::novo(c.utilizador_der)?;
        let casa = match query {
            KeySearchOptions::Id(q) => q == cert.id,
            KeySearchOptions::Label(_) => true,
        };
        Ok(if casa { Some(Box::new(cert.chave_pub)) } else { None })
    }

    fn find_all_private_keys(&self) -> Resultado<Vec<Arc<dyn PrivateKey>>> {
        let c = cliente::certificados()?;
        Ok(vec![Arc::new(ChavePrivada { id: id_de(&c.utilizador_der) })])
    }

    fn find_all_public_keys(&self) -> Resultado<Vec<Arc<dyn PublicKey>>> {
        let c = cliente::certificados()?;
        let cert = Certificado::novo(c.utilizador_der)?;
        Ok(vec![Arc::new(cert.chave_pub)])
    }

    fn generate_key(&self, _a: KeyAlgorithm, _l: Option<&str>) -> Resultado<Arc<dyn PrivateKey>> {
        Err("gerar chave não se aplica: a chave vive na nuvem".into())
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn sha256_vira_digest_de_32_bytes() {
        let (d, alg) = digest_para_nuvem(&SignatureAlgorithm::RsaPkcs1v15Sha256, b"abc").unwrap();
        assert_eq!(d.len(), 32);
        assert_eq!(alg, "SHA256");
    }

    #[test]
    fn sha384_e_512_rotulam_certo() {
        assert_eq!(digest_para_nuvem(&SignatureAlgorithm::RsaPkcs1v15Sha384, b"x").unwrap().1, "SHA384");
        assert_eq!(digest_para_nuvem(&SignatureAlgorithm::RsaPkcs1v15Sha512, b"x").unwrap().1, "SHA512");
    }

    #[test]
    fn raw_passa_os_dados_direto() {
        let (d, alg) = digest_para_nuvem(&SignatureAlgorithm::RsaPkcs1v15Raw, b"ja-pronto").unwrap();
        assert_eq!(d, b"ja-pronto");
        assert_eq!(alg, "RAW");
    }

    #[test]
    fn digestinfo_sha256_do_tls_vira_hash_sha256() {
        // DigestInfo SHA-256 (o que o NSS manda no login por certificado) -> hash + "SHA256".
        let mut di = vec![0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20];
        di.extend_from_slice(&[0xAB; 32]);
        let (d, alg) = digest_para_nuvem(&SignatureAlgorithm::RsaPkcs1v15Raw, &di).unwrap();
        assert_eq!(alg, "SHA256");
        assert_eq!(d, vec![0xAB; 32]);
    }

    #[test]
    fn pss_e_ecdsa_sao_recusados() {
        assert!(digest_para_nuvem(&SignatureAlgorithm::Ecdsa, b"x").is_err());
    }

    #[test]
    fn id_e_sha1_de_20_bytes() {
        assert_eq!(id_de(b"qualquer der").len(), 20);
    }
}
