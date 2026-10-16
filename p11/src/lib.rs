//! `libcertisign_p11.so` — módulo PKCS#11 do e-CPF em nuvem da Certisign.
//!
//! Toda a maquinaria Cryptoki vem do crate `native-pkcs11` (Google, Apache-2.0). Aqui só
//! registamos o nosso `Backend`, que é um cliente fino do daemon `certisign-nuvemd` pelo socket
//! Unix. Nenhuma chamada de rede neste módulo: ele roda dentro do Chrome e do Java.

mod backend;
mod cliente;

use native_pkcs11::{CK_FUNCTION_LIST_PTR_PTR, CK_RV, CKR_OK};
use std::sync::Once;

/// CKR_ARGUMENTS_BAD do padrão Cryptoki (não é reexportado pelo native-pkcs11).
const CKR_ARGUMENTS_BAD: CK_RV = 7;

static REGISTO: Once = Once::new();

/// Ponto de entrada do PKCS#11. Regista o backend na primeira chamada e devolve a tabela de
/// funções do native-pkcs11 (usamos `custom-function-list`, então esta função é nossa).
///
/// # Safety
/// `ppFunctionList` tem de ser um ponteiro válido onde escrever o endereço da tabela.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn C_GetFunctionList(ppFunctionList: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    if ppFunctionList.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    REGISTO.call_once(|| {
        native_pkcs11_traits::register_backend(Box::new(backend::BackendNuvem));
    });
    unsafe {
        *ppFunctionList = std::ptr::addr_of_mut!(native_pkcs11::FUNC_LIST);
    }
    CKR_OK
}
