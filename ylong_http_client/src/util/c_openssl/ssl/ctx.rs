// Copyright (c) 2023 Huawei Device Co., Ltd.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use core::{fmt, mem, ptr};
use std::ffi::CString;
use std::path::Path;

use libc::{c_int, c_uint, c_void};

use super::filetype::SslFiletype;
use super::method::SslMethod;
use super::version::SslVersion;
use crate::c_openssl::ffi::ssl::{
    SSL_CTX_free, SSL_CTX_get_cert_store, SSL_CTX_set_default_verify_paths, SSL_CTX_set_verify,
};
use crate::c_openssl::x509::{X509Store, X509StoreRef};
use crate::util::c_openssl::error::ErrorStack;
#[cfg(feature = "__c_openssl")]
use crate::util::c_openssl::ffi::ssl::SSL_CTX_ctrl;
use crate::util::c_openssl::ffi::ssl::{
    SSL_CTX_load_verify_locations, SSL_CTX_new, SSL_CTX_set_alpn_protos, SSL_CTX_set_cert_store,
    SSL_CTX_set_cert_verify_callback, SSL_CTX_set_cipher_list, SSL_CTX_up_ref,
    SSL_CTX_use_certificate_chain_file, SSL_CTX_use_certificate_file, SSL_CTX,
};
#[cfg(feature = "c_boringssl")]
use crate::util::c_openssl::ffi::ssl::{
    SSL_CTX_set1_sigalgs_list, SSL_CTX_set_max_proto_version, SSL_CTX_set_min_proto_version,
};
use crate::util::c_openssl::foreign::{Foreign, ForeignRef};
use crate::util::c_openssl::{cert_verify, check_ptr, check_ret, ssl_init};
use crate::util::config::tls::DefaultCertVerifier;

#[cfg(feature = "__c_openssl")]
const SSL_CTRL_SET_MIN_PROTO_VERSION: c_int = 123;
#[cfg(feature = "__c_openssl")]
const SSL_CTRL_SET_MAX_PROTO_VERSION: c_int = 124;
#[cfg(feature = "__c_openssl")]
const SSL_CTRL_SET_SIGALGS_LIST: c_int = 98;

foreign_type!(
    type CStruct = SSL_CTX;
    fn drop = SSL_CTX_free;
    pub(crate) struct SslContext;
    pub(crate) struct SslContextRef;
);

impl SslContext {
    pub(crate) fn builder(method: SslMethod) -> Result<SslContextBuilder, ErrorStack> {
        SslContextBuilder::new(method)
    }
}

// TODO: add useful info here.
impl fmt::Debug for SslContext {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "SslContext")
    }
}

impl Clone for SslContext {
    fn clone(&self) -> Self {
        (**self).to_owned()
    }
}

impl ToOwned for SslContextRef {
    type Owned = SslContext;

    fn to_owned(&self) -> Self::Owned {
        unsafe {
            SSL_CTX_up_ref(self.as_ptr());
            SslContext::from_ptr(self.as_ptr())
        }
    }
}

pub(crate) const SSL_VERIFY_NONE: c_int = 0;
pub(crate) const SSL_VERIFY_PEER: c_int = 1;

/// A builder for `SslContext`.
pub(crate) struct SslContextBuilder(SslContext);

impl SslContextBuilder {
    pub(crate) fn new(method: SslMethod) -> Result<Self, ErrorStack> {
        ssl_init();

        let ptr = check_ptr(unsafe { SSL_CTX_new(method.as_ptr()) })?;
        check_ret(unsafe { SSL_CTX_set_default_verify_paths(ptr) })?;

        let mut builder = Self::from_ptr(ptr);
        builder.set_verify(SSL_VERIFY_PEER);
        builder.set_cipher_list(
            "DEFAULT:!aNULL:!eNULL:!MD5:!3DES:!DES:!RC4:!IDEA:!SEED:!aDSS:!SRP:!PSK:!SHA1:!CBC",
        )?;
        builder.set_sigalgs_list()?;

        Ok(builder)
    }

    /// Creates a `SslContextBuilder` from a `SSL_CTX`.
    pub(crate) fn from_ptr(ptr: *mut SSL_CTX) -> Self {
        SslContextBuilder(SslContext(ptr))
    }

    /// Creates a `*mut SSL_CTX` from a `SSL_CTX`.
    pub(crate) fn as_ptr_mut(&mut self) -> *mut SSL_CTX {
        self.0 .0
    }

    /// Builds a `SslContext`.
    pub(crate) fn build(self) -> SslContext {
        self.0
    }

    pub(crate) fn set_min_proto_version(&mut self, version: SslVersion) -> Result<(), ErrorStack> {
        let ptr = self.as_ptr_mut();

        #[cfg(feature = "__c_openssl")]
        return check_ret(unsafe {
            SSL_CTX_ctrl(
                ptr,
                SSL_CTRL_SET_MIN_PROTO_VERSION,
                version.0 as libc::c_long,
                ptr::null_mut(),
            )
        } as c_int)
        .map(|_| ());

        #[cfg(feature = "c_boringssl")]
        return check_ret(
            unsafe { SSL_CTX_set_min_proto_version(ptr, version.0 as libc::c_ushort) } as c_int,
        )
        .map(|_| ());
    }

    pub(crate) fn set_max_proto_version(&mut self, version: SslVersion) -> Result<(), ErrorStack> {
        let ptr = self.as_ptr_mut();

        #[cfg(feature = "__c_openssl")]
        return check_ret(unsafe {
            SSL_CTX_ctrl(
                ptr,
                SSL_CTRL_SET_MAX_PROTO_VERSION,
                version.0 as libc::c_long,
                ptr::null_mut(),
            )
        } as c_int)
        .map(|_| ());
        #[cfg(feature = "c_boringssl")]
        return check_ret(
            unsafe { SSL_CTX_set_max_proto_version(ptr, version.0 as libc::c_ushort) } as c_int,
        )
        .map(|_| ());
    }

    /// Loads trusted root certificates from a file.\
    /// Uses to Set default locations for trusted CA certificates.
    ///
    /// The file should contain a sequence of PEM-formatted CA certificates.
    pub(crate) fn set_ca_file<P>(&mut self, file: P) -> Result<(), ErrorStack>
    where
        P: AsRef<Path>,
    {
        let file = Self::get_c_file(file)?;
        let ptr = self.as_ptr_mut();
        check_ret(unsafe {
            SSL_CTX_load_verify_locations(ptr, file.as_ptr() as *const _, ptr::null())
        })
        .map(|_| ())
    }

    /// Sets the list of supported ciphers for protocols before `TLSv1.3`.
    pub(crate) fn set_cipher_list(&mut self, list: &str) -> Result<(), ErrorStack> {
        let list = match CString::new(list) {
            Ok(cstr) => cstr,
            Err(_) => return Err(ErrorStack::get()),
        };
        let ptr = self.as_ptr_mut();

        check_ret(unsafe { SSL_CTX_set_cipher_list(ptr, list.as_ptr() as *const _) }).map(|_| ())
    }

    /// Loads a leaf certificate from a file.
    ///
    /// Only a single certificate will be loaded - use `add_extra_chain_cert` to
    /// add the remainder of the certificate chain, or
    /// `set_certificate_chain_file` to load the entire chain from a
    /// single file.
    pub(crate) fn set_certificate_file<P>(
        &mut self,
        file: P,
        file_type: SslFiletype,
    ) -> Result<(), ErrorStack>
    where
        P: AsRef<Path>,
    {
        let file = Self::get_c_file(file)?;
        let ptr = self.as_ptr_mut();
        check_ret(unsafe {
            SSL_CTX_use_certificate_file(ptr, file.as_ptr() as *const _, file_type.as_raw())
        })
        .map(|_| ())
    }

    /// Loads a certificate chain from file into ctx.
    /// The certificates must be in PEM format and must be sorted starting with
    /// the subject's certificate (actual client or server certificate),
    /// followed by intermediate CA certificates if applicable, and ending
    /// at the highest level (root) CA.
    pub(crate) fn set_certificate_chain_file<P>(&mut self, file: P) -> Result<(), ErrorStack>
    where
        P: AsRef<Path>,
    {
        let file = Self::get_c_file(file)?;
        let ptr = self.as_ptr_mut();
        check_ret(unsafe { SSL_CTX_use_certificate_chain_file(ptr, file.as_ptr() as *const _) })
            .map(|_| ())
    }

    pub(crate) fn get_c_file<P>(file: P) -> Result<CString, ErrorStack>
    where
        P: AsRef<Path>,
    {
        let path = match file.as_ref().as_os_str().to_str() {
            Some(path) => path,
            None => return Err(ErrorStack::get()),
        };
        match CString::new(path) {
            Ok(path) => Ok(path),
            Err(_) => Err(ErrorStack::get()),
        }
    }

    /// Sets the protocols to sent to the server for Application Layer Protocol
    /// Negotiation (ALPN).
    pub(crate) fn set_alpn_protos(&mut self, protocols: &[u8]) -> Result<(), ErrorStack> {
        assert!(protocols.len() <= c_uint::max_value() as usize);

        let ptr = self.as_ptr_mut();
        match unsafe { SSL_CTX_set_alpn_protos(ptr, protocols.as_ptr(), protocols.len() as c_uint) }
        {
            0 => Ok(()),
            _ => Err(ErrorStack::get()),
        }
    }

    pub(crate) fn set_verify(&mut self, mode: c_int) {
        let ptr = self.as_ptr_mut();
        unsafe { SSL_CTX_set_verify(ptr, mode, None) };
    }

    pub(crate) fn set_cert_verify_callback(&mut self, verifier: *const DefaultCertVerifier) {
        let ptr = self.as_ptr_mut();
        unsafe {
            SSL_CTX_set_cert_verify_callback(ptr, cert_verify, verifier as *mut c_void);
        }
    }

    pub(crate) fn set_cert_store(&mut self, cert_store: X509Store) {
        let ptr = self.as_ptr_mut();
        unsafe {
            SSL_CTX_set_cert_store(ptr, cert_store.as_ptr());
            mem::forget(cert_store);
        }
    }

    pub(crate) fn cert_store_mut(&mut self) -> &mut X509StoreRef {
        let ptr = self.as_ptr_mut();
        unsafe { X509StoreRef::from_ptr_mut(SSL_CTX_get_cert_store(ptr)) }
    }

    pub(crate) fn set_sigalgs_list(&mut self) -> Result<(), ErrorStack> {
        // Allowed signature algorithms:
        // ecdsa_secp256r1_sha256 (0x0403)
        // ecdsa_secp384r1_sha384 (0x0503)
        // ecdsa_secp521r1_sha512 (0x0603)
        // ed25519 (0x0807)
        // ed448 (0x0808)
        // rsa_pss_pss_sha256 (0x0809)
        // rsa_pss_pss_sha384 (0x080a)
        // rsa_pss_pss_sha512 (0x080b)
        // rsa_pss_rsae_sha256 (0x0804)
        // rsa_pss_rsae_sha384 (0x0805)
        // rsa_pss_rsae_sha512 (0x0806)
        // rsa_pkcs1_sha256 (0x0401)
        // rsa_pkcs1_sha384 (0x0501)
        // rsa_pkcs1_sha512 (0x0601)
        // SHA256 DSA (0x0402)
        // SHA384 DSA (0x0502)
        // SHA512 DSA (0x0602)
        const SUPPORT_SIGNATURE_ALGORITHMS: &str = "\
        ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:ed25519:\
        rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:\
        rsa_pss_rsae_sha512:rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512";
        let list = match CString::new(SUPPORT_SIGNATURE_ALGORITHMS) {
            Ok(cstr) => cstr,
            Err(_) => return Err(ErrorStack::get()),
        };

        let ptr = self.as_ptr_mut();
        #[cfg(feature = "__c_openssl")]
        return check_ret(unsafe {
            SSL_CTX_ctrl(
                ptr,
                SSL_CTRL_SET_SIGALGS_LIST,
                0,
                list.as_ptr() as *const c_void as *mut c_void,
            )
        } as c_int)
        .map(|_| ());
        #[cfg(feature = "c_boringssl")]
        return check_ret(unsafe {
            SSL_CTX_set1_sigalgs_list(ptr, list.as_ptr() as *const c_void as *mut c_void)
        } as c_int)
        .map(|_| ());
    }
}
