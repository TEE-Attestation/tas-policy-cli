// TEE Attestation Service Policy Library - Key Loader
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// RSA private key loading from PEM files (PKCS#8 or traditional PKCS#1).

use std::path::Path;

use pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// RSA signing key for policy signatures.
pub struct SigningKey {
    pub(crate) private_key: RsaPrivateKey,
}

impl SigningKey {
    /// Load an RSA private key from a PEM file.
    ///
    /// Supports both encrypted and unencrypted PKCS#8 PEM files,
    /// as well as traditional OpenSSL (PKCS#1) PEM files.
    ///
    /// The raw PEM data is zeroized after parsing so it does not
    /// linger in process memory.
    ///
    /// # Arguments
    /// * `path` - Path to the PEM-encoded private key file.
    /// * `password` - Optional passphrase for encrypted keys.
    pub fn from_file(path: impl AsRef<Path>, password: Option<&str>) -> Result<Self> {
        let mut pem_data =
            std::fs::read_to_string(path.as_ref()).map_err(|e| Error::KeyFileError {
                path: path.as_ref().display().to_string(),
                source: e,
            })?;

        let result = if let Some(pass) = password {
            // Try encrypted PKCS#8
            RsaPrivateKey::from_pkcs8_encrypted_pem(&pem_data, pass.as_bytes()).map_err(|e| {
                Error::SigningError(format!(
                    "failed to decrypt key from {}: {}",
                    path.as_ref().display(),
                    e
                ))
            })
        } else {
            // Try unencrypted PKCS#8, then fall back to PKCS#1
            RsaPrivateKey::from_pkcs8_pem(&pem_data)
                .or_else(|_| {
                    use rsa::pkcs1::DecodeRsaPrivateKey;
                    RsaPrivateKey::from_pkcs1_pem(&pem_data)
                })
                .map_err(|e| {
                    Error::SigningError(format!(
                        "failed to load key from {}: {}",
                        path.as_ref().display(),
                        e
                    ))
                })
        };

        // Zeroize the raw PEM regardless of success or failure
        pem_data.zeroize();

        Ok(Self {
            private_key: result?,
        })
    }
}
