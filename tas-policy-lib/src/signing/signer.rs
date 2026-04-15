// TEE Attestation Service Policy Library - Policy Signer
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// RSA-SHA384-PSS signing that matches the TAS demo_signer.py implementation.
// See: https://github.com/TEE-Attestation/tas/blob/main/docs/POLICY.md
//
// Signing process (matching TAS server verification):
// 1. Extract `validation_rules` from the policy
// 2. Recursively sort all dict keys
// 3. Serialize to compact JSON (no spaces, sorted keys)
// 4. Sign with RSA-PSS (SHA-384 hash, MGF1-SHA384, max salt length)
// 5. Base64-encode the signature

use rsa::pss::{BlindedSigningKey, Signature as PssSignature};
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use sha2::Sha384;

use super::key_loader::SigningKey;
use crate::error::{Error, Result};
use crate::policy::signed::{PolicySignature, SignedPolicyEnvelope, ValidationRules};

/// RSA-SHA384-PSS signature bytes.
#[derive(Debug, Clone)]
pub struct Signature {
    pub bytes: Vec<u8>,
}

impl Signature {
    /// Encode signature as base64 (standard encoding with padding).
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&self.bytes)
    }
}

/// Canonicalize a serde_json::Value by recursively sorting object keys.
///
/// This matches TAS's `sort_dict_recursively()` in policy_helper.py.
fn canonicalize(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            // Collect keys, sort them, then recursively canonicalize values
            let mut sorted: Vec<(String, serde_json::Value)> = map
                .iter()
                .map(|(k, v)| (k.clone(), canonicalize(v)))
                .collect();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(canonicalize).collect())
        }
        other => other.clone(),
    }
}

/// Produce the canonical JSON bytes of validation_rules for signing.
///
/// Matches the TAS signing process:
/// 1. Serialize validation_rules to a serde_json::Value
/// 2. Recursively sort all object keys
/// 3. Serialize to compact JSON (no whitespace, sorted keys)
fn canonical_validation_rules_bytes(rules: &ValidationRules) -> Result<Vec<u8>> {
    let value = serde_json::to_value(rules).map_err(|e| Error::Serialization(e.to_string()))?;
    let sorted = canonicalize(&value);
    let compact =
        serde_json::to_string(&sorted).map_err(|e| Error::Serialization(e.to_string()))?;
    Ok(compact.into_bytes())
}

/// Sign validation rules with an RSA private key using SHA384-PSS.
///
/// This produces a signature compatible with TAS server verification.
/// The signed data is the compact JSON of the canonicalized validation_rules.
pub fn sign_validation_rules(key: &SigningKey, rules: &ValidationRules) -> Result<Signature> {
    let data = canonical_validation_rules_bytes(rules)?;
    let signing_key = BlindedSigningKey::<Sha384>::new(key.private_key.clone());
    let mut rng = rsa::rand_core::OsRng;
    let pss_sig: PssSignature = signing_key.sign_with_rng(&mut rng, &data);

    Ok(Signature {
        bytes: pss_sig.to_vec(),
    })
}

/// Sign a policy envelope in place — fills in the real signature.
///
/// This is the main entry point for signing a complete policy.
/// It extracts the validation_rules, canonicalizes and signs them,
/// then replaces the placeholder signature with the real one.
pub fn sign_envelope(key: &SigningKey, envelope: &mut SignedPolicyEnvelope) -> Result<()> {
    let sig = sign_validation_rules(key, &envelope.policy.validation_rules)?;

    envelope.policy.signature = PolicySignature {
        algorithm: "SHA384".to_string(),
        padding: "PSS".to_string(),
        value: sig.to_base64(),
        signed_data: Some("validation_rules".to_string()),
    };

    Ok(())
}
