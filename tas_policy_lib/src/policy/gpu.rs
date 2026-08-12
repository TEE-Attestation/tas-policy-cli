// TEE Attestation Service Policy Library - GPU component policy
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// GPU component policy types.

use serde::{Deserialize, Serialize};

/// `components.gpu` — GPU component policies keyed by GPU device type.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GpuComponent {
    #[serde(rename = "gpu-nvidia", skip_serializing_if = "Option::is_none")]
    pub gpu_nvidia: Option<GpuPolicy>,
}

impl GpuComponent {
    /// GPU component containing the default NVIDIA policy section.
    pub fn nvidia_default() -> Self {
        Self {
            gpu_nvidia: Some(GpuPolicy::nvidia_default()),
        }
    }
}

/// A single GPU device-type policy (nvidia_pytools `authorization-rules` format).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuPolicy {
    pub version: String,
    #[serde(rename = "authorization-rules")]
    pub authorization_rules: AuthorizationRules,
}

impl GpuPolicy {
    pub fn nvidia_default() -> Self {
        Self {
            version: "4.0".to_string(),
            authorization_rules: AuthorizationRules::nvidia_default(),
        }
    }
}

/// The claim sets a verified GPU must satisfy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRules {
    #[serde(rename = "type")]
    pub rule_type: String,
    #[serde(rename = "overall-claims")]
    pub overall_claims: OverallClaims,
    #[serde(rename = "detached-claims")]
    pub detached_claims: DetachedClaims,
}

impl AuthorizationRules {
    pub fn nvidia_default() -> Self {
        Self {
            rule_type: "JWT".to_string(),
            overall_claims: OverallClaims::default(),
            detached_claims: DetachedClaims::default(),
        }
    }
}

/// Overall (token-level) claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverallClaims {
    #[serde(rename = "x-nvidia-overall-att-result")]
    pub overall_att_result: bool,
    #[serde(rename = "x-nvidia-ver")]
    pub ver: String,
}

impl Default for OverallClaims {
    fn default() -> Self {
        Self {
            overall_att_result: true,
            ver: "3.0".to_string(),
        }
    }
}

/// A certificate-chain claim (status + OCSP status).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertChainClaim {
    #[serde(rename = "x-nvidia-cert-status")]
    pub cert_status: String,
    #[serde(rename = "x-nvidia-cert-ocsp-status")]
    pub cert_ocsp_status: String,
}

impl Default for CertChainClaim {
    fn default() -> Self {
        Self {
            cert_status: "valid".to_string(),
            cert_ocsp_status: "good".to_string(),
        }
    }
}

/// Per-GPU (detached) claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetachedClaims {
    pub measres: String,
    pub dbgstat: String,
    pub secboot: bool,
    #[serde(rename = "x-nvidia-gpu-arch-check")]
    pub gpu_arch_check: bool,
    #[serde(rename = "x-nvidia-gpu-attestation-report-parsed")]
    pub attestation_report_parsed: bool,
    #[serde(rename = "x-nvidia-gpu-attestation-report-nonce-match")]
    pub attestation_report_nonce_match: bool,
    #[serde(rename = "x-nvidia-gpu-attestation-report-signature-verified")]
    pub attestation_report_signature_verified: bool,
    #[serde(rename = "x-nvidia-gpu-attestation-report-cert-chain")]
    pub attestation_report_cert_chain: CertChainClaim,
    #[serde(rename = "x-nvidia-gpu-attestation-report-cert-chain-fwid-match")]
    pub attestation_report_cert_chain_fwid_match: bool,
    #[serde(rename = "x-nvidia-gpu-driver-rim-fetched")]
    pub driver_rim_fetched: bool,
    #[serde(rename = "x-nvidia-gpu-driver-rim-schema-validated")]
    pub driver_rim_schema_validated: bool,
    #[serde(rename = "x-nvidia-gpu-driver-rim-signature-verified")]
    pub driver_rim_signature_verified: bool,
    #[serde(rename = "x-nvidia-gpu-driver-rim-version-match")]
    pub driver_rim_version_match: bool,
    #[serde(rename = "x-nvidia-gpu-driver-rim-cert-chain")]
    pub driver_rim_cert_chain: CertChainClaim,
    #[serde(rename = "x-nvidia-gpu-driver-rim-measurements-available")]
    pub driver_rim_measurements_available: bool,
    #[serde(rename = "x-nvidia-gpu-vbios-rim-fetched")]
    pub vbios_rim_fetched: bool,
    #[serde(rename = "x-nvidia-gpu-vbios-rim-schema-validated")]
    pub vbios_rim_schema_validated: bool,
    #[serde(rename = "x-nvidia-gpu-vbios-rim-signature-verified")]
    pub vbios_rim_signature_verified: bool,
    #[serde(rename = "x-nvidia-gpu-vbios-rim-version-match")]
    pub vbios_rim_version_match: bool,
    #[serde(rename = "x-nvidia-gpu-vbios-rim-cert-chain")]
    pub vbios_rim_cert_chain: CertChainClaim,
    #[serde(rename = "x-nvidia-gpu-vbios-rim-measurements-available")]
    pub vbios_rim_measurements_available: bool,
    #[serde(rename = "x-nvidia-gpu-vbios-index-no-conflict")]
    pub vbios_index_no_conflict: bool,
}

impl Default for DetachedClaims {
    fn default() -> Self {
        Self {
            measres: "success".to_string(),
            dbgstat: "disabled".to_string(),
            secboot: true,
            gpu_arch_check: true,
            attestation_report_parsed: true,
            attestation_report_nonce_match: true,
            attestation_report_signature_verified: true,
            attestation_report_cert_chain: CertChainClaim::default(),
            attestation_report_cert_chain_fwid_match: true,
            driver_rim_fetched: true,
            driver_rim_schema_validated: true,
            driver_rim_signature_verified: true,
            driver_rim_version_match: true,
            driver_rim_cert_chain: CertChainClaim::default(),
            driver_rim_measurements_available: true,
            vbios_rim_fetched: true,
            vbios_rim_schema_validated: true,
            vbios_rim_signature_verified: true,
            vbios_rim_version_match: true,
            vbios_rim_cert_chain: CertChainClaim::default(),
            vbios_rim_measurements_available: true,
            vbios_index_no_conflict: true,
        }
    }
}
