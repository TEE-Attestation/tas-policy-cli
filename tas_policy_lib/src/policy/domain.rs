// TEE Attestation Service Policy Library - Domain policy envelope
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This module defines the domain-policy registration payload for the certify
// flow. A domain-policy is a named object that references a list of
// certify-policy ids; the certify flow succeeds when the attestation satisfies
// at least one of them. It is stored separately from secret-release policies.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::signed::PolicySignature;

/// Metadata for a domain-policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainPolicyMetadata {
    /// Domain-policy id — supplied by the agent as `domain-policy` and used as
    /// the SPIFFE path segment in the issued certificate.
    pub policy_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Domain-policy registration payload for the TAS certify management API.
///
/// ```json
/// {
///   "metadata": { "policy_id": "prod", "description": "..." },
///   "certify_policies": {
///     "amd-sev-snp": ["sev-baseline"],
///     "intel-tdx": ["tdx-baseline"]
///   },
///   "signature": {...}
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainPolicyEnvelope {
    pub metadata: DomainPolicyMetadata,
    /// Certify-policy ids grouped by TEE type (e.g. `amd-sev-snp`,
    /// `intel-tdx`). At verification the attestation is evaluated only against
    /// the ids listed for its TEE type, and must satisfy at least one (OR).
    pub certify_policies: BTreeMap<String, Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<PolicySignature>,
}

impl DomainPolicyEnvelope {
    /// Build a new unsigned domain-policy envelope.
    pub fn new(
        policy_id: impl Into<String>,
        description: Option<String>,
        certify_policies: BTreeMap<String, Vec<String>>,
    ) -> Self {
        Self {
            metadata: DomainPolicyMetadata {
                policy_id: policy_id.into(),
                description,
            },
            certify_policies,
            signature: None,
        }
    }
}
