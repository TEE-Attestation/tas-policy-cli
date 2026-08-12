// TEE Attestation Service Policy Library - Components section
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// The optional top-level `components` section attaches per-component
// attestation policies (GPU today; NIC/DPU/etc. in future) to a CPU policy.

use serde::{Deserialize, Serialize};

use super::gpu::GpuComponent;

/// Optional top-level `components` section of a policy.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Components {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu: Option<GpuComponent>,
}

impl Components {
    /// True when no component sub-policies are present.
    pub fn is_empty(&self) -> bool {
        self.gpu.is_none()
    }

    /// Add component entries from `other` that are absent here; never overwrites existing ones.
    pub fn fill_missing_from(&mut self, other: &Components) {
        if let Some(other_gpu) = &other.gpu {
            let gpu = self.gpu.get_or_insert_with(GpuComponent::default);
            if gpu.gpu_nvidia.is_none() {
                gpu.gpu_nvidia = other_gpu.gpu_nvidia.clone();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Components;
    use crate::policy::gpu::GpuComponent;

    #[test]
    fn fill_missing_adds_when_absent() {
        let mut existing = Components::default();
        existing.fill_missing_from(&Components {
            gpu: Some(GpuComponent::nvidia_default()),
        });
        assert!(existing.gpu.and_then(|g| g.gpu_nvidia).is_some());
    }

    #[test]
    fn fill_missing_preserves_existing() {
        let mut existing = Components {
            gpu: Some(GpuComponent::nvidia_default()),
        };
        if let Some(p) = existing.gpu.as_mut().and_then(|g| g.gpu_nvidia.as_mut()) {
            p.version = "custom".to_string();
        }
        existing.fill_missing_from(&Components {
            gpu: Some(GpuComponent::nvidia_default()),
        });
        assert_eq!(existing.gpu.unwrap().gpu_nvidia.unwrap().version, "custom");
    }
}
