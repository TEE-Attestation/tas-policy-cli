// TEE Attestation Service Policy CLI - Create command
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This module provides the create command for creating new TAS policies.

use crate::args::{CreateArgs, CvmTypeArg, GlobalOpts};
use crate::commands::signing;
use crate::convert;
use log::info;
use tas_policy_lib::{Components, Policy, SigningKey};

/// Build the policy, component set, and signing key from `create`-style args.
///
/// Shared by the `create` command and the certify-policy create flow, which
/// accept identical policy-building options.
pub fn prepare(
    args: &CreateArgs,
) -> anyhow::Result<(Policy, Option<Components>, Option<SigningKey>)> {
    let policy: Policy = match args.cvm_type {
        CvmTypeArg::Tdx => {
            info!("Creating TDX policy with config: {:?}", args);
            let config = convert::into_tdx_config(args);
            tas_policy_lib::TdxPolicy::from_config(config)?.into()
        }
        CvmTypeArg::Sev => {
            info!("Creating SEV policy with config: {:?}", args);
            let config = convert::into_sev_config(args)?;
            tas_policy_lib::SevPolicy::from_config(config)?.into()
        }
    };

    let signing_key = if args.unsigned {
        None
    } else {
        let path = args
            .signing_key
            .as_ref()
            .expect("signing_key required when not unsigned");
        Some(signing::load_signing_key(
            path,
            &args.signing_key_pass_file,
        )?)
    };

    let components = convert::into_components(&args.component);

    Ok((policy, components, signing_key))
}

/// Execute the `create` command.
pub fn execute(args: CreateArgs, global: &GlobalOpts) -> anyhow::Result<()> {
    // key_id is optional on CreateArgs so certify-policies can omit it, but
    // secret-release policies still require it.
    if args.key_id.as_deref().unwrap_or_default().is_empty() {
        anyhow::bail!("--key-id is required");
    }

    let (policy, components, signing_key) = prepare(&args)?;

    if args.dry_run {
        signing::dry_run(&policy, components, signing_key.as_ref())?;
        return Ok(());
    }

    let policy_id = signing::upload(policy, components, signing_key.as_ref(), global)?;
    println!("Policy created: {}", policy_id);
    Ok(())
}
