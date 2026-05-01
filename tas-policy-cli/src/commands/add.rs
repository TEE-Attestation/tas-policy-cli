// TEE Attestation Service Policy CLI - Add command (experimental)
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This module provides the add command for submitting policies via the
// experimental incrementable endpoint.

use crate::args::{CreateArgs, CvmTypeArg, GlobalOpts};
use crate::convert;
use log::info;
use tas_policy_lib::{PolicySignature, SignedPolicyEnvelope, SigningKey, sign_envelope};
use zeroize::Zeroize;

/// Execute the `add` command.
pub fn execute(args: CreateArgs, global: &GlobalOpts) -> anyhow::Result<()> {
    match args.cvm_type {
        CvmTypeArg::TDX => execute_tdx(&args, global),
        CvmTypeArg::SEV => execute_sev(&args, global),
    }
}

fn read_passphrase(path: &Option<std::path::PathBuf>) -> anyhow::Result<Option<String>> {
    match path {
        Some(p) => {
            let mut raw = std::fs::read_to_string(p).map_err(|e| {
                anyhow::anyhow!("failed to read passphrase from {}: {}", p.display(), e)
            })?;
            let trimmed = raw.trim().to_string();
            raw.zeroize();
            Ok(Some(trimmed))
        }
        None => Ok(None),
    }
}

fn execute_tdx(args: &CreateArgs, global: &GlobalOpts) -> anyhow::Result<()> {
    info!("Adding TDX policy with config: {:?}", args);

    let config = convert::into_tdx_config(args);
    let policy = tas_policy_lib::TdxPolicy::from_config(config)?;

    let passphrase = read_passphrase(&args.signing_key_pass_file)?;
    let key = SigningKey::from_file(args.signing_key.as_path(), passphrase.as_deref())?;

    if args.dry_run {
        let mut envelope =
            SignedPolicyEnvelope::from_tdx(&policy, PolicySignature::placeholder());
        sign_envelope(&key, &mut envelope)?;
        println!("{}", serde_json::to_string_pretty(&envelope)?);
        return Ok(());
    }

    let client = convert::build_client(global)?;
    let result = client.add_policy(policy, &key)?;
    crate::output::maybe_show_deprecation(&result, global.verbose);
    if let Some(ref warning) = result.data.warning {
        eprintln!("{}", warning);
    }
    println!("{}", result.data.message);

    Ok(())
}

fn execute_sev(args: &CreateArgs, global: &GlobalOpts) -> anyhow::Result<()> {
    info!("Adding SEV policy with config: {:?}", args);

    let config = convert::into_sev_config(args)?;
    let policy = tas_policy_lib::SevPolicy::from_config(config)?;

    let passphrase = read_passphrase(&args.signing_key_pass_file)?;
    let key = SigningKey::from_file(args.signing_key.as_path(), passphrase.as_deref())?;

    if args.dry_run {
        let mut envelope =
            SignedPolicyEnvelope::from_sev(&policy, PolicySignature::placeholder());
        sign_envelope(&key, &mut envelope)?;
        println!("{}", serde_json::to_string_pretty(&envelope)?);
        return Ok(());
    }

    let client = convert::build_client(global)?;
    let result = client.add_policy(policy, &key)?;
    crate::output::maybe_show_deprecation(&result, global.verbose);
    if let Some(ref warning) = result.data.warning {
        eprintln!("{}", warning);
    }
    println!("{}", result.data.message);

    Ok(())
}
