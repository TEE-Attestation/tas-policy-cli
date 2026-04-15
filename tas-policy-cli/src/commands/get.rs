// TEE Attestation Service Policy CLI - Get command
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This module provides the get command for retrieving a TAS policy.

use crate::args::GlobalOpts;
use crate::convert;
use crate::output;
use clap::Args;
use log::info;

/// Arguments for the `get` command.
#[derive(Args)]
pub struct GetArgs {
    /// Full policy key (e.g. policy:TDX:my-key).
    #[arg(long)]
    pub policy_key: String,
}

pub fn execute(args: GetArgs, global: &GlobalOpts) -> anyhow::Result<()> {
    info!("Executing get command for policy key: {}", args.policy_key);
    let client = convert::build_client(global)?;
    let resp = client.get_policy(&args.policy_key)?;
    output::maybe_show_deprecation(&resp, global.verbose);
    output::print_value(&resp.data, &global.output_format);
    Ok(())
}
