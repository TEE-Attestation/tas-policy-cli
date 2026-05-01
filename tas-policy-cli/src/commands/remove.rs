// TEE Attestation Service Policy CLI - Remove command (experimental)
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This module provides the remove command for decrementing (or deleting)
// policies via the experimental incrementable endpoint.

use crate::args::GlobalOpts;
use crate::commands::delete::DeleteArgs;
use crate::convert;
use crate::interactive;
use log::info;

pub fn execute(args: DeleteArgs, global: &GlobalOpts) -> anyhow::Result<()> {
    let client = convert::build_client(global)?;

    if !interactive::confirm(
        &format!("Remove policy '{}'? (decrements count or deletes if last)", args.policy_key),
        global.non_interactive,
    ) {
        println!("Aborted.");
        return Ok(());
    }

    let result = client.remove_policy(&args.policy_key)?;
    crate::output::maybe_show_deprecation(&result, global.verbose);
    info!("Policy '{}' removed.", args.policy_key);
    println!("{}", result.data.message);
    Ok(())
}
