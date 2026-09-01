// TEE Attestation Service Policy CLI - Certify command
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// This module implements the `certify` command tree, which manages the certify
// flow's domain-policies and certify-policies via their dedicated management
// endpoints. It is kept separate from the secret-release policy commands.

use std::collections::BTreeMap;
use std::path::PathBuf;

use clap::{Args, Subcommand};

use tas_policy_lib::client::ListFilter;
use tas_policy_lib::{CvmType, DomainPolicyEnvelope};

/// Wire values for the TEE-type groups in a domain-policy.
const TEE_SEV: &str = "amd-sev-snp";
const TEE_TDX: &str = "intel-tdx";

use crate::args::{CreateArgs, GlobalOpts};
use crate::commands::{create, signing};
use crate::convert;
use crate::interactive;
use crate::output;

/// `certify` — manage the certify flow's domain-policies and certify-policies.
#[derive(Args)]
pub struct CertifyArgs {
    #[command(subcommand)]
    command: CertifyCommand,
}

#[derive(Subcommand)]
enum CertifyCommand {
    /// Manage certify-policies (attestation policies referenced by domain-policies).
    #[command(subcommand)]
    Policy(PolicyCommand),
    /// Manage domain-policies (named collections of certify-policy ids).
    #[command(subcommand)]
    Domain(DomainCommand),
}

// =============================================================================
// certify-policy subcommands
// =============================================================================

#[derive(Subcommand)]
enum PolicyCommand {
    /// Create and upload a signed certify-policy.
    Create(Box<CreateArgs>),
    /// List certify-policies.
    List(PolicyListArgs),
    /// Get a certify-policy by id.
    Get(PolicyIdArgs),
    /// Delete a certify-policy by id.
    Delete(PolicyIdArgs),
}

/// Options for `certify policy list`.
#[derive(Args)]
pub struct PolicyListArgs {
    /// Filter by CVM type (TDX or SEV).
    #[arg(long)]
    pub filter_type: Option<String>,

    /// Filter by key-id prefix.
    #[arg(long)]
    pub key_id_prefix: Option<String>,
}

/// A single certify-policy id argument (used by get/delete).
#[derive(Args)]
pub struct PolicyIdArgs {
    /// Certify-policy id.
    #[arg(long)]
    pub policy_id: String,
}

// =============================================================================
// domain-policy subcommands
// =============================================================================

#[derive(Subcommand)]
enum DomainCommand {
    /// Create and upload a domain-policy.
    Create(DomainCreateArgs),
    /// List domain-policies.
    List,
    /// Get a domain-policy by id.
    Get(DomainPolicyIdArgs),
    /// Delete a domain-policy by id.
    Delete(DomainPolicyIdArgs),
}

/// Options for `certify domain create`.
#[derive(Args)]
pub struct DomainCreateArgs {
    /// Domain-policy id — the value agents request as `domain-policy`; used as
    /// the Redis key and SPIFFE path segment.
    #[arg(long = "policy-id")]
    pub policy_id: String,

    /// Human-readable description.
    #[arg(long)]
    pub description: Option<String>,

    /// A certify-policy id evaluated for AMD SEV-SNP evidence (repeatable).
    #[arg(long = "sev-policy-id")]
    pub sev_policy_ids: Vec<String>,

    /// A certify-policy id evaluated for Intel TDX evidence (repeatable).
    #[arg(long = "tdx-policy-id")]
    pub tdx_policy_ids: Vec<String>,

    /// Path to signing key (PEM format). Required unless --unsigned is specified.
    #[arg(
        long,
        required_unless_present = "unsigned",
        conflicts_with = "unsigned"
    )]
    pub signing_key: Option<PathBuf>,

    /// Path to file containing the signing key passphrase.
    #[arg(long, conflicts_with = "unsigned")]
    pub signing_key_pass_file: Option<PathBuf>,

    /// Create an unsigned domain-policy (no signature field).
    #[arg(long, conflicts_with = "signing_key")]
    pub unsigned: bool,

    /// Preview the signed domain-policy JSON without uploading.
    #[arg(long)]
    pub dry_run: bool,
}

/// A single domain-policy id argument (used by get/delete).
#[derive(Args)]
pub struct DomainPolicyIdArgs {
    /// Domain-policy id.
    #[arg(long = "policy-id")]
    pub policy_id: String,
}

// =============================================================================
// Dispatch
// =============================================================================

pub fn execute(args: CertifyArgs, global: &GlobalOpts) -> anyhow::Result<()> {
    match args.command {
        CertifyCommand::Policy(cmd) => match cmd {
            PolicyCommand::Create(a) => policy_create(*a, global),
            PolicyCommand::List(a) => policy_list(a, global),
            PolicyCommand::Get(a) => policy_get(a, global),
            PolicyCommand::Delete(a) => policy_delete(a, global),
        },
        CertifyCommand::Domain(cmd) => match cmd {
            DomainCommand::Create(a) => domain_create(a, global),
            DomainCommand::List => domain_list(global),
            DomainCommand::Get(a) => domain_get(a, global),
            DomainCommand::Delete(a) => domain_delete(a, global),
        },
    }
}

// =============================================================================
// certify-policy handlers
// =============================================================================

fn policy_create(args: CreateArgs, global: &GlobalOpts) -> anyhow::Result<()> {
    let (policy, components, signing_key) = create::prepare(&args)?;

    if args.dry_run {
        signing::dry_run(&policy, components, signing_key.as_ref())?;
        return Ok(());
    }

    let policy_id =
        signing::upload_certify_policy(policy, components, signing_key.as_ref(), global)?;
    println!("Certify-policy created: {}", policy_id);
    Ok(())
}

fn policy_list(args: PolicyListArgs, global: &GlobalOpts) -> anyhow::Result<()> {
    let client = convert::build_client(global)?;

    let cvm_type = args.filter_type.map(|s| s.parse::<CvmType>()).transpose()?;
    let filter = if cvm_type.is_some() || args.key_id_prefix.is_some() {
        Some(ListFilter {
            cvm_type,
            key_id_prefix: args.key_id_prefix,
        })
    } else {
        None
    };

    let resp = client.list_certify_policies(filter)?;
    output::maybe_show_deprecation(&resp, global.verbose);
    let summaries = resp.data;

    if summaries.is_empty() {
        println!("No certify-policies found.");
        return Ok(());
    }

    output::print_value(&summaries, &global.output_format);
    Ok(())
}

fn policy_get(args: PolicyIdArgs, global: &GlobalOpts) -> anyhow::Result<()> {
    let client = convert::build_client(global)?;
    let resp = client.get_certify_policy(&args.policy_id)?;
    output::maybe_show_deprecation(&resp, global.verbose);
    output::print_value(&resp.data, &global.output_format);
    Ok(())
}

fn policy_delete(args: PolicyIdArgs, global: &GlobalOpts) -> anyhow::Result<()> {
    let client = convert::build_client(global)?;

    if !interactive::confirm(
        &format!("Delete certify-policy '{}'?", args.policy_id),
        global.non_interactive,
    ) {
        println!("Aborted.");
        return Ok(());
    }

    let resp = client.delete_certify_policy(&args.policy_id)?;
    output::maybe_show_deprecation(&resp, global.verbose);
    println!("Certify-policy '{}' deleted successfully.", args.policy_id);
    Ok(())
}

// =============================================================================
// domain-policy handlers
// =============================================================================

fn domain_create(args: DomainCreateArgs, global: &GlobalOpts) -> anyhow::Result<()> {
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

    let mut certify_policies: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if !args.sev_policy_ids.is_empty() {
        certify_policies.insert(TEE_SEV.to_string(), args.sev_policy_ids);
    }
    if !args.tdx_policy_ids.is_empty() {
        certify_policies.insert(TEE_TDX.to_string(), args.tdx_policy_ids);
    }
    if certify_policies.is_empty() {
        anyhow::bail!("at least one --sev-policy-id or --tdx-policy-id is required");
    }

    let envelope = DomainPolicyEnvelope::new(args.policy_id, args.description, certify_policies);

    if args.dry_run {
        let mut preview = envelope;
        if let Some(key) = signing_key.as_ref() {
            tas_policy_lib::sign_domain_envelope(key, &mut preview)?;
        }
        println!("{}", serde_json::to_string_pretty(&preview)?);
        return Ok(());
    }

    let client = convert::build_client(global)?;
    let resp = client.create_domain_policy(envelope, signing_key.as_ref())?;
    output::maybe_show_deprecation(&resp, global.verbose);
    println!("Domain policy created: {}", resp.data.policy_id);
    Ok(())
}

fn domain_list(global: &GlobalOpts) -> anyhow::Result<()> {
    let client = convert::build_client(global)?;
    let resp = client.list_domain_policies()?;
    output::maybe_show_deprecation(&resp, global.verbose);
    let domains = resp.data;

    if domains.is_empty() {
        println!("No domain policies found.");
        return Ok(());
    }

    match global.output_format {
        output::OutputFormat::Json => output::print_value(&domains, &global.output_format),
        output::OutputFormat::Human => {
            println!(
                "{} domain polic{} found:\n",
                domains.len(),
                if domains.len() == 1 { "y" } else { "ies" }
            );
            for d in &domains {
                println!("  {}", d.policy_id);
                if let Some(ref desc) = d.description {
                    println!("    Desc:     {}", desc);
                }
                if d.certify_policies.is_empty() {
                    println!("    Policies: (none)");
                } else {
                    for (tee_type, ids) in &d.certify_policies {
                        println!("    {:>11}: {}", tee_type, ids.join(", "));
                    }
                }
                if d.signed {
                    println!("    Signed:   yes");
                }
                println!();
            }
        }
    }

    Ok(())
}

fn domain_get(args: DomainPolicyIdArgs, global: &GlobalOpts) -> anyhow::Result<()> {
    let client = convert::build_client(global)?;
    let resp = client.get_domain_policy(&args.policy_id)?;
    output::maybe_show_deprecation(&resp, global.verbose);
    output::print_value(&resp.data, &global.output_format);
    Ok(())
}

fn domain_delete(args: DomainPolicyIdArgs, global: &GlobalOpts) -> anyhow::Result<()> {
    let client = convert::build_client(global)?;

    if !interactive::confirm(
        &format!("Delete domain policy '{}'?", args.policy_id),
        global.non_interactive,
    ) {
        println!("Aborted.");
        return Ok(());
    }

    let resp = client.delete_domain_policy(&args.policy_id)?;
    output::maybe_show_deprecation(&resp, global.verbose);
    println!("Domain policy '{}' deleted successfully.", args.policy_id);
    Ok(())
}
