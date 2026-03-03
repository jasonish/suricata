// SPDX-FileCopyrightText: Copyright 2023 Open Information Security Foundation
// SPDX-License-Identifier: GPL-2.0-only

// Allow these patterns as its a style we like.
#![allow(clippy::needless_return)]
#![allow(clippy::let_and_return)]
#![allow(clippy::uninlined_format_args)]

use clap::Parser;
use clap::Subcommand;
use std::ffi::OsStr;
use std::ffi::OsString;
use tracing::Level;

mod filestore;

#[derive(Parser, Debug)]
struct Cli {
    #[arg(long, short, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[arg(
        long,
        short,
        global = true,
        help = "Quiet mode, only warnings and errors will be logged"
    )]
    quiet: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Filestore management commands
    Filestore(FilestoreCommand),

    /// Suricata configuration commands
    Config,
}

#[derive(Parser, Debug)]
struct FilestoreCommand {
    #[command(subcommand)]
    command: FilestoreCommands,
}

#[derive(Subcommand, Debug)]
enum FilestoreCommands {
    /// Remove files by age
    Prune(FilestorePruneArgs),
}

#[derive(Parser, Debug)]
struct FilestorePruneArgs {
    #[arg(long, short = 'n', help = "only print what would happen")]
    dry_run: bool,
    #[arg(long, short, help = "file-store directory")]
    directory: String,
    #[arg(long, help = "prune files older than age, units: s, m, h, d")]
    age: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if dispatch_config_command_from_argv()? {
        return Ok(());
    }

    let cli = Cli::parse();

    let log_level = if cli.quiet {
        Level::WARN
    } else if cli.verbose > 0 {
        Level::DEBUG
    } else {
        Level::INFO
    };
    tracing_subscriber::fmt().with_max_level(log_level).init();

    match cli.command {
        Commands::Filestore(filestore) => match filestore.command {
            FilestoreCommands::Prune(args) => crate::filestore::prune::prune(args),
        },
        Commands::Config => unreachable!("config dispatch is handled before clap parsing"),
    }
}

fn dispatch_config_command_from_argv() -> Result<bool, Box<dyn std::error::Error>> {
    let args: Vec<OsString> = std::env::args_os().collect();
    if args.len() < 2 {
        return Ok(false);
    }

    let mut index = 1;
    while index < args.len() && is_global_passthrough_flag(args[index].as_os_str()) {
        index += 1;
    }

    let Some(command) = args.get(index) else {
        return Ok(false);
    };
    if command != OsStr::new("config") {
        return Ok(false);
    }

    let mut command_name = args[0].clone();
    command_name.push(" config");
    let forwarded = std::iter::once(command_name)
        .chain(args.into_iter().skip(index + 1))
        .collect::<Vec<_>>();
    suricata_config::cli::run_from_iter(forwarded)?;
    Ok(true)
}

fn is_global_passthrough_flag(arg: &OsStr) -> bool {
    if arg == OsStr::new("--verbose") || arg == OsStr::new("-q") || arg == OsStr::new("--quiet") {
        return true;
    }

    let value = arg.to_string_lossy();
    value.starts_with('-') && value.chars().skip(1).all(|ch| ch == 'v')
}
