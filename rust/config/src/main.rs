// SPDX-FileCopyrightText: Copyright 2026 Open Information Security Foundation
// SPDX-License-Identifier: GPL-2.0-only

use std::path::PathBuf;

use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;

#[derive(Parser, Debug)]
#[command(about = "Utilities for Suricata configuration files")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Read and print a Suricata configuration file.
    Print(PrintArgs),

    /// Validate a Suricata configuration file against a JSON schema.
    Validate(ValidateArgs),

    /// Print the embedded Suricata YAML JSON schema.
    PrintSchema,
}

#[derive(Parser, Debug)]
struct PrintArgs {
    /// Path to the Suricata configuration file.
    path: PathBuf,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Yaml)]
    format: OutputFormat,
}

#[derive(Parser, Debug)]
struct ValidateArgs {
    /// Path to the Suricata configuration file.
    path: PathBuf,

    /// Path to a JSON schema file. If omitted, the embedded schema is used.
    #[arg(long)]
    schema: Option<PathBuf>,

    /// Quiet mode. Print nothing when validation succeeds.
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Yaml,
    Json,
    Debug,
    Flat,
}

// Parse CLI arguments and dispatch the selected subcommand.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Print(args) => print_config(args),
        Command::Validate(args) => validate_config(args),
        Command::PrintSchema => print_schema(),
    }
}

// Load a configuration file and print it in the requested format.
fn print_config(args: PrintArgs) -> Result<(), Box<dyn std::error::Error>> {
    let config = suricata_config::load_file(&args.path)?;

    match args.format {
        OutputFormat::Yaml => print!("{}", suricata_config::print_yaml(&config)?),
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&suricata_config::config_to_json(&config))?
            );
        }
        OutputFormat::Debug => println!("{config:#?}"),
        OutputFormat::Flat => print!("{}", suricata_config::print_flat_config(&config)),
    }

    Ok(())
}

// Print the embedded Suricata YAML JSON schema.
fn print_schema() -> Result<(), Box<dyn std::error::Error>> {
    print!("{}", suricata_config::SURICATA_YAML_SCHEMA);
    Ok(())
}

// Load a configuration file, validate it against a schema, and report all issues.
fn validate_config(args: ValidateArgs) -> Result<(), Box<dyn std::error::Error>> {
    let config = suricata_config::load_file(&args.path)?;
    let instance = suricata_config::config_to_json(&config);

    let (schema, schema_label) = if let Some(schema_path) = args.schema {
        let schema_input = std::fs::read_to_string(&schema_path)?;
        let schema: serde_json::Value = serde_json::from_str(&schema_input)?;
        (schema, schema_path.display().to_string())
    } else {
        (
            suricata_config::embedded_schema()?,
            String::from("embedded schema"),
        )
    };

    let errors = suricata_config::validate_json_schema(&instance, &schema);
    if errors.is_empty() {
        if !args.quiet {
            println!("OK: {}", args.path.display());
        }
        return Ok(());
    }

    eprintln!(
        "Validation failed: {} issue(s) in {} against {}",
        errors.len(),
        args.path.display(),
        schema_label
    );
    for error in errors {
        eprintln!("{}", error);
    }

    Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "schema validation failed").into())
}
