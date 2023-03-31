// SPDX-FileCopyrightText: Copyright (C) 2023 Open Information Security Foundation
// SPDX-License-Identifier: MIT

use clap::Parser;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = ".")]
    sep: String,
    #[arg(long)]
    include: Vec<String>,
    filename: String,
}

fn main() {
    let args = Args::parse();

    let mut config = suricata_config::loader::load_file(&args.filename).unwrap();
    for include in &args.include {
        let include_config = suricata_config::loader::load_file(include).unwrap();
        suricata_config::merge(&mut config, &include_config);
    }

    suricata_config::dump(&config, &args.sep, false);
}
