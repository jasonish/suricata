// SPDX-FileCopyrightText: Copyright 2026 Open Information Security Foundation
// SPDX-License-Identifier: GPL-2.0-only

fn main() -> Result<(), Box<dyn std::error::Error>> {
    suricata_config::cli::run_from_env()
}
