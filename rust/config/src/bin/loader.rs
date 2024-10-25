// SPDX-FileCopyrightText: Copyright (C) 2024 Open Information Security Foundation
// SPDX-License-Identifier: MIT

use saphyr::Yaml;

fn main() {
    let filename = std::env::args().nth(1).expect("No filename given");
    let config = suricata_config::load_from_file(filename).unwrap();
    dump_yaml(&config, ".");
}

fn dump_yaml(value: &Yaml, sep: &str) {
    let mut stack: Vec<(Vec<String>, &Yaml)> = vec![(vec![], value)];
    while let Some((prefix, node)) = stack.pop() {
        match node {
            Yaml::Real(value) => {
                println!("{} = {}", prefix.join(sep), value);
            }
            Yaml::Integer(value) => {
                println!("{} = {}", prefix.join(sep), value);
            }
            Yaml::String(value) => {
                println!("{} = {}", prefix.join(sep), value);
            }
            Yaml::Boolean(value) => {
                println!("{} = {}", prefix.join(sep), value);
            }
            Yaml::Array(array) => {
                let mut tmp = vec![];
                for (i, v) in array.iter().enumerate() {
                    let mut prefix = prefix.clone();
                    prefix.push(format!("{}", i));
                    tmp.push((prefix, v));
                }
                tmp.reverse();
                stack.extend(tmp);
            }
            Yaml::Hash(hash) => {
                for (key, v) in hash.iter().rev() {
                    let mut prefix = prefix.clone();
                    prefix.push(key.as_str().unwrap().to_string());
                    stack.push((prefix, v));
                }
            }
            Yaml::Null => {
                println!("{} = ~", prefix.join(sep));
            }
            Yaml::Alias(_) => todo!(),
            Yaml::BadValue => todo!(),
        }
    }
}
