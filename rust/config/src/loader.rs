// SPDX-FileCopyrightText: Copyright (C) 2024 Open Information Security Foundation
// SPDX-License-Identifier: MIT

use std::path::{Path, PathBuf};

use crate::load_from_file;
use saphyr::{Hash, Yaml};
use saphyr_parser::{Input, Parser, TScalarStyle, Tag};

fn parse_scalar(value: String, style: &TScalarStyle) -> Yaml {
    // Parse as integer.
    if let Ok(value) = value.parse::<i64>() {
        return Yaml::Integer(value);
    }

    // Parse as float.
    if value.parse::<f64>().is_ok() {
        return Yaml::Real(value);
    }

    match style {
        TScalarStyle::SingleQuoted | TScalarStyle::DoubleQuoted => {
            return Yaml::String(value);
        }
        _ => {}
    }

    if value == "~" || value.to_lowercase() == "null" {
        return Yaml::Null;
    }

    match value.as_ref() {
        "true" => Yaml::Boolean(true),
        "false" => Yaml::Boolean(false),
        _ => Yaml::String(value),
    }
}

fn is_include(tag: Option<Tag>) -> bool {
    if let Some(tag) = tag {
        if tag.handle == "!" && tag.suffix == "include" {
            return true;
        }
    }
    false
}

pub struct Loader {
    dir: PathBuf,
    stack: Vec<Yaml>,
}

impl Loader {
    pub fn new<P: AsRef<Path>>(dir: P) -> Self {
        Self {
            dir: dir.as_ref().to_path_buf(),
            stack: vec![],
        }
    }

    fn load_from_file(&self, filename: &str) -> Result<Yaml, Box<dyn std::error::Error>> {
        let path = self.dir.join(filename);
        crate::load_from_file(&path)
    }

    pub fn load_from_parser<I: Input>(
        mut self, mut parser: Parser<I>,
    ) -> Result<Yaml, Box<dyn std::error::Error>> {
        while let Some(next) = parser.next_event() {
            match next {
                Ok((ev, _span)) => {
                    match ev {
                        saphyr_parser::Event::Nothing => {}
                        saphyr_parser::Event::StreamStart => {}
                        saphyr_parser::Event::StreamEnd => {}
                        saphyr_parser::Event::DocumentStart(_) => {}
                        saphyr_parser::Event::DocumentEnd => {}
                        saphyr_parser::Event::Alias(_anchor_id) => {
                            return Err("aliases not supported".into());
                        }
                        saphyr_parser::Event::Scalar(value, style, _anchor_id, tag) => {
                            let mut parent = self.stack.pop().unwrap();
                            match parent {
                                Yaml::String(key) => {
                                    // Parent is a string, so must be a key.
                                    if is_include(tag) {
                                        let include = self.load_from_file(&value)?;
                                        let last = self.stack.last_mut();
                                        match last {
                                            Some(Yaml::Hash(map)) => {
                                                map.insert(Yaml::String(key), include);
                                            }
                                            _ => {
                                                return Err(format!(
                                                        "internal error: unexpected parent type at {}:{}: {:?}",
                                                        file!(), line!(), last
                                                    ).into());
                                            }
                                        }
                                    } else if key == "include" {
                                        let include = self.load_from_file(&value)?;
                                        if let Yaml::Hash(include) = include {
                                            let last = self.stack.last_mut();
                                            match last {
                                                Some(Yaml::Hash(map)) => {
                                                    for (key, val) in include {
                                                        map.insert(key, val);
                                                    }
                                                }
                                                _ => {
                                                    return Err(format!(
                                                            "internal error: unexpected parent type at {}:{}: {:?}",
                                                            file!(), line!(), last
                                                        ).into());
                                                }
                                            }
                                        } else {
                                            return Err(
                                                "\"include\" statements can only include mappings"
                                                    .to_string()
                                                    .into(),
                                            );
                                        }
                                    } else {
                                        let last = self.stack.last_mut();
                                        match last {
                                            Some(Yaml::Hash(map)) => {
                                                map.insert(
                                                    Yaml::String(key),
                                                    parse_scalar(value, &style),
                                                );
                                            }
                                            _ => {
                                                return Err(format!(
                                                "internal error: unexpected parent type at {}:{}: {:?}",
                                                file!(), line!(), last
                                            ).into());
                                            }
                                        }
                                    }
                                }
                                Yaml::Array(ref mut array) => {
                                    array.push(parse_scalar(value, &style));
                                    self.stack.push(parent);
                                }
                                _ => {
                                    self.stack.push(parent);
                                    self.stack.push(Yaml::String(value));
                                }
                            }
                        }
                        saphyr_parser::Event::SequenceStart(_anchor_id, _tag) => {
                            self.stack.push(Yaml::Array(vec![]));
                        }
                        saphyr_parser::Event::SequenceEnd => {
                            let array = self.stack.pop().unwrap().into_vec().unwrap();
                            let key = self.stack.pop().unwrap().into_string().unwrap();
                            let last = self.stack.last_mut();
                            match last {
                                Some(Yaml::Hash(map)) => {
                                    map.insert(Yaml::String(key), Yaml::Array(array));
                                }
                                _ => {
                                    return Err(format!(
                                        "internal error: unexpected parent type at {}:{}: {:?}",
                                        file!(),
                                        line!(),
                                        last
                                    )
                                    .into());
                                }
                            }
                        }
                        saphyr_parser::Event::MappingStart(_anchor_id, _tag) => {
                            self.stack.push(Yaml::Hash(Hash::new()));
                        }
                        saphyr_parser::Event::MappingEnd => {
                            if self.stack.len() == 1 {
                                // Return the first item on the stack.
                                return Ok(self.stack.pop().unwrap());
                            }

                            let map = self.stack.pop().unwrap().into_hash().unwrap();

                            let last = self.stack.last_mut().unwrap();
                            match last {
                                Yaml::String(_) => {
                                    let key = self.stack.pop().unwrap().into_string().unwrap();
                                    let last = self.stack.last_mut();
                                    match last {
                                        Some(Yaml::Hash(pmap)) => {
                                            pmap.insert(Yaml::String(key), Yaml::Hash(map));
                                        }
                                        _ => {
                                            return Err(format!(
                                                "internal error: unexpected parent type at {}:{}: {:?}",
                                                file!(),
                                                line!(),
                                                last
                                            )
                                                       .into());
                                        }
                                    }
                                }
                                Yaml::Array(array) => {
                                    array.push(Yaml::Hash(map));
                                }
                                _ => {
                                    return Err(format!(
                                        "internal error: unexpected parent type at {}:{}: {:?}",
                                        file!(),
                                        line!(),
                                        last
                                    )
                                    .into());
                                }
                            }
                        }
                    }
                }
                Err(err) => {
                    return Err(err.into());
                }
            }
        }
        Ok(Yaml::Hash(Hash::new()))
    }
}

/// Handle "include" lists.
///
/// Includes of the type "include: filename" are handling while
/// parsing of the YAML to allow for multiple includes being included
/// that way (with duplicate keys).
pub fn resolve_includes<P: AsRef<Path>>(
    config: &mut Yaml, dir: P,
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = dir.as_ref();
    let mut stack = vec![config];
    while let Some(node) = stack.pop() {
        if let Yaml::Hash(map) = node {
            if let Some(include) = map.remove(&Yaml::String("include".to_string())) {
                if let Yaml::Array(includes) = include {
                    for include in includes {
                        let path = dir.join(include.into_string().unwrap());
                        let config = load_from_file(&path)?;
                        // Includes must be maps.
                        let config = config.into_hash().unwrap();
                        for (key, value) in config {
                            map.insert(key, value);
                        }
                    }
                } else {
                    return Err("Found non-array include statement".to_string().into());
                }
            }
            for value in map.values_mut() {
                stack.push(value);
            }
        }
    }
    Ok(())
}

/// Unflatten "flat" keys in maps where a flat key is a key that
/// contains ".", for example:
///
/// ```yaml
///     foo:
///       bar: chocolate
///     foo.nut: almond
/// ```
///
/// will be unflattened as if it was written like:
///
/// ```yaml
///     foo:
///       bar: chocolate
///       nut: almond
/// ```
pub fn resolve_flat_keys(config: &mut Yaml) -> Result<(), Box<dyn std::error::Error>> {
    let mut stack = vec![config];
    while let Some(node) = stack.pop() {
        if let Yaml::Hash(map) = node {
            let mut keys: Vec<Yaml> = vec![];
            for (key, _) in map.iter() {
                if key.as_str().unwrap().contains('.') {
                    keys.push(key.clone());
                }
            }
            for key in keys {
                let skey = key.as_str().unwrap();
                if let Some(value) = map.remove(&key) {
                    let (root, rest) = skey.split_once('.').unwrap();

                    // parse rest as integer.
                    if let Ok(index) = rest.parse::<usize>() {
                        if let Some(Yaml::Array(array)) =
                            map.get_mut(&Yaml::String(root.to_string()))
                        {
                            if index < array.len() {
                                array[index] = value;
                            } else {
                                for _i in array.len()..index {
                                    array.push(Yaml::Null);
                                }
                                array.push(value);
                            }
                        } else {
                            return Err(format!(
                                "Array index found for existing non-array index: key={}",
                                key.as_str().unwrap()
                            )
                            .into());
                        }
                    } else if let Some(Yaml::Hash(child)) =
                        map.get_mut(&Yaml::String(root.to_string()))
                    {
                        child.insert(Yaml::String(rest.to_string()), value);
                    } else {
                        // Create the node. Its questionable whether
                        // we should allow creation of new maps
                        // especially if we have a rather complete
                        // default configuration.
                        let mut child = Hash::new();
                        child.insert(Yaml::String(rest.to_string()), value);
                        map.insert(Yaml::String(root.to_string()), Yaml::Hash(child));
                    }
                }
            }
            for value in map.values_mut() {
                stack.push(value);
            }
        }
    }
    Ok(())
}
