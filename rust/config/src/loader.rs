// SPDX-FileCopyrightText: Copyright (C) 2023 Open Information Security Foundation
// SPDX-License-Identifier: MIT

use super::Error;
use serde_yaml::Value;
use std::{collections::HashSet, fs::File, io::Cursor, path::Path};

pub fn load_file(filename: impl AsRef<std::path::Path>) -> Result<Value, Error> {
    load_from_reader(File::open(&filename)?, filename)
}

pub fn load_string(input: &str, filename: impl AsRef<std::path::Path>) -> Result<Value, Error> {
    load_from_reader(Cursor::new(input), filename)
}

pub fn load_from_reader(
    reader: impl std::io::Read, filename: impl AsRef<std::path::Path>,
) -> Result<Value, Error> {
    // First load the initial document using serde_yaml.
    let mut config = serde_yaml::from_reader(reader)?;

    loop {
        // Expand any flattened keys to sub-objects.
        apply_flattened(&mut config);

        // Now process any includes.
        if apply_includes(&mut config, &filename)? == 0 {
            break;
        }
    }

    Ok(config)
}

fn get_include_filenames(mapping: &serde_yaml::Mapping) -> Vec<String> {
    let mut filenames = vec![];
    for (key, value) in mapping {
        if let Value::String(key) = key {
            if key == "include" {
                match value {
                    Value::String(value) => {
                        filenames.push(value.clone());
                    }
                    Value::Sequence(values) => {
                        for value in values {
                            if let Value::String(value) = value {
                                filenames.push(value.clone());
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    filenames
}

/// Apply any includes in config.
///
/// The number of includes processed are returned and indicates that
/// the config will need further processing to unflatten any keys and
/// possibly re-scan for includes.
fn apply_includes(config: &mut Value, filename: impl AsRef<std::path::Path>) -> Result<i32, Error> {
    let mut count = 0;
    let mut stack = vec![(config, filename.as_ref().to_owned())];

    while let Some((config, filename)) = stack.pop() {
        if stack.len() > 255 {
            return Err(Error::MaxLevels);
        }

        let path = filename.parent().unwrap_or(Path::new(""));

        if let Value::Mapping(mapping) = config {
            let include_filenames = get_include_filenames(mapping);
            if !include_filenames.is_empty() {
                let mut include_mapping = serde_yaml::Mapping::new();
                for filename in &include_filenames {
                    let include_path = path.join(filename);
                    let include_value = load_file(&include_path)?;
                    for (key, val) in include_value.as_mapping().unwrap() {
                        include_mapping.insert(key.clone(), val.clone());
                    }
                }

                let keys: HashSet<&Value> = mapping
                    .keys()
                    .skip_while(|key| key != &&serde_yaml::Value::String("include".to_string()))
                    .skip(1)
                    .collect();
                for key in keys {
                    if include_mapping.contains_key(key) {
                        println!("Removing key {:?} from include.", key);
                        include_mapping.remove(key);
                    }
                }
                for (key, value) in include_mapping {
                    mapping.insert(key, value);
                }
                mapping.remove("include");
            }

            // Handle !include tags.
            for value in mapping.values_mut() {
                if let Value::Tagged(tagged) = value {
                    if tagged.tag == "!include" {
                        if let Value::String(include_filename) = &tagged.value {
                            *value = load_file(path.join(include_filename))?;
                            count += 1;
                        } else {
                            return Err(Error::BadInclude(format!(
                                "include must be a string: filename={}",
                                filename.display()
                            )));
                        }
                    }
                }
                stack.push((value, filename.clone()));
            }
        }
    }

    Ok(count)
}

fn apply_flattened(config: &mut Value) {
    let mut stack = vec![config];

    while let Some(node) = stack.pop() {
        if stack.len() > 255 {
            return;
        }

        if let Value::Mapping(mapping) = node {
            let mut keys: Vec<String> = vec![];
            for (key, _) in mapping.iter() {
                if let Value::String(key) = key {
                    if key.contains('.') {
                        keys.push(key.clone());
                    }
                }
            }
            for key in keys {
                if let Some(value) = mapping.remove(&key) {
                    let (root, rest) = key.split_once('.').unwrap();
                    if let Some(Value::Mapping(child)) = mapping.get_mut(root) {
                        child.insert(rest.into(), value);
                    } else {
                        let mut child = serde_yaml::Mapping::new();
                        child.insert(rest.into(), value);
                        mapping.insert(root.into(), Value::Mapping(child));
                    }
                }
            }
            for value in mapping.values_mut() {
                stack.push(value);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_load_file_simple() {
        let filename = if let Ok(d) = std::env::var("ABS_TOP_SRCDIR") {
            format!("{}/rust/config/tests/simple.yaml", d)
        } else {
            "./tests/simple.yaml".to_string()
        };
        let config = load_file(&filename).unwrap();
        assert_eq!(config["suricata-version"], "7.0");
        assert_eq!(config["parent"]["child"]["value"], "foobar");
    }

    #[test]
    fn test_load_file_that_doesnt_exist() {
        assert!(load_file("./tests/noexist.yaml").is_err());
    }

    #[test]
    fn test_load_file_with_includes() {
        let filename = if let Ok(d) = std::env::var("ABS_TOP_SRCDIR") {
            format!("{}/rust/config/tests/with-includes.yaml", d)
        } else {
            "./tests/with-includes.yaml".to_string()
        };
        let config = load_file(filename).unwrap();
        assert_eq!(config["one"], "one");
        assert_eq!(config["nested"]["one"], "one");
    }

    #[test]
    fn test_include_list() {
        let filename = if let Ok(d) = std::env::var("ABS_TOP_SRCDIR") {
            format!("{}/rust/config/tests/include-list.yaml", d)
        } else {
            "./tests/include-list.yaml".to_string()
        };
        let config = load_file(filename).unwrap();
        assert_eq!(config["one"], "one");
        assert_eq!(config["two"], "two");
    }

    #[test]
    fn test_include_tag() {
        let filename = if let Ok(d) = std::env::var("ABS_TOP_SRCDIR") {
            format!("{}/rust/config/tests/include-tag.yaml", d)
        } else {
            "./tests/include-tag.yaml".to_string()
        };
        let config = load_file(&filename).unwrap();
        assert_eq!(config["parent"]["one"], "one");
    }

    #[test]
    fn test_include_with_include() {
        let filename = if let Ok(d) = std::env::var("ABS_TOP_SRCDIR") {
            format!("{}/rust/config/tests/include-with-include.yaml", d)
        } else {
            "./tests/include-with-include.yaml".to_string()
        };
        let config = load_file(&filename).unwrap();
        assert_eq!(config["one"], "one");
    }

    #[test]
    fn test_include_from_string() {
        let prefix = if let Ok(d) = std::env::var("ABS_TOP_SRCDIR") {
            format!("{}/rust/config/dummy.yaml", d)
        } else {
            "".to_string()
        };
        let yaml = r#"include: tests/one.yaml"#;
        let config = load_string(yaml, &prefix).unwrap();
        assert_eq!(config["one"], "one");
    }

    #[test]
    fn test_apply_flattened() {
        let yaml = r#"
foo.bar: bar

nested:
  foo.bar: foobar

vars:
  address-groups:
    HOME_NET: "any"
    EXTERNAL_NET: "any"

vars.address-groups.HOME_NET: "10.10.10.10/32"
"#;
        let mut config: Value = serde_yaml::from_str(yaml).unwrap();
        apply_flattened(&mut config);
        assert_eq!(config["foo"]["bar"], "bar");
        assert_eq!(config["nested"]["foo"]["bar"], "foobar");
        assert_eq!(config["vars"]["address-groups"]["EXTERNAL_NET"], "any");
        assert_eq!(
            &config["vars"]["address-groups"]["HOME_NET"],
            &serde_yaml::Value::String("10.10.10.10/32".to_string())
        );
    }
}
