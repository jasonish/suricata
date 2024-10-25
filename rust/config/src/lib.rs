// SPDX-FileCopyrightText: Copyright (C) 2024 Open Information Security Foundation
// SPDX-License-Identifier: MIT

use std::{fs::File, path::Path};

use saphyr::Yaml;
use saphyr_parser::Parser;

use file::FileCharIterator;

mod ffi;
mod file;
mod loader;

pub fn display(yaml: &Yaml) -> Option<String> {
    match yaml {
        Yaml::Real(v) | Yaml::String(v) => Some(v.to_string()),
        Yaml::Integer(i) => Some(i.to_string()),
        Yaml::Boolean(b) => Some(b.to_string()),
        Yaml::Array(_) => None,
        Yaml::Hash(_) => None,
        Yaml::Alias(_) => None,
        Yaml::Null => Some("null".to_string()),
        Yaml::BadValue => None,
    }
}

pub fn get<'a>(yaml: &'a Yaml, key: &str) -> Option<&'a Yaml> {
    let parts: Vec<&str> = key.splitn(2, '.').collect();
    if parts.is_empty() {
        return None;
    }
    if let Yaml::Hash(hash) = yaml {
        let key = Yaml::String(parts[0].to_string());
        if let Some(node) = hash.get(&key) {
            if parts.len() == 1 {
                return Some(node);
            } else {
                return get(node, parts[1]);
            }
        }
    }
    None
}

pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Yaml, Box<dyn std::error::Error>> {
    let path = path.as_ref();
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let file = File::open(path)
        .map_err(|err| format!("Failed to open file {}: {:?}", path.display(), err))?;
    let iter = FileCharIterator::new(file);
    load_from_iter(iter, dir)
}

pub fn load_from_str<P: AsRef<Path>>(
    source: &str, dir: P,
) -> Result<Yaml, Box<dyn std::error::Error>> {
    let chars = source.chars();
    load_from_iter(chars, dir)
}

pub fn load_from_str0<P: AsRef<Path>>(
    source: &str, dir: P,
) -> Result<Yaml, Box<dyn std::error::Error>> {
    let chars = source.chars();
    load_from_iter0(chars, dir)
}

fn load_from_iter<I: Iterator<Item = char>, P: AsRef<Path>>(
    source: I, dir: P,
) -> Result<Yaml, Box<dyn std::error::Error>> {
    let input = saphyr_parser::BufferedInput::new(source);
    let parser = Parser::new(input);
    let loader = crate::loader::Loader::new(&dir);
    let mut value = loader.load_from_parser(parser)?;
    crate::loader::resolve_flat_keys(&mut value)?;
    crate::loader::resolve_includes(&mut value, &dir)?;
    Ok(value)
}

/// Does not resolved includes or flattened keys.
fn load_from_iter0<I: Iterator<Item = char>, P: AsRef<Path>>(
    source: I, dir: P,
) -> Result<Yaml, Box<dyn std::error::Error>> {
    let input = saphyr_parser::BufferedInput::new(source);
    let parser = Parser::new(input);
    let loader = crate::loader::Loader::new(&dir);
    let value = loader.load_from_parser(parser)?;
    Ok(value)
}

/// Merge source into target.
///
/// This is a very simple merge, only top level keys from source are
/// merged into target, overwriting the existing key in target.
pub fn merge(target: &mut Yaml, source: &Yaml) {
    if let Yaml::Hash(target) = target {
        if let Yaml::Hash(source) = source {
            for (key, val) in source {
                target.insert(key.clone(), val.clone());
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Test NULL handling.
    #[test]
    fn test_null() {
        let input = r#"
quoted-tilde: "~"     # Not NULL
unquoted-tilde: ~     # NULL
quoted-null: "null"   # Not NULL
unquoted-null: null   # NULL
quoted-Null: "Null"   # Not NULL
unquoted-Null: Null   # Null
quoted-NULL: "NULL"   # Not NULL
unquoted-NULL: NULL   # NULL
empty-quoted: ""      # Not NULL
empty-unquoted:       # NULL

list: ["null", null, "Null", Null, "NULL", NULL, "~", ~]
"#;
        let config = load_from_str(input, ".").unwrap();
        assert!(&config["quoted-tilde"].is_string());
        assert!(&config["unquoted-tilde"].is_null());
        assert!(&config["quoted-null"].is_string());
        assert!(&config["unquoted-null"].is_null());
        assert!(&config["quoted-Null"].is_string());
        assert!(&config["unquoted-Null"].is_null());
        assert!(&config["quoted-NULL"].is_string());
        assert!(&config["unquoted-NULL"].is_null());
        assert!(&config["empty-quoted"].is_string());
        assert!(&config["empty-unquoted"].is_null());

        let array = &config["list"];
        assert!(array[0].is_string());
        assert!(array[1].is_null());
        assert!(array[2].is_string());
        assert!(array[3].is_null());
        assert!(array[4].is_string());
        assert!(array[5].is_null());
        assert!(array[6].is_string());
        assert!(array[7].is_null());
    }

    #[test]
    fn test_overrides() {
        let input = r#"
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/23]"
vars.address-groups.HOME_NET: "10.10.10.10/32"
"#;
        let config = load_from_str(input, ".").unwrap();
        let home_net = &config["vars"]["address-groups"]["HOME_NET"];
        assert!(home_net.is_string());
        assert_eq!(home_net.as_str().unwrap(), "10.10.10.10/32");
    }

    #[test]
    fn test_include() {
        let config = load_from_file("./tests/include.yaml").unwrap();
        assert_eq!(config["one"], Yaml::from_str("foobar"));
        assert_eq!(config["two"], Yaml::from_str("foobar"));
    }

    #[test]
    fn test_include_list() {
        let config = load_from_file("./tests/include-list.yaml").unwrap();
        assert_eq!(config["one"], Yaml::from_str("foobar"));
        assert_eq!(config["two"], Yaml::from_str("foobar"));
    }

    #[test]
    fn test_include_tag() {
        let config = load_from_file("./tests/include-tag.yaml").unwrap();
        assert_eq!(config["one"]["two"]["foo"]["bar"], Yaml::from_str("foo"));
    }

    #[test]
    fn test_merge_no_override() {
        let config_a = "foo: bar";
        let config_b = "bar: foo";

        let mut config = load_from_str(config_a, ".").unwrap();
        let config_b = load_from_str(config_b, ".").unwrap();
        merge(&mut config, &config_b);

        assert_eq!(config["foo"], Yaml::from_str("bar"));
        assert_eq!(config["bar"], Yaml::from_str("foo"));
    }

    #[test]
    fn test_merge() {
        let config = r#"
var:
  HOME_NET: "127.0.0.1/32"
  EXTERNAL_NET: any
"#;

        // Should override "var" completely.
        let config_b = r#"
var:
  HOME_NET: any
  EXTERNAL_NET: none
"#;

        let mut config = load_from_str(config, ".").unwrap();
        let config_b = load_from_str(config_b, ".").unwrap();
        merge(&mut config, &config_b);
        assert_eq!(config["var"]["HOME_NET"], Yaml::from_str("any"));
        assert_eq!(config["var"]["EXTERNAL_NET"], Yaml::from_str("none"));
    }

    #[test]
    fn test_merge_override() {
        let config = r#"
var:
  HOME_NET: "127.0.0.1/32"
  EXTERNAL_NET: any
"#;

        // Should override "var" completely.
        let config_b = r#"
var.HOME_NET: none
"#;

        let mut config = load_from_str(config, ".").unwrap();
        let config_b = load_from_str0(config_b, ".").unwrap();
        merge(&mut config, &config_b);
        loader::resolve_flat_keys(&mut config).unwrap();
        assert_eq!(config["var"]["HOME_NET"], Yaml::from_str("none"));
        assert_eq!(config["var"]["EXTERNAL_NET"], Yaml::from_str("any"));
    }
}
