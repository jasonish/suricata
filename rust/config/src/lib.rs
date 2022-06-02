// Copyright (C) 2022 Open Information Security Foundation
//
// You can copy, redistribute or modify this Program under the terms of
// the GNU General Public License version 2 as published by the Free
// Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// version 2 along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
// 02110-1301, USA.

mod ffi;
mod file;
pub mod loader;

pub use crate::loader::LoaderError;
use lazy_static::lazy_static;
use linked_hash_map::LinkedHashMap;
use std::sync::RwLock;
pub use yaml_rust::Yaml;

lazy_static! {
    static ref GLOBAL: RwLock<Yaml> = RwLock::new(Yaml::Hash(LinkedHashMap::new()));
}

pub trait SuricataYaml {
    fn set_int(&mut self, key: &str, value: i64) -> bool;
    fn set_from_str(&mut self, key: &str, value: &str) -> bool;

    /// The legacy Yaml handling in Suricata treated strings with certain values as truthy
    /// for boolean values, such as "yes", or "on", or "1". This method gives an interface
    /// that is compatible with that logic.
    fn is_true(&self) -> bool;
}

impl SuricataYaml for Yaml {
    fn is_true(&self) -> bool {
        match self {
            Yaml::Boolean(v) => *v,
            Yaml::String(v) => matches!(v.to_lowercase().as_str(), "1" | "yes" | "true" | "on"),
            Yaml::Integer(v) => *v != 0,
            _ => false,
        }
    }

    fn set_int(&mut self, key: &str, value: i64) -> bool {
        let parts: Vec<&str> = key.splitn(2, '.').collect();
        let key = Yaml::from_str(parts[0]);
        match self {
            Yaml::Hash(hash) => {
                if parts.len() == 1 {
                    match hash.get(&key) {
                        None | Some(Yaml::Integer(_)) => {
                            hash.insert(key, Yaml::Integer(value));
                            true
                        }
                        _ => false,
                    }
                } else {
                    let entry = hash
                        .entry(key)
                        .or_insert_with(|| Yaml::Hash(LinkedHashMap::new()));
                    entry.set_int(parts[1], value)
                }
            }
            _ => false,
        }
    }

    fn set_from_str(&mut self, key: &str, value: &str) -> bool {
        let parts: Vec<&str> = key.splitn(2, '.').collect();
        let key = Yaml::from_str(parts[0]);
        match self {
            Yaml::Hash(hash) => {
                if parts.len() == 1 {
                    match hash.get(&key) {
                        None | Some(Yaml::Integer(_)) => {
                            hash.insert(key, Yaml::from_str(value));
                            true
                        }
                        _ => false,
                    }
                } else {
                    let entry = hash
                        .entry(key)
                        .or_insert_with(|| Yaml::Hash(LinkedHashMap::new()));
                    entry.set_from_str(parts[1], value)
                }
            }
            _ => false,
        }
    }
}

pub fn get_node<'a>(node: &'a Yaml, key: &str) -> Option<&'a Yaml> {
    let parts: Vec<&str> = key.splitn(2, '.').collect();
    if parts.is_empty() {
        return None;
    }
    if let Yaml::Hash(hash) = node {
        let key = Yaml::from_str(parts[0]);
        if let Some(node) = hash.get(&key) {
            if parts.len() == 1 {
                return Some(node);
            } else {
                return get_node(node, parts[1]);
            }
        }
    }
    None
}

pub fn set_default(yaml: Yaml) {
    let mut default = GLOBAL.write().unwrap();
    *default = yaml;
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_get_node() {
        let doc = r#"
        simple: value
        nested:
            aaa: bbb
        "#;

        let config = loader::load_from_str(doc).unwrap().pop().unwrap();

        let node = get_node(&config, "simple").unwrap();
        assert_eq!(node.as_str().unwrap(), "value");

        let node = get_node(&config, "nested.aaa").unwrap();
        assert_eq!(node.as_str().unwrap(), "bbb");
    }

    #[test]
    fn test_set_int() {
        let mut config = Yaml::Hash(LinkedHashMap::new());
        config.set_int("foo", 1);
        assert_eq!(config["foo"], Yaml::Integer(1));

        config.set_int("foo", 2);
        assert_eq!(config["foo"], Yaml::Integer(2));

        config.set_int("bar.foo", 3);
        assert_eq!(config["bar"]["foo"], Yaml::Integer(3));

        config.set_int("bar.far", 4);
        assert_eq!(config["bar"]["far"], Yaml::Integer(4));

        // This will fail as bar is a hash, so we can't set it to a value of a different
        // type.
        assert_eq!(config.set_int("bar", 5), false);
    }
}
