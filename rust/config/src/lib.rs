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

mod file;
pub mod loader;

pub use crate::loader::LoaderError;
pub use yaml_rust::Yaml;

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
}
