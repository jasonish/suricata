use crate::loader::{FileCharIterator, IoError, YamlLoader, YamlScanError};
use std::collections::HashMap;
use std::ffi::CString;
use std::path::Path;
use yaml_rust::parser::Parser;

pub mod ffi;
pub mod loader;

#[derive(Clone, Debug, PartialEq)]
pub struct StringNode {
    value: String,
    c_string: CString,
}

impl StringNode {
    pub fn new(s: String) -> Self {
        Self {
            c_string: CString::new(s.clone()).unwrap(),
            value: s,
        }
    }

    pub fn as_cptr(&self) -> *const std::os::raw::c_char {
        self.c_string.as_ptr()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Node {
    Null,
    Map(HashMap<String, Node>),
    List(Vec<Node>),
    String(StringNode),
}

impl Node {
    pub fn node_type(&self) -> String {
        match self {
            Self::Null => "null",
            Self::Map(_) => "map",
            Self::List(_) => "list",
            Self::String(_) => "string",
        }
        .to_string()
    }

    pub fn as_hashmap(&self) -> Option<&HashMap<String, Node>> {
        match self {
            Self::Map(map) => Some(map),
            _ => None,
        }
    }

    /// Returns true if the Node is a map.
    pub fn is_map(&self) -> bool {
        matches!(self, Self::Map(_))
    }

    /// Returns true if the Node is a list.
    pub fn is_list(&self) -> bool {
        matches!(self, Self::List(_))
    }

    /// Returns true if the Node is a string.
    pub fn is_string(&self) -> bool {
        matches!(self, Self::String(_))
    }

    /// Find a child configuration node of this one based on the provided dotted name.
    pub fn get_node(&self, name: &str) -> Option<&Node> {
        let parts: Vec<&str> = name.splitn(2, '.').collect();
        if parts.is_empty() {
            return None;
        }
        if let Node::Map(map) = self {
            if let Some(node) = map.get(parts[0]) {
                if parts.len() == 1 {
                    // No remaining names to look up, return this node.
                    return Some(node);
                }
                if node.is_map() {
                    return node.get_node(parts[1]);
                }
            }
        }
        None
    }
}

impl std::ops::Index<&str> for Node {
    type Output = Node;

    fn index(&self, index: &str) -> &Self::Output {
        match self {
            Self::Map(map) => map.get(index).unwrap_or(&Self::Null),
            _ => &Self::Null,
        }
    }
}

pub fn load_from_str(source: &str) -> Result<Node, loader::Error> {
    let mut loader = crate::loader::YamlLoader::new();
    let mut parser = Parser::new(source.chars());
    parser.load(&mut loader, false).map_err(|err| {
        loader::Error::YamlScanError(YamlScanError {
            filename: None,
            source: err,
        })
    })?;
    if let Some(err) = loader.error {
        Err(err)
    } else {
        Ok(loader.root)
    }
}

pub fn load_from_file<P: AsRef<Path>>(filename: P) -> Result<Node, loader::Error> {
    let file = std::fs::File::open(&filename).map_err(|err| {
        loader::Error::IoError(IoError {
            filename: Some(filename.as_ref().to_str().unwrap().to_string()),
            source: err,
        })})?;
    let mut loader = YamlLoader::new();
    let mut parser = Parser::new(FileCharIterator::new(file));
    parser.load(&mut loader, false).map_err(|err| {
        loader::Error::YamlScanError(YamlScanError {
            filename: Some(filename.as_ref().to_str().unwrap().to_string()),
            source: err,
        })})?;
    if let Some(err) = loader.error {
        Err(err)
    } else {
        Ok(loader.root)
    }

}

pub fn dump_node(node: &Node, prefix: Vec<String>) {
    match node {
        Node::String(s) => {
            let prefix = prefix.join(".");
            println!("{} = {}", prefix, s.value);
        }
        Node::Map(m) => {
            for (k, v) in m {
                let mut prefix = prefix.clone();
                prefix.push(k.to_string());
                dump_node(v, prefix.clone());
            }
        }
        Node::List(l) => {
            for (i, e) in l.iter().enumerate() {
                let mut prefix = prefix.clone();
                prefix.push(i.to_string());
                dump_node(e, prefix);
            }
        }
        _ => {
            panic!("dump not supported for {:?}", node);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::load_from_str;

    #[test]
    fn test_index() {
        let doc = r#"
        simple: value
        nested:
            aaa: bbb
        "#;
        let config = load_from_str(doc).unwrap();
        let x = &config["simple"];
        assert!(x.is_string());
        if let Node::String(s) = x {
            assert_eq!(s.value, "value");
        } else {
            unreachable!();
        }

        let y = &config["nested"]["aaa"];
        assert!(y.is_string());
    }

    #[test]
    fn test_conf_get_node() {
        let doc = r#"
        one:
            two:
                three: val
        "#;
        let config = load_from_str(doc).unwrap();

        let node = config.get_node("one.two.three");
        assert!(node.is_some());
        let node = node.unwrap();
        assert!(node.is_string());
    }

    #[test]
    fn test_include() {
        let config = load_from_file("test.yaml").unwrap();
        let sensor_name = &config["included-sensor-name"];
        assert!(sensor_name.is_string());
        if let Node::String(s) = sensor_name {
            assert_eq!(s.value, "suricata");
        } else {
            unreachable!();
        }
    }

    #[test]
    fn test_include_tag() {
        let config = load_from_file("test.yaml").unwrap();
        let sensor_name = &config["nested-include"]["child"]["included-sensor-name"];
        assert!(sensor_name.is_string());
        if let Node::String(s) = sensor_name {
            assert_eq!(s.value, "suricata");
        } else {
            unreachable!();
        }
    }
}
