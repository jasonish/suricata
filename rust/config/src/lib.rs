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
pub enum ConfValue {
    Null,
    Map(HashMap<String, ConfValue>),
    List(Vec<ConfValue>),
    String(StringNode),
    Boolean(bool),
}

impl ConfValue {
    /// Return this nodes type as a String.
    pub fn node_type(&self) -> String {
        match self {
            Self::Null => "null",
            Self::Map(_) => "map",
            Self::List(_) => "list",
            Self::String(_) => "string",
            Self::Boolean(_) => "boolean",
        }
        .to_string()
    }

    /// Find a child configuration node of this one based on the provided dotted name.
    pub fn get_node(&self, name: &str) -> Option<&ConfValue> {
        let parts: Vec<&str> = name.splitn(2, '.').collect();
        if parts.is_empty() {
            return None;
        }
        if let ConfValue::Map(map) = self {
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

    pub fn as_hashmap(&self) -> Option<&HashMap<String, ConfValue>> {
        match self {
            Self::Map(map) => Some(map),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&Vec<ConfValue>> {
        match self {
            Self::List(list) => Some(list),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(&s.value),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    /// Returns true if the Node is a map.
    pub fn is_map(&self) -> bool {
        self.as_hashmap().is_some()
    }

    /// Returns true if the Node is a list.
    pub fn is_list(&self) -> bool {
        self.as_list().is_some()
    }

    /// Returns true if the Node is a string.
    pub fn is_string(&self) -> bool {
        self.as_str().is_some()
    }

    pub fn is_bool(&self) -> bool {
        self.as_bool().is_some()
    }
}

impl std::ops::Index<&str> for ConfValue {
    type Output = ConfValue;

    fn index(&self, index: &str) -> &Self::Output {
        match self {
            Self::Map(map) => map.get(index).unwrap_or(&Self::Null),
            _ => &Self::Null,
        }
    }
}

pub fn load_from_str(source: &str) -> Result<ConfValue, loader::Error> {
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

pub fn load_from_file<P: AsRef<Path>>(filename: P) -> Result<ConfValue, loader::Error> {
    let file = std::fs::File::open(&filename).map_err(|err| {
        loader::Error::IoError(IoError {
            error: format!("failed to open {}", filename.as_ref().display()),
            source: err,
        })
    })?;

    // Prevent attempts to read from a directory. This is the match the behaviour of the C code.
    if let Ok(metadata) = file.metadata() {
        if metadata.is_dir() {
            return Err(loader::Error::NotAFile(
                filename.as_ref().display().to_string(),
            ));
        }
    }

    let mut loader = YamlLoader::new();
    loader.set_filename(&filename);
    let mut parser = Parser::new(FileCharIterator::new(file));
    parser.load(&mut loader, false).map_err(|err| {
        loader::Error::YamlScanError(YamlScanError {
            filename: Some(filename.as_ref().to_str().unwrap().to_string()),
            source: err,
        })
    })?;
    if let Some(err) = loader.error {
        Err(err)
    } else {
        Ok(loader.root)
    }
}

pub fn dump_node(node: &ConfValue, prefix: Vec<String>) {
    let path = prefix.join(".");
    match node {
        ConfValue::String(s) => {
            println!("{} = {}", path, s.value);
        }
        ConfValue::Boolean(b) => {
            println!("{} = {}", path, b);
        }
        ConfValue::Null => {
            println!("{} = (null)", path);
        }
        ConfValue::Map(m) => {
            for (k, v) in m {
                let mut prefix = prefix.clone();
                prefix.push(k.to_string());
                dump_node(v, prefix.clone());
            }
        }
        ConfValue::List(l) => {
            for (i, e) in l.iter().enumerate() {
                let mut prefix = prefix.clone();
                prefix.push(i.to_string());
                dump_node(e, prefix);
            }
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
        if let ConfValue::String(s) = x {
            assert_eq!(s.value, "value");
        } else {
            unreachable!();
        }

        let y = &config["nested"]["aaa"];
        assert!(y.is_string());
    }

    // ConfYamlSequenceTest
    #[test]
    fn test_list() {
        let doc = r#"
        rule-files:
          - netbios.rules
          - x11.rules
        default-log-dir: /tmp
        "#;
        let config = load_from_str(doc).unwrap();
        let node = config.get_node("rule-files").unwrap();
        assert!(matches!(node, ConfValue::List(_)));
        let list = node.as_list().unwrap();
        assert_eq!(list[0].as_str().unwrap(), "netbios.rules");
        assert_eq!(list[1].as_str().unwrap(), "x11.rules");
    }

    // ConfYamlLoggingOutputTest
    #[test]
    fn test_list_of_maps() {
        let doc = r#"
        logging:
          output:
            - interface: console
              log-level: error
            - interface: syslog
              facility: local4
              log-level: info
        "#;
        let config = load_from_str(doc).unwrap();
        let outputs = config.get_node("logging.output").unwrap();
        let outputs = outputs.as_list().unwrap();
        assert_eq!(outputs.len(), 2);
        let first = &outputs[0];
        assert!(first.is_map());
        let first = first.as_hashmap().unwrap();
        assert_eq!(first.get("interface").unwrap().as_str().unwrap(), "console");
        assert_eq!(first.get("log-level").unwrap().as_str().unwrap(), "error");
        let second = &outputs[1];
        assert!(second.is_map());
        let second = second.as_hashmap().unwrap();
        assert_eq!(second.get("interface").unwrap().as_str().unwrap(), "syslog");
        assert_eq!(second.get("log-level").unwrap().as_str().unwrap(), "info");
        assert_eq!(second.get("facility").unwrap().as_str().unwrap(), "local4");
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
        if let ConfValue::String(s) = sensor_name {
            assert_eq!(s.value, "suricata");
        } else {
            unreachable!();
        }
    }

    #[test]
    fn test_include_tag() {
        let config = load_from_file("test.yaml").unwrap();
        dump_node(&config, vec![]);
        let sensor_name = &config["nested-include"]["child"]["included-sensor-name"];
        assert!(sensor_name.is_string());
        if let ConfValue::String(s) = sensor_name {
            assert_eq!(s.value, "suricata");
        } else {
            unreachable!();
        }
    }
}
