use crate::{load_from_file, ConfValue, StringNode};
use std::collections::HashMap;
use std::fmt::Formatter;
use std::io::Read;
use std::path::{Path, PathBuf};
use yaml_rust::parser::MarkedEventReceiver;
use yaml_rust::scanner::{Marker, TScalarStyle, TokenType};
use yaml_rust::Event;

#[derive(Debug)]
pub struct IoError {
    pub error: String,
    pub source: std::io::Error,
}

#[derive(Debug)]
pub struct YamlScanError {
    pub filename: Option<String>,
    pub source: yaml_rust::ScanError,
}

#[derive(Debug)]
#[repr(C)]
pub enum Error {
    IoError(IoError),
    YamlScanError(YamlScanError),

    /// The provided filename was not a file.
    NotAFile(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Self::YamlScanError(_) => {
                write!(f, "scan error")
            }
            Self::IoError(err) => {
                write!(f, "{}: {}", err.error, err.source)
            }
            Self::NotAFile(filename) => {
                write!(f, "{} is not a file but a directory", filename)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum State {
    Value,
    Include,
}

#[derive(Debug)]
pub struct YamlLoader {
    stack: Vec<(ConfValue, usize)>,
    keys: Vec<String>,
    state: Option<State>,
    pub filename: Option<PathBuf>,
    pub error: Option<Error>,
    pub root: ConfValue,
    anchors: HashMap<usize, ConfValue>,
    debug: bool,
}

impl YamlLoader {
    pub fn new() -> Self {
        Self {
            stack: Vec::new(),
            keys: vec!["".to_string()],
            state: None,
            root: ConfValue::Null,
            error: None,
            filename: None,
            anchors: HashMap::new(),
            debug: false,
        }
    }

    /// Set the filename that is being loaded. This is used for resolving the path to any includes.
    pub fn set_filename<P: AsRef<Path>>(&mut self, path: P) {
        let mut filename = PathBuf::new();
        filename.push(path.as_ref().clone());
        self.filename = Some(filename);
    }
}

fn is_include(token: &Option<TokenType>) -> bool {
    if let Some(TokenType::Tag(prefix, value)) = token {
        if prefix.starts_with('!') && value == "include" {
            return true;
        }
    }
    false
}

fn resolve_include_filename(parent: &Option<PathBuf>, include_filename: &str) -> PathBuf {
    let mut filename = if let Some(filename) = parent {
        filename.parent().unwrap().to_path_buf()
    } else {
        PathBuf::new()
    };
    filename.push(include_filename);
    filename
}

impl MarkedEventReceiver for YamlLoader {
    fn on_event(&mut self, ev: Event, _marker: Marker) {
        // If an error has occurred, do nothing.
        if self.error.is_some() {
            return;
        }
        match ev {
            Event::Nothing => {}
            Event::StreamStart => {}
            Event::StreamEnd => {}
            Event::DocumentStart => {}
            Event::DocumentEnd => {}
            Event::Alias(alias) => {
                // Find anchor.
                let mut anchor = None;
                for (aid, value) in &self.anchors {
                    if alias == *aid {
                        anchor = Some(value);
                    }
                }
                if anchor.is_none() {
                    panic!("anchor not found");
                }
                let anchor = anchor.unwrap();
                if self.debug {
                    println!("Event::Alias: Found anchor ID {}: {:?}", alias, anchor);
                }
                match self.state {
                    Some(State::Value) => {
                        let (parent, _) = self.stack.last_mut().unwrap();
                        match parent {
                            ConfValue::Map(map) => {
                                let key = self.keys.pop().unwrap();
                                map.insert(key, anchor.clone());
                            }
                            _ => {
                                unreachable!()
                            }
                        }
                        self.state = None;
                    }
                    _ => {
                        panic!("alias not expected")
                    }
                }
            }
            Event::MappingStart(aid) => {
                self.stack.push((ConfValue::Map(HashMap::new()), aid));
                self.state = None;
            }
            Event::MappingEnd => {
                let (node, aid) = self.stack.pop().unwrap();
                if self.stack.is_empty() {
                    self.root = node;
                } else {
                    let (parent, _) = self.stack.last_mut().unwrap();
                    if aid != 0 {
                        self.anchors.insert(aid, node.clone());
                    }
                    match parent {
                        ConfValue::Map(parent) => {
                            let key = self.keys.pop().unwrap();
                            parent.insert(key, node);
                        }
                        ConfValue::List(parent) => {
                            parent.push(node);
                        }
                        _ => {
                            unreachable!();
                        }
                    }
                }
            }
            Event::SequenceStart(aid) => {
                self.stack.push((ConfValue::List(Vec::new()), aid));
                self.state = None;
            }
            Event::SequenceEnd => {
                let (node, _) = self.stack.pop().unwrap();
                let (parent, _) = self.stack.last_mut().unwrap();
                match parent {
                    ConfValue::Map(parent) => {
                        parent.insert(self.keys.pop().unwrap(), node);
                    }
                    _ => {
                        unreachable!();
                    }
                }
            }
            Event::Scalar(s, style, aid, token) => {
                let (parent, _) = self.stack.last_mut().unwrap();
                match parent {
                    ConfValue::Map(parent) => match self.state {
                        None => {
                            if s == "include" {
                                self.state = Some(State::Include);
                            } else {
                                self.keys.push(s);
                                self.state = Some(State::Value);
                            }
                        }
                        Some(State::Value) => {
                            if is_include(&token) {
                                let filename = resolve_include_filename(&self.filename, &s);
                                match load_from_file(&filename) {
                                    Err(err) => {
                                        self.error = Some(err);
                                    }
                                    Ok(node) => {
                                        parent.insert(self.keys.pop().unwrap(), node);
                                    }
                                }
                            } else {
                                let val = match s.as_ref() {
                                    "true" | "TRUE" | "yes" | "YES" => ConfValue::Boolean(true),
                                    "false" | "FALSE" | "no" | "NO" => ConfValue::Boolean(false),
                                    "~" if matches!(style, TScalarStyle::Plain) => ConfValue::Null,
                                    _ => ConfValue::String(StringNode::new(s)),
                                };
                                if aid != 0 {
                                    self.anchors.insert(aid, val.clone());
                                }
                                parent.insert(self.keys.pop().unwrap(), val);
                            }
                            self.state = None;
                        }
                        Some(State::Include) => {
                            let filename = resolve_include_filename(&self.filename, &s);
                            match load_from_file(&filename) {
                                Ok(node) => match node {
                                    ConfValue::Map(map) => {
                                        for (k, v) in map {
                                            parent.insert(k, v);
                                        }
                                    }
                                    _ => {
                                        panic!("includes must be a map");
                                    }
                                },
                                Err(err) => {
                                    self.error = Some(err);
                                }
                            }
                            self.state = None;
                        }
                    },
                    ConfValue::List(list) => {
                        list.push(ConfValue::String(StringNode::new(s)));
                    }
                    _ => {
                        unreachable!();
                    }
                }
            }
        }
    }
}

/// A janky character iterator of a file to satisfy the YAML parser that only takes a char
/// iterator. We could read the whole file into a string, but that could cause issues with
/// very large files that may be passed by accident.
pub struct FileCharIterator {
    file: std::fs::File,
}

impl FileCharIterator {
    pub fn new(file: std::fs::File) -> Self {
        Self { file }
    }

    fn next_char(&mut self) -> Option<char> {
        let mut buf: Vec<u8> = Vec::new();
        loop {
            let mut byte = [0; 1];
            match self.file.read(&mut byte) {
                Ok(n) => {
                    if n == 0 {
                        return None;
                    }
                }
                Err(_) => {
                    return None;
                }
            }
            buf.push(byte[0]);
            match String::from_utf8(buf) {
                Ok(s) => {
                    assert_eq!(s.len(), 1);
                    return s.chars().next();
                }
                Err(err) => {
                    buf = err.as_bytes().to_vec();
                    continue;
                }
            }
        }
    }
}

impl Iterator for FileCharIterator {
    type Item = char;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_char()
    }
}
