use crate::{load_from_file, Node, StringNode};
use std::collections::HashMap;
use std::fmt::Formatter;
use std::io::Read;
use yaml_rust::parser::MarkedEventReceiver;
use yaml_rust::scanner::{Marker, TokenType};
use yaml_rust::{Event, ScanError};

#[derive(Debug)]
pub struct IoError {
    pub filename: Option<String>,
    pub source: std::io::Error,
}

#[derive(Debug)]
pub struct YamlScanError {
    pub filename: Option<String>,
    pub source: yaml_rust::ScanError,
}

#[derive(Debug)]
pub enum Error {
    IoError(IoError),
    YamlScanError(YamlScanError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Self::YamlScanError(_) => {
                write!(f, "scan error")
            }
            Self::IoError(_) => {
                write!(f, "io error")
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
    stack: Vec<Node>,
    keys: Vec<String>,
    state: Option<State>,
    pub error: Option<Error>,
    pub root: Node,
}

impl YamlLoader {
    pub fn new() -> Self {
        Self {
            stack: Vec::new(),
            keys: vec!["".to_string()],
            state: None,
            root: Node::Null,
            error: None,
        }
    }

    fn is_include(&self, token: Option<TokenType>) -> bool {
        if let Some(TokenType::Tag(prefix, value)) = token {
            if prefix.starts_with('!') && value == "include" {
                return true;
            }
        }
        false
    }
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
            Event::Alias(_) => {}
            Event::MappingStart(_) => {
                self.stack.push(Node::Map(HashMap::new()));
                self.state = None;
            }
            Event::MappingEnd => {
                let node = self.stack.pop().unwrap();
                let parent = self.stack.last_mut();
                match parent {
                    Some(parent) => match parent {
                        Node::Map(parent) => {
                            let key = self.keys.pop().unwrap();
                            parent.insert(key, node);
                        }
                        Node::List(parent) => {
                            parent.push(node);
                        }
                        _ => {
                            unreachable!();
                        }
                    },
                    None => {
                        self.root = node;
                    }
                }
            }
            Event::SequenceStart(_) => {
                self.stack.push(Node::List(Vec::new()));
                self.state = None;
            }
            Event::SequenceEnd => {
                let node = self.stack.pop().unwrap();
                match self.stack.last_mut().unwrap() {
                    Node::Map(parent) => {
                        parent.insert(self.keys.pop().unwrap(), node);
                    }
                    _ => {
                        unreachable!();
                    }
                }
            }
            Event::Scalar(s, _style, _aid, token) => {
                let is_include = self.is_include(token);
                let parent = self.stack.last_mut().unwrap();
                match parent {
                    Node::Map(parent) => match self.state {
                        None => {
                            if s == "include" {
                                self.state = Some(State::Include);
                            } else {
                                self.keys.push(s);
                                self.state = Some(State::Value);
                            }
                        }
                        Some(State::Value) => {
                            if is_include {
                                match load_from_file(&s) {
                                    Err(err) => {
                                        self.error = Some(err);
                                    }
                                    Ok(node) => {
                                        parent.insert(self.keys.pop().unwrap(), node);
                                    }
                                }
                            } else {
                                parent
                                    .insert(self.keys.pop().unwrap(), Node::String(StringNode::new(s)));
                            }
                            self.state = None;
                        }
                        Some(State::Include) => {
                            match load_from_file(&s) {
                                Ok(node) => {
                                    match node {
                                        Node::Map(map) => {
                                            for (k, v) in map {
                                                parent.insert(k, v);
                                            }
                                        }
                                        _ => {
                                            panic!("includes must be a map");
                                        }
                                    }
                                }
                                Err(err) => {
                                    self.error = Some(err);
                                }
                            }
                            self.state = None;
                        }
                    },
                    Node::List(list) => {
                        list.push(Node::String(StringNode::new(s)));
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
