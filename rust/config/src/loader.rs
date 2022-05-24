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

use crate::file::FileCharIterator;
use linked_hash_map::LinkedHashMap;
use std::collections::BTreeMap;
use std::fmt::Formatter;
use std::mem;
use std::path::Path;
use std::path::PathBuf;
use yaml_rust::parser::MarkedEventReceiver;
use yaml_rust::scanner::TScalarStyle;
use yaml_rust::scanner::TokenType;
use yaml_rust::Event;
use yaml_rust::ScanError;
use yaml_rust::Yaml;

pub type Hash = LinkedHashMap<Yaml, Yaml>;

#[derive(Debug)]
pub struct YamlScanError {
    pub filename: Option<String>,
    pub source: yaml_rust::ScanError,
}

#[derive(Debug)]
pub struct IoError {
    pub error: String,
    pub source: std::io::Error,
}

#[derive(Debug)]
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

// copied from yaml-rust
//
// parse f64 as Core schema
// See: https://github.com/chyh1990/yaml-rust/issues/51
fn parse_f64(v: &str) -> Option<f64> {
    match v {
        ".inf" | ".Inf" | ".INF" | "+.inf" | "+.Inf" | "+.INF" => Some(f64::INFINITY),
        "-.inf" | "-.Inf" | "-.INF" => Some(f64::NEG_INFINITY),
        ".nan" | "NaN" | ".NAN" => Some(f64::NAN),
        _ => v.parse::<f64>().ok(),
    }
}

/// Practically idential yaml yaml-rust::YamlLoader
struct SuricataYamlLoader {
    docs: Vec<Yaml>,
    doc_stack: Vec<(Yaml, usize)>,
    key_stack: Vec<Yaml>,
    anchor_map: BTreeMap<usize, Yaml>,

    // The current filename being parsed.
    filename: Option<PathBuf>,
}

impl SuricataYamlLoader {
    fn new() -> Self {
        Self {
            docs: Vec::new(),
            doc_stack: Vec::new(),
            key_stack: Vec::new(),
            anchor_map: BTreeMap::new(),
            filename: None,
        }
    }

    /// Set the filename that is being loaded. This is used for resolving the path to any includes.
    pub fn set_filename<P: AsRef<Path>>(&mut self, path: P) {
        let mut filename = PathBuf::new();
        filename.push(path.as_ref());
        self.filename = Some(filename);
    }

    /// Copied from yaml-rust.
    fn insert_new_node(&mut self, node: (Yaml, usize)) {
        // valid anchor id starts from 1
        if node.1 > 0 {
            self.anchor_map.insert(node.1, node.0.clone());
        }
        if self.doc_stack.is_empty() {
            self.doc_stack.push(node);
        } else {
            let parent = self.doc_stack.last_mut().unwrap();
            match *parent {
                (Yaml::Array(ref mut v), _) => v.push(node.0),
                (Yaml::Hash(ref mut h), _) => {
                    let cur_key = self.key_stack.last_mut().unwrap();
                    // current node is a key
                    if cur_key.is_badvalue() {
                        *cur_key = node.0;
                    // current node is a value
                    } else {
                        let mut newkey = Yaml::BadValue;
                        mem::swap(&mut newkey, cur_key);
                        h.insert(newkey, node.0);
                    }
                }
                _ => unreachable!(),
            }
        }
    }
}

impl MarkedEventReceiver for SuricataYamlLoader {
    fn on_event(&mut self, ev: yaml_rust::Event, _: yaml_rust::scanner::Marker) {
        match ev {
            Event::DocumentStart => {
                // do nothing
            }
            Event::DocumentEnd => {
                match self.doc_stack.len() {
                    // empty document
                    0 => self.docs.push(Yaml::BadValue),
                    1 => self.docs.push(self.doc_stack.pop().unwrap().0),
                    _ => unreachable!(),
                }
            }
            Event::SequenceStart(aid) => {
                self.doc_stack.push((Yaml::Array(Vec::new()), aid));
            }
            Event::SequenceEnd => {
                let node = self.doc_stack.pop().unwrap();
                self.insert_new_node(node);
            }
            Event::MappingStart(aid) => {
                self.doc_stack.push((Yaml::Hash(Hash::new()), aid));
                self.key_stack.push(Yaml::BadValue);
            }
            Event::MappingEnd => {
                self.key_stack.pop().unwrap();
                let node = self.doc_stack.pop().unwrap();
                self.insert_new_node(node);
            }
            Event::Scalar(v, style, aid, tag) => {
                let node = if style != TScalarStyle::Plain {
                    Yaml::String(v)
                } else if let Some(TokenType::Tag(ref handle, ref suffix)) = tag {
                    // XXX tag:yaml.org,2002:
                    if handle == "!!" {
                        match suffix.as_ref() {
                            "bool" => {
                                // "true" or "false"
                                match v.parse::<bool>() {
                                    Err(_) => Yaml::BadValue,
                                    Ok(v) => Yaml::Boolean(v),
                                }
                            }
                            "int" => match v.parse::<i64>() {
                                Err(_) => Yaml::BadValue,
                                Ok(v) => Yaml::Integer(v),
                            },
                            "float" => match parse_f64(&v) {
                                Some(_) => Yaml::Real(v),
                                None => Yaml::BadValue,
                            },
                            "null" => match v.as_ref() {
                                "~" | "null" => Yaml::Null,
                                _ => Yaml::BadValue,
                            },
                            _ => Yaml::String(v),
                        }
                    } else {
                        Yaml::String(v)
                    }
                } else {
                    // Datatype is not specified, or unrecognized
                    Yaml::from_str(&v)
                };

                self.insert_new_node((node, aid));
            }
            Event::Alias(id) => {
                let n = match self.anchor_map.get(&id) {
                    Some(v) => v.clone(),
                    None => Yaml::BadValue,
                };
                self.insert_new_node((n, 0));
            }
            _ => { /* ignore */ }
        }
    }
}

pub fn load_from_str(source: &str) -> Result<Vec<Yaml>, ScanError> {
    let mut loader = SuricataYamlLoader::new();
    let mut parser = yaml_rust::parser::Parser::new(source.chars());
    parser.load(&mut loader, true)?;
    Ok(loader.docs)
}

pub fn load_from_file<P: AsRef<Path>>(filename: P) -> Result<Vec<Yaml>, Error> {
    let file = std::fs::File::open(&filename).map_err(|err| {
        Error::IoError(IoError {
            error: format!("failed to open {}", filename.as_ref().display()),
            source: err,
        })
    })?;

    // Prevent attempts to read from a directory. This is the match the behaviour of the C code.
    if let Ok(metadata) = file.metadata() {
        if metadata.is_dir() {
            return Err(Error::NotAFile(filename.as_ref().display().to_string()));
        }
    }

    let mut loader = SuricataYamlLoader::new();
    loader.set_filename(&filename);
    let mut parser = yaml_rust::parser::Parser::new(FileCharIterator::new(file));
    parser.load(&mut loader, false).map_err(|err| {
        Error::YamlScanError(YamlScanError {
            filename: Some(filename.as_ref().to_str().unwrap().to_string()),
            source: err,
        })
    })?;
    Ok(loader.docs)
}
