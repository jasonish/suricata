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

use crate::loader::parse_f64;
pub use crate::loader::LoaderError;
use lazy_static::lazy_static;
use libc::{int64_t, intmax_t};
use linked_hash_map::LinkedHashMap;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fmt::Formatter;
use std::hash::{Hash, Hasher};
use std::os::raw::{c_char, c_int};
use std::sync::Mutex;
use std::sync::RwLock;
pub use yaml_rust::Yaml;

lazy_static! {
    static ref DEFAULT: RwLock<ConfValue> = RwLock::new(ConfValue::Hash(LinkedHashMap::new()));
    static ref CSTRINGS: Mutex<HashMap<String, CString>> = Mutex::new(HashMap::new());
}

#[derive(Clone, PartialOrd, PartialEq, Debug, Eq, Ord, Hash)]
pub enum ConfValue {
    Real(String),
    Integer(i64),
    String(StringValue),
    Boolean(bool),
    Array(Vec<ConfValue>),
    Hash(LinkedHashMap<ConfValue, ConfValue>),
    Null,
    BadValue,
}

#[derive(Debug)]
pub struct StringValue {
    value: String,

    /// For FFI, we need to store the C variation of the string, do it here.
    cstring: Mutex<Option<CString>>,
}

impl std::fmt::Display for StringValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl Clone for StringValue {
    fn clone(&self) -> Self {
        Self {
            value: self.value.to_string(),
            cstring: Mutex::new(None),
        }
    }
}

impl PartialEq for StringValue {
    fn eq(&self, other: &Self) -> bool {
        self.value.eq(&other.value)
    }
}

impl Eq for StringValue {}

impl Ord for StringValue {
    fn cmp(&self, other: &Self) -> Ordering {
        self.value.cmp(&other.value)
    }
}

impl PartialOrd for StringValue {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.value.partial_cmp(&other.value)
    }
}

impl Hash for StringValue {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.value.hash(state)
    }
}

impl StringValue {
    fn new(s: String) -> Self {
        Self {
            value: s,
            cstring: Mutex::new(None),
        }
    }
}

impl ConfValue {
    // Copied from yaml_rust as we had to reimplement Yaml as ConfValue.
    fn from_str(v: &str) -> Self {
        if v.starts_with("0x") {
            if let Ok(i) = i64::from_str_radix(&v[2..], 16) {
                return ConfValue::Integer(i);
            }
        }
        if v.starts_with("0o") {
            if let Ok(i) = i64::from_str_radix(&v[2..], 8) {
                return ConfValue::Integer(i);
            }
        }
        if v.starts_with('+') {
            if let Ok(i) = v[1..].parse::<i64>() {
                return ConfValue::Integer(i);
            }
        }
        match v {
            "~" | "null" => ConfValue::Null,
            "true" => ConfValue::Boolean(true),
            "false" => ConfValue::Boolean(false),
            _ if v.parse::<i64>().is_ok() => ConfValue::Integer(v.parse::<i64>().unwrap()),
            // try parsing as f64
            _ if parse_f64(v).is_some() => ConfValue::Real(v.to_owned()),
            _ => ConfValue::String(StringValue::new(v.to_owned())),
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            ConfValue::String(s) => Some(&s.value),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            ConfValue::Integer(n) => Some(*n),
            _ => None,
        }
    }

    fn is_badvalue(&self) -> bool {
        *self == Self::BadValue
    }
}

pub fn get_node<'a>(node: &'a ConfValue, key: &str) -> Option<&'a ConfValue> {
    let parts: Vec<&str> = key.splitn(2, '.').collect();
    if parts.is_empty() {
        return None;
    }
    if let ConfValue::Hash(hash) = node {
        let key = ConfValue::String(StringValue::new(parts[0].to_string()));
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

#[allow(non_snake_case)]
pub unsafe extern "C" fn ConfGet(key: *mut c_char, vptr: *mut *mut c_char) -> c_int {
    let key = match CStr::from_ptr(key).to_str() {
        Ok(key) => key,
        Err(_) => return -1,
    };

    let root = DEFAULT.read().unwrap();
    let node = get_node(&*root, key).unwrap();
    if let ConfValue::String(s) = node {
        let mut xs = s.cstring.lock().unwrap();
        let ptr = match &*xs {
            Some(cstring) => cstring.as_ptr(),
            None => {
                match CString::new(s.value.clone()) {
                    Ok(cs) => {
                        *xs = Some(cs);
                    }
                    Err(_) => {
                        return -1;
                    }
                }
                xs.as_ref().unwrap().as_ptr()
            }
        };
        *vptr = ptr as *mut _;
        return 0;
    }
    -1
}

#[allow(non_snake_case)]
pub unsafe extern "C" fn ConfGetInt(key: *const c_char, vptr: *mut i64) -> c_int {
    let key = match CStr::from_ptr(key).to_str() {
        Ok(key) => key,
        Err(_) => return -1,
    };
    let root = DEFAULT.read().unwrap();
    let node = get_node(&*root, key).unwrap();
    dbg!(node);
    if let Some(n) = node.as_i64() {
        *vptr = n;
        0
    } else {
        -1
    }
}

pub fn set_default(node: ConfValue) {
    let mut default = DEFAULT.write().unwrap();
    *default = node;
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

        let mut config = loader::load_from_str(doc).unwrap().pop().unwrap();

        let node = get_node(&mut config, "simple").unwrap();
        assert_eq!(node.as_str().unwrap(), "value");

        let node = get_node(&mut config, "nested.aaa").unwrap();
        assert_eq!(node.as_str().unwrap(), "bbb");
    }

    #[test]
    fn test_ffi_conf_get() {
        let doc = r#"
        simple: value
        nested:
            aaa: bbb
        "#;
        let config = loader::load_from_str(doc).unwrap().pop().unwrap();
        set_default(config);
        let mut vptr: *mut c_char = std::ptr::null_mut();
        let key = CString::new("nested.aaa").unwrap();
        let rc = unsafe { ConfGet(key.as_ptr() as *mut _, &mut vptr) };
        assert_eq!(rc, 0);
        assert_ne!(vptr, std::ptr::null_mut());
    }

    #[test]
    fn test_ffi_conf_getint() {
        let doc = r#"
        simple: value
        nested:
            int: 999
        "#;
        let config = loader::load_from_str(doc).unwrap().pop().unwrap();
        set_default(config);
        let mut vptr: i64 = -1;
        let key = CString::new("nested.int").unwrap();
        let rc = unsafe { ConfGetInt(key.as_ptr() as *mut _, &mut vptr) };
        assert_eq!(rc, 0);
        assert_eq!(vptr, 999);
    }
}
