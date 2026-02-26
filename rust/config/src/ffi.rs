// SPDX-FileCopyrightText: Copyright 2026 Open Information Security Foundation
// SPDX-License-Identifier: GPL-2.0-only

//! FFI interface to allow the Suricata C code to build the Conf tree
//! from the Rust YAML data structures, allowing us to move to Rust
//! parsing with minimal impact on the Conf API as we
//! transition.

use std::cell::RefCell;
use std::ffi::{c_char, CStr, CString};
use std::path::Path;
use std::ptr;

use saphyr::ScalarOwned;
use saphyr::YamlOwned;

use crate::Config;

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

pub struct SCConfig {
    root: SCConfigNode,
}

pub struct SCConfigNode {
    name: CString,
    value: Option<CString>,
    is_sequence: bool,
    children: Vec<SCConfigNode>,
}

impl SCConfigNode {
    fn new(name: String, value: Option<String>, is_sequence: bool) -> Result<Self, String> {
        let name = cstring_from_string(name, "node name")?;
        let value = match value {
            Some(value) => Some(cstring_from_string(value, "node value")?),
            None => None,
        };

        Ok(Self {
            name,
            value,
            is_sequence,
            children: Vec::new(),
        })
    }

    fn set_value(&mut self, value: String, context: &str) -> Result<(), String> {
        self.value = Some(cstring_from_string(value, context)?);
        Ok(())
    }
}

fn cstring_from_string(value: String, context: &str) -> Result<CString, String> {
    CString::new(value).map_err(|_| format!("{context} contains an interior NUL byte"))
}

fn set_last_error(error: String) {
    let mut sanitized = error.replace('\0', "\\0");
    if sanitized.is_empty() {
        sanitized = "unknown error".into();
    }

    let c_error =
        CString::new(sanitized).unwrap_or_else(|_| CString::new("unknown error").unwrap());
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = Some(c_error);
    });
}

fn clear_last_error() {
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = None;
    });
}

#[cfg(not(feature = "debug-validate"))]
fn untagged_node(mut node: YamlOwned) -> YamlOwned {
    loop {
        match node {
            YamlOwned::Tagged(_, inner) => node = *inner,
            _ => return node,
        }
    }
}

#[cfg(feature = "debug-validate")]
fn untagged_node(node: YamlOwned) -> YamlOwned {
    if matches!(node, YamlOwned::Tagged(_, _)) {
        panic!("tagged YAML values should be removed before FFI conversion");
    }
    node
}

fn yaml_scalar_to_option_string(node: YamlOwned) -> Option<String> {
    match untagged_node(node) {
        YamlOwned::Value(ScalarOwned::Null) => None,
        YamlOwned::Value(ScalarOwned::String(value)) => Some(value),
        YamlOwned::Value(ScalarOwned::Integer(value)) => Some(value.to_string()),
        YamlOwned::Value(ScalarOwned::FloatingPoint(value)) => Some(value.to_string()),
        YamlOwned::Value(ScalarOwned::Boolean(value)) => Some(value.to_string()),
        YamlOwned::Representation(value, _, _) => Some(value),
        YamlOwned::Alias(anchor) => Some(format!("*{anchor}")),
        YamlOwned::BadValue => None,
        YamlOwned::Mapping(_) | YamlOwned::Sequence(_) => None,
        YamlOwned::Tagged(_, _) => unreachable!(),
    }
}

fn yaml_key_to_string(node: YamlOwned) -> Result<String, String> {
    match untagged_node(node) {
        YamlOwned::Value(ScalarOwned::String(value)) => Ok(value),
        YamlOwned::Value(ScalarOwned::Integer(value)) => Ok(value.to_string()),
        YamlOwned::Value(ScalarOwned::FloatingPoint(value)) => Ok(value.to_string()),
        YamlOwned::Value(ScalarOwned::Boolean(value)) => Ok(value.to_string()),
        YamlOwned::Value(ScalarOwned::Null) => Ok("null".into()),
        YamlOwned::Representation(value, _, _) => Ok(value),
        YamlOwned::Alias(anchor) => Ok(format!("*{anchor}")),
        YamlOwned::BadValue => Err("invalid yaml mapping key".into()),
        YamlOwned::Mapping(_) | YamlOwned::Sequence(_) => {
            Err("yaml mapping keys must be scalar values".into())
        }
        YamlOwned::Tagged(_, _) => unreachable!(),
    }
}

fn build_mapping_child(name: String, node: YamlOwned) -> Result<SCConfigNode, String> {
    match untagged_node(node) {
        YamlOwned::Mapping(mapping) => {
            let mut child = SCConfigNode::new(name, None, false)?;
            for (key, value) in mapping {
                let key_name = yaml_key_to_string(key)?;
                child.children.push(build_mapping_child(key_name, value)?);
            }
            Ok(child)
        }
        YamlOwned::Sequence(sequence) => {
            let mut child = SCConfigNode::new(name, None, true)?;
            for (index, value) in sequence.into_iter().enumerate() {
                child.children.push(build_sequence_child(index, value)?);
            }
            Ok(child)
        }
        YamlOwned::Tagged(_, _) => unreachable!(),
        scalar => SCConfigNode::new(name, yaml_scalar_to_option_string(scalar), false),
    }
}

fn build_sequence_child(index: usize, node: YamlOwned) -> Result<SCConfigNode, String> {
    let name = index.to_string();

    match untagged_node(node) {
        YamlOwned::Mapping(mapping) => {
            let mut child = SCConfigNode::new(name, None, true)?;

            for (entry_index, (key, value)) in mapping.into_iter().enumerate() {
                let key_name = yaml_key_to_string(key)?;
                if entry_index == 0 {
                    child.set_value(key_name.clone(), "sequence entry key")?;
                }
                child.children.push(build_mapping_child(key_name, value)?);
            }

            Ok(child)
        }
        YamlOwned::Sequence(sequence) => {
            let mut child = SCConfigNode::new(name, None, true)?;
            for (nested_index, value) in sequence.into_iter().enumerate() {
                child
                    .children
                    .push(build_sequence_child(nested_index, value)?);
            }
            Ok(child)
        }
        YamlOwned::Tagged(_, _) => unreachable!(),
        scalar => SCConfigNode::new(name, yaml_scalar_to_option_string(scalar), false),
    }
}

fn build_config_tree(config: Config) -> Result<SCConfig, String> {
    let mut root = SCConfigNode::new(String::new(), None, false)?;

    match untagged_node(config) {
        YamlOwned::Mapping(mapping) => {
            for (key, value) in mapping {
                let key_name = yaml_key_to_string(key)?;
                root.children.push(build_mapping_child(key_name, value)?);
            }
        }
        YamlOwned::Sequence(sequence) => {
            root.is_sequence = true;
            for (index, value) in sequence.into_iter().enumerate() {
                root.children.push(build_sequence_child(index, value)?);
            }
        }
        YamlOwned::Tagged(_, _) => unreachable!(),
        scalar => {
            root.value = match yaml_scalar_to_option_string(scalar) {
                Some(value) => Some(cstring_from_string(value, "root node value")?),
                None => None,
            };
        }
    }

    Ok(SCConfig { root })
}

fn load_file_as_tree(path: &str) -> Result<SCConfig, String> {
    let config = crate::load_file(Path::new(path)).map_err(|err| err.to_string())?;
    build_config_tree(config)
}

fn load_string_as_tree(input: &[u8]) -> Result<SCConfig, String> {
    let input =
        std::str::from_utf8(input).map_err(|err| format!("config is not valid utf-8: {err}"))?;
    let config = crate::load_string(input).map_err(|err| err.to_string())?;
    build_config_tree(config)
}

/// Load a YAML file into an FFI-safe config tree.
///
/// # Safety
/// - `path` must point to a valid, NUL-terminated C string.
/// - `path` must remain valid for the duration of this call.
/// - The bytes referenced by `path` must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn SCConfigLoadFile(path: *const c_char) -> *mut SCConfig {
    if path.is_null() {
        set_last_error("config path must not be NULL".into());
        return ptr::null_mut();
    }

    let path = match CStr::from_ptr(path).to_str() {
        Ok(path) => path,
        Err(err) => {
            set_last_error(format!("config path is not valid utf-8: {err}"));
            return ptr::null_mut();
        }
    };

    match load_file_as_tree(path) {
        Ok(config) => {
            clear_last_error();
            Box::into_raw(Box::new(config))
        }
        Err(err) => {
            set_last_error(err);
            ptr::null_mut()
        }
    }
}

/// Load YAML bytes into an FFI-safe config tree.
///
/// # Safety
/// - When `len > 0`, `input` must be non-NULL and point to at least `len` readable bytes.
/// - `input` must remain valid for the duration of this call.
/// - The buffer contents must be valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn SCConfigLoadString(input: *const u8, len: usize) -> *mut SCConfig {
    let bytes = if len == 0 {
        &[][..]
    } else {
        if input.is_null() {
            set_last_error("config buffer must not be NULL when len is non-zero".into());
            return ptr::null_mut();
        }
        std::slice::from_raw_parts(input, len)
    };

    match load_string_as_tree(bytes) {
        Ok(config) => {
            clear_last_error();
            Box::into_raw(Box::new(config))
        }
        Err(err) => {
            set_last_error(err);
            ptr::null_mut()
        }
    }
}

/// Free a config tree previously returned by SCConfigLoadFile/SCConfigLoadString.
///
/// # Safety
/// - `config` must be either NULL or a pointer returned by
///   SCConfigLoadFile/SCConfigLoadString.
/// - `config` must not be freed more than once.
/// - No pointers derived from `config` may be used after this call.
#[no_mangle]
pub unsafe extern "C" fn SCConfigFree(config: *mut SCConfig) {
    if config.is_null() {
        return;
    }

    drop(Box::from_raw(config));
}

/// Return the last config loader error for the current thread, or NULL if none.
#[no_mangle]
pub extern "C" fn SCConfigGetLastError() -> *const c_char {
    LAST_ERROR.with(|slot| {
        if let Some(error) = slot.borrow().as_ref() {
            error.as_ptr()
        } else {
            ptr::null()
        }
    })
}

/// Get the root node for a loaded config tree.
///
/// # Safety
/// - `config` must be either NULL or a valid pointer returned by this module's
///   config-loading APIs.
/// - The returned pointer is borrowed and is valid only while `config` remains alive.
#[no_mangle]
pub unsafe extern "C" fn SCConfigGetRoot(config: *const SCConfig) -> *const SCConfigNode {
    if config.is_null() {
        return ptr::null();
    }

    &(*config).root
}

/// Return the node name as a NUL-terminated string.
///
/// # Safety
/// - `node` must be either NULL or a valid pointer to an `SCConfigNode` from this API.
/// - The returned string pointer is borrowed and valid only while the owning
///   `SCConfig` is alive.
#[no_mangle]
pub unsafe extern "C" fn SCConfigNodeName(node: *const SCConfigNode) -> *const c_char {
    if node.is_null() {
        return ptr::null();
    }

    (*node).name.as_ptr()
}

/// Return the node scalar value as a NUL-terminated string, or NULL if absent.
///
/// # Safety
/// - `node` must be either NULL or a valid pointer to an `SCConfigNode` from this API.
/// - The returned string pointer is borrowed and valid only while the owning
///   `SCConfig` is alive.
#[no_mangle]
pub unsafe extern "C" fn SCConfigNodeValue(node: *const SCConfigNode) -> *const c_char {
    if node.is_null() {
        return ptr::null();
    }

    match (*node).value.as_ref() {
        Some(value) => value.as_ptr(),
        None => ptr::null(),
    }
}

/// Return true when the node represents a YAML sequence.
///
/// # Safety
/// - `node` must be either NULL or a valid pointer to an `SCConfigNode` from this API.
#[no_mangle]
pub unsafe extern "C" fn SCConfigNodeIsSequence(node: *const SCConfigNode) -> bool {
    if node.is_null() {
        return false;
    }

    (*node).is_sequence
}

/// Return the number of child nodes attached to this node.
///
/// # Safety
/// - `node` must be either NULL or a valid pointer to an `SCConfigNode` from this API.
#[no_mangle]
pub unsafe extern "C" fn SCConfigNodeChildrenCount(node: *const SCConfigNode) -> usize {
    if node.is_null() {
        return 0;
    }

    (*node).children.len()
}

/// Return the child node at index, or NULL when index is out of bounds.
///
/// # Safety
/// - `node` must be either NULL or a valid pointer to an `SCConfigNode` from this API.
/// - The returned pointer is borrowed and is valid only while the owning
///   `SCConfig` is alive.
#[no_mangle]
pub unsafe extern "C" fn SCConfigNodeChildAt(
    node: *const SCConfigNode, index: usize,
) -> *const SCConfigNode {
    if node.is_null() {
        return ptr::null();
    }

    let children = &(*node).children;
    match children.get(index) {
        Some(child) => child,
        None => ptr::null(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_tree_sequence_entry_key() {
        let config = crate::load_string(
            "outputs:\n  - eve-log:\n      enabled: yes\n      filename: eve.json\n",
        )
        .expect("config should parse");

        let tree = build_config_tree(config).expect("tree should build");
        assert_eq!(tree.root.children.len(), 1);

        let outputs = &tree.root.children[0];
        assert!(outputs.is_sequence);
        assert_eq!(outputs.children.len(), 1);

        let entry = &outputs.children[0];
        assert_eq!(
            entry.value.as_ref().map(|s| s.to_str().unwrap()),
            Some("eve-log")
        );
    }

    #[test]
    fn test_load_string_invalid_utf8() {
        match load_string_as_tree(&[0x80, 0x81]) {
            Ok(_) => panic!("invalid utf-8 should fail"),
            Err(error) => assert!(error.contains("utf-8")),
        }
    }

    #[cfg(not(feature = "debug-validate"))]
    #[test]
    fn test_build_tree_ignores_tagged_values() {
        let config = crate::parse_yaml("foo: !tag value\n").expect("config should parse");
        let tree = build_config_tree(config).expect("tree should build");

        assert_eq!(tree.root.children.len(), 1);
        let foo = &tree.root.children[0];
        assert_eq!(foo.name.to_str().ok(), Some("foo"));
        assert_eq!(
            foo.value.as_ref().and_then(|v| v.to_str().ok()),
            Some("value")
        );
    }

    #[cfg(feature = "debug-validate")]
    #[test]
    #[should_panic(expected = "tagged YAML values should be removed before FFI conversion")]
    fn test_build_tree_panics_on_tagged_values() {
        let config = crate::parse_yaml("foo: !tag value\n").expect("config should parse");
        let _ = build_config_tree(config);
    }
}
