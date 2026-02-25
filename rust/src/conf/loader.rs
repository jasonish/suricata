/* Copyright (C) 2026 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

//! Populate the C Conf tree from the Rust YAML loader.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::path::Path;
use std::ptr;
use std::slice;

use saphyr::{MappingOwned, YamlOwned};

use suricata_sys::sys::{
    SCConfNode, SCConfNodeGetNodeOrCreate, SCConfNodeLookupChild, SCConfNodePrune, SCConfNode_,
};

const RECURSION_LIMIT: usize = 128;

#[derive(Debug)]
enum PopulateError {
    InvalidInput,
    InvalidDocumentRoot,
    UnsupportedInclude,
    InvalidKey,
    InvalidScalar,
    StringContainsNul,
    Allocation,
    RecursionLimit,
}

#[no_mangle]
pub unsafe extern "C" fn SCRustConfigLoadIntoConfFromFile(
    parent: *mut SCConfNode, filename: *const c_char,
) -> c_int {
    if parent.is_null() || filename.is_null() {
        return -1;
    }

    let filename = match CStr::from_ptr(filename).to_str() {
        Ok(value) => value,
        Err(_) => return -1,
    };

    let config = match suricata_config::load_config(Path::new(filename)) {
        Ok(config) => config,
        Err(_) => return -1,
    };

    match populate_loaded_config(parent, &config) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn SCRustConfigLoadIntoConfFromString(
    parent: *mut SCConfNode, input: *const c_char, len: usize,
) -> c_int {
    if parent.is_null() || input.is_null() {
        return -1;
    }

    let bytes = slice::from_raw_parts(input as *const u8, len);
    let input = match std::str::from_utf8(bytes) {
        Ok(value) => value,
        Err(_) => return -1,
    };

    let config = match suricata_config::parse_config(input) {
        Ok(config) => config,
        Err(_) => return -1,
    };

    match populate_loaded_config(parent, &config) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

fn populate_loaded_config(
    parent: *mut SCConfNode, config: &YamlOwned,
) -> Result<(), PopulateError> {
    let config = untagged_node(config);

    match config {
        YamlOwned::Mapping(mapping) => populate_mapping(parent, mapping, 0),
        YamlOwned::Sequence(sequence) => populate_sequence(parent, sequence, 0),
        _ => Err(PopulateError::InvalidDocumentRoot),
    }
}

fn populate_node(
    node: *mut SCConfNode, value: &YamlOwned, depth: usize,
) -> Result<(), PopulateError> {
    if depth > RECURSION_LIMIT {
        return Err(PopulateError::RecursionLimit);
    }

    let value = untagged_node(value);

    match value {
        YamlOwned::Mapping(mapping) => populate_mapping(node, mapping, depth),
        YamlOwned::Sequence(sequence) => populate_sequence(node, sequence, depth),
        _ => {
            let value = scalar_value_to_string(value)?;
            unsafe {
                set_node_value(node, value.as_deref(), true)?;
            }
            Ok(())
        }
    }
}

fn populate_mapping(
    parent: *mut SCConfNode, mapping: &MappingOwned, depth: usize,
) -> Result<(), PopulateError> {
    if depth > RECURSION_LIMIT {
        return Err(PopulateError::RecursionLimit);
    }

    for (key_node, value_node) in mapping {
        let raw_key = scalar_key_to_string(key_node)?;
        if raw_key == "include" {
            return Err(PopulateError::UnsupportedInclude);
        }

        if is_include_tag(value_node) {
            return Err(PopulateError::UnsupportedInclude);
        }

        unsafe {
            if node_is_sequence(parent) && node_value_is_null(parent) {
                let seq_value = mangle_name(&raw_key);
                set_node_value(parent, Some(&seq_value), false)?;
            }
        }

        let key_is_dotted = raw_key.contains('.');
        let key = if key_is_dotted {
            raw_key.clone()
        } else {
            unsafe { mangle_mapping_key(parent, &raw_key) }
        };

        let child = unsafe {
            if key_is_dotted {
                get_or_create_node(parent, &key)?
            } else {
                let existing = lookup_child(parent, &key)?;
                if !existing.is_null() {
                    if !node_is_final(existing) {
                        SCConfNodePrune(existing);
                    }
                    existing
                } else {
                    get_or_create_node(parent, &key)?
                }
            }
        };

        populate_node(child, value_node, depth + 1)?;
    }

    Ok(())
}

fn populate_sequence(
    parent: *mut SCConfNode, sequence: &[YamlOwned], depth: usize,
) -> Result<(), PopulateError> {
    if depth > RECURSION_LIMIT {
        return Err(PopulateError::RecursionLimit);
    }

    unsafe {
        set_node_sequence(parent);
    }

    for (index, value) in sequence.iter().enumerate() {
        let index_name = index.to_string();
        let child = unsafe { get_or_create_node(parent, &index_name)? };
        let value = untagged_node(value);

        match value {
            YamlOwned::Mapping(mapping) => {
                unsafe {
                    set_node_sequence(child);
                }
                populate_mapping(child, mapping, depth + 1)?;
            }
            YamlOwned::Sequence(subsequence) => {
                unsafe {
                    set_node_sequence(child);
                }
                populate_sequence(child, subsequence, depth + 1)?;
            }
            _ => {
                let scalar_value = scalar_value_to_string(value)?;
                unsafe {
                    set_node_value(child, scalar_value.as_deref(), true)?;
                }
            }
        }
    }

    Ok(())
}

fn scalar_key_to_string(node: &YamlOwned) -> Result<String, PopulateError> {
    let node = untagged_node(node);

    if node.is_null() {
        return Ok("null".to_string());
    }

    if let Some(value) = node.as_str() {
        return Ok(value.to_string());
    }

    if let Some(value) = node.as_integer() {
        return Ok(value.to_string());
    }

    if let Some(value) = node.as_floating_point() {
        return Ok(value.to_string());
    }

    if let Some(value) = node.as_bool() {
        return Ok(value.to_string());
    }

    match node {
        YamlOwned::Representation(value, _, _) => Ok(value.to_string()),
        YamlOwned::Alias(anchor) => Ok(format!("*{anchor}")),
        YamlOwned::BadValue => Err(PopulateError::InvalidKey),
        _ => Err(PopulateError::InvalidKey),
    }
}

fn scalar_value_to_string(node: &YamlOwned) -> Result<Option<String>, PopulateError> {
    let node = untagged_node(node);

    if node.is_null() {
        return Ok(None);
    }

    if let Some(value) = node.as_str() {
        return Ok(Some(value.to_string()));
    }

    if let Some(value) = node.as_integer() {
        return Ok(Some(value.to_string()));
    }

    if let Some(value) = node.as_floating_point() {
        return Ok(Some(value.to_string()));
    }

    if let Some(value) = node.as_bool() {
        return Ok(Some(value.to_string()));
    }

    match node {
        YamlOwned::Representation(value, _, _) => Ok(Some(value.to_string())),
        YamlOwned::Alias(anchor) => Ok(Some(format!("*{anchor}"))),
        YamlOwned::BadValue => Err(PopulateError::InvalidScalar),
        _ => Err(PopulateError::InvalidScalar),
    }
}

fn untagged_node(mut node: &YamlOwned) -> &YamlOwned {
    while let Some(inner) = node.get_tagged_node() {
        node = inner;
    }
    node
}

fn is_include_tag(node: &YamlOwned) -> bool {
    if let YamlOwned::Tagged(tag, _) = node {
        return tag.handle == "!" && tag.suffix == "include";
    }

    false
}

fn mangle_name(value: &str) -> String {
    value.replace('_', "-")
}

unsafe fn mangle_mapping_key(parent: *mut SCConfNode, key: &str) -> String {
    if !key.contains('_') {
        return key.to_string();
    }

    if parent_name_is(parent, b"address-groups") || parent_name_is(parent, b"port-groups") {
        return key.to_string();
    }

    mangle_name(key)
}

unsafe fn parent_name_is(parent: *mut SCConfNode, expected: &[u8]) -> bool {
    if parent.is_null() {
        return false;
    }

    let inner = &*(parent as *const SCConfNode_);
    if inner.name.is_null() {
        return false;
    }

    CStr::from_ptr(inner.name).to_bytes() == expected
}

unsafe fn node_is_sequence(node: *mut SCConfNode) -> bool {
    if node.is_null() {
        return false;
    }

    (*(node as *const SCConfNode_)).is_seq != 0
}

unsafe fn node_is_final(node: *mut SCConfNode) -> bool {
    if node.is_null() {
        return false;
    }

    (*(node as *const SCConfNode_)).final_ != 0
}

unsafe fn node_value_is_null(node: *mut SCConfNode) -> bool {
    if node.is_null() {
        return true;
    }

    (*(node as *const SCConfNode_)).val.is_null()
}

unsafe fn set_node_sequence(node: *mut SCConfNode) {
    if node.is_null() {
        return;
    }

    (*(node as *mut SCConfNode_)).is_seq = 1;
}

unsafe fn get_or_create_node(
    parent: *mut SCConfNode, key: &str,
) -> Result<*mut SCConfNode, PopulateError> {
    let key = CString::new(key).map_err(|_| PopulateError::StringContainsNul)?;
    let node = SCConfNodeGetNodeOrCreate(parent, key.as_ptr(), 0);
    if node.is_null() {
        return Err(PopulateError::Allocation);
    }

    Ok(node)
}

unsafe fn lookup_child(
    parent: *mut SCConfNode, key: &str,
) -> Result<*mut SCConfNode, PopulateError> {
    let key = CString::new(key).map_err(|_| PopulateError::StringContainsNul)?;
    Ok(SCConfNodeLookupChild(
        parent as *const SCConfNode,
        key.as_ptr(),
    ))
}

unsafe fn set_node_value(
    node: *mut SCConfNode, value: Option<&str>, honor_final: bool,
) -> Result<(), PopulateError> {
    if node.is_null() {
        return Err(PopulateError::InvalidInput);
    }

    let node = &mut *(node as *mut SCConfNode_);
    if honor_final && node.final_ != 0 {
        return Ok(());
    }

    if !node.val.is_null() {
        libc::free(node.val as *mut libc::c_void);
        node.val = ptr::null_mut();
    }

    if let Some(value) = value {
        let c_value = CString::new(value).map_err(|_| PopulateError::StringContainsNul)?;
        let bytes = c_value.as_bytes_with_nul();
        let ptr = libc::malloc(bytes.len()) as *mut c_char;
        if ptr.is_null() {
            return Err(PopulateError::Allocation);
        }

        ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, ptr, bytes.len());
        node.val = ptr;
    }

    Ok(())
}
