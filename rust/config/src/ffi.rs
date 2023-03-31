// SPDX-FileCopyrightText: Copyright (C) 2023 Open Information Security Foundation
// SPDX-License-Identifier: MIT

use std::os::raw::c_char;
use std::{collections::HashMap, ffi::CString};

use serde_yaml::Value;

/// A wrapper around serde_yaml::Value for the purposes of FFI.
///
/// Contains a raw pointer to a serde_yaml::Value. This is required to
/// allow this wrapper to contain a root node, or a reference to a
/// deeper node in the case of an iterator.
///
/// It also helps out with the case of Rust value to C value
/// conversion such as a string, and answers that problem, where
/// should I store the real CString a pointer will be returned to.
pub struct SCConfigValue {
    value: *mut Value,

    // Internal storage for C values. By storing here and using
    // pointers we get de-allocation for free.
    cstring: Option<CString>,
    cstrings: HashMap<String, CString>,
}

impl SCConfigValue {
    fn new(value: *mut Value) -> Self {
        Self {
            value,
            cstring: None,
            cstrings: HashMap::new(),
        }
    }
}

/// Create a new empty SCConfigValue with an empty map.
///
/// A map is used as this is intended to be used as the root of a
/// configuration.
#[no_mangle]
pub extern "C" fn SCConfigNewMapping() -> *mut SCConfigValue {
    let config = serde_yaml::Mapping::new();
    let config: serde_yaml::Value = config.into();
    let config = SCConfigValue::new(Box::into_raw(Box::new(config)));
    Box::into_raw(Box::new(config))
}

/// Free (drop) a SCConfigValue.
///
/// # Safety
///
/// `value` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn SCConfigValueFree(value: *mut SCConfigValue) {
    let value = Box::from_raw(value);
    std::mem::drop(Box::from_raw(value.value));
}

/// Check if a value is a string.
///
/// # Safety
///
/// `value` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn SCConfigValueIsString(value: &mut SCConfigValue) -> bool {
    let inner = &mut *value.value;
    matches!(inner, Value::String(_))
}

/// Check if a value is an array.
///
/// # Safety
///
/// `value` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn SCConfigValueIsArray(value: &mut SCConfigValue) -> bool {
    let inner = &mut *value.value;
    matches!(inner, Value::Sequence(_))
}

/// Check if a value is a mapping.
///
/// # Safety
///
/// `value` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn SCConfigValueIsMapping(value: &mut SCConfigValue) -> bool {
    let inner = &mut *value.value;
    matches!(inner, Value::Mapping(_))
}

/// Check if a value is a bool.
///
/// Unlike `SCConfigValueAsBool`, this will only return true if the
/// value is an actual bool.
///
/// # Safety
///
/// `value` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn SCConfigValueIsBool(value: &mut SCConfigValue) -> bool {
    let inner = &mut *value.value;
    matches!(inner, Value::Bool(_))
}

/// Check if a value is a number.
///
/// # Safety
///
/// `value` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn SCConfigValueIsNumber(value: &mut SCConfigValue) -> bool {
    let inner = &mut *value.value;
    matches!(inner, Value::Number(_))
}

/// Check if a value is null.
///
/// # Safety
///
/// `value` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn SCConfigValueIsNull(value: &mut SCConfigValue) -> bool {
    let inner = &mut *value.value;
    matches!(inner, Value::Null)
}

/// # Safety
///
/// `value` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn SCConfigValueAsString(value: &mut SCConfigValue) -> *const c_char {
    let inner = &mut *value.value;
    match inner {
        Value::String(string) => {
            value.cstring = Some(CString::new(string.clone()).unwrap());
            value.cstring.as_ref().unwrap().as_ptr()
        }
        Value::Number(number) => {
            let string = number.to_string();
            value.cstring = Some(CString::new(string.clone()).unwrap());
            value.cstring.as_ref().unwrap().as_ptr()
        }
        Value::Bool(boolean) => {
            let string = boolean.to_string();
            value.cstring = Some(CString::new(string.clone()).unwrap());
            value.cstring.as_ref().unwrap().as_ptr()
        }
        _ => std::ptr::null(),
    }
}

/// Get the value as a bool. Truthy values will automatically be converted.
///
/// For strings, the following values are considered true:
///     1, yes, true, on
///
/// For numbers, any integer value greater than 0.
///
/// All other values are false.
///
/// # Safety
///
/// `value` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn SCConfigValueAsBool(value: &mut SCConfigValue) -> bool {
    match &mut *value.value {
        Value::Bool(value) => *value,
        Value::String(value) => {
            matches!(value.to_lowercase().as_ref(), "1" | "yes" | "true" | "on")
        }
        Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                value > 0
            } else {
                false
            }
        }
        _ => false,
    }
}

/// # Safety
///
/// `value` and `out` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn SCConfigValueAsI64(value: &mut SCConfigValue, out: *mut i64) -> bool {
    if let Value::Number(value) = &mut *value.value {
        if let Some(value) = value.as_i64() {
            *out = value;
            return true;
        }
    }
    false
}

/// # Safety
///
/// `value` and `out` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn SCConfigValueAsF64(value: &mut SCConfigValue, out: *mut f64) -> bool {
    if let Value::Number(value) = &mut *value.value {
        if let Some(value) = value.as_f64() {
            *out = value;
            return true;
        }
    }
    false
}

#[no_mangle]
pub unsafe extern "C" fn SCConfigValueGet(
    config: &mut SCConfigValue, key: *const c_char, vptr: *mut *const c_char,
) -> bool {
    let key = std::ffi::CStr::from_ptr(key).to_str().unwrap();
    let value = &mut *config.value;
    if let Some(child) = crate::get(value, key) {
        match child {
            Value::Null => {
                *vptr = std::ptr::null();
                return true;
            }
            Value::Bool(b) => {
                let cstring = CString::new(b.to_string()).unwrap();
                config.cstrings.insert(key.to_string(), cstring);
                *vptr = config.cstrings.get(key).unwrap().as_ptr();
                return true;
            }
            Value::Number(n) => {
                let cstring = CString::new(n.to_string()).unwrap();
                config.cstrings.insert(key.to_string(), cstring);
                *vptr = config.cstrings.get(key).unwrap().as_ptr();
                return true;
            }
            Value::String(s) => {
                let cstring = CString::new(s.clone()).unwrap();
                config.cstrings.insert(key.to_string(), cstring);
                *vptr = config.cstrings.get(key).unwrap().as_ptr();
                return true;
            }
            _ => {
                // The remaining types exist so we still return true,
                // but with a null value.
                return true;
            }
        }
    }
    false
}

pub struct SCConfigMapIter<'a> {
    iter: serde_yaml::mapping::IterMut<'a>,
    strings: Vec<CString>,
    values: Vec<SCConfigValue>,
}

/// # Safety
///
/// `value` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn SCConfigMapIterGet(value: &mut SCConfigValue) -> *mut SCConfigMapIter {
    match &mut *value.value {
        serde_yaml::Value::Mapping(mapping) => {
            let iter = SCConfigMapIter {
                iter: mapping.iter_mut(),
                strings: vec![],
                values: vec![],
            };
            Box::into_raw(Box::new(iter))
        }
        _ => std::ptr::null_mut(),
    }
}

/// # Safety
///
/// `iter`, `key_out`, and `value_out` must be a valid pointers.
#[no_mangle]
pub unsafe extern "C" fn SCConfigMapIterNext(
    iter: &mut SCConfigMapIter, key_out: *mut *const c_char, value_out: *mut *mut SCConfigValue,
) -> bool {
    if let Some((key, val)) = iter.iter.next() {
        let key = match key {
            Value::Number(n) => n.to_string(),
            Value::String(s) => s.to_string(),
            _ => return false,
        };
        let key = CString::new(key).unwrap();
        iter.strings.push(key);
        iter.values.push(SCConfigValue::new(val));
        *key_out = iter.strings.last().unwrap().as_ptr();
        *value_out = iter.values.last_mut().unwrap() as *mut _;
        true
    } else {
        false
    }
}

/// # Safety
///
/// `iter` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn SCConfigMapIterFree(iter: *mut SCConfigMapIter) {
    std::mem::drop(Box::from_raw(iter));
}

pub struct SCConfigArrayIter<'a> {
    iter: std::slice::IterMut<'a, Value>,
    values: Vec<SCConfigValue>,
}

/// # Safety
///
/// `value` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn SCConfigArrayIterGet(value: &mut SCConfigValue) -> *mut SCConfigArrayIter {
    match &mut *value.value {
        serde_yaml::Value::Sequence(array) => {
            let iter = SCConfigArrayIter {
                iter: array.iter_mut(),
                values: vec![],
            };
            Box::into_raw(Box::new(iter))
        }
        _ => std::ptr::null_mut(),
    }
}

/// # Safety
///
/// `iter`, and `value_out` must be a valid pointers.
#[no_mangle]
pub unsafe extern "C" fn SCConfigArrayIterNext(
    iter: &mut SCConfigArrayIter, value_out: *mut *mut SCConfigValue,
) -> bool {
    if let Some(val) = iter.iter.next() {
        iter.values.push(SCConfigValue::new(val));
        *value_out = iter.values.last_mut().unwrap() as *mut _;
        true
    } else {
        false
    }
}

/// # Safety
///
/// `iter` must be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn SCConfigArrayIterFree(iter: *mut SCConfigArrayIter) {
    std::mem::drop(Box::from_raw(iter));
}

/// # Safety
///
/// `filename` must be a valid C string
#[no_mangle]
pub unsafe extern "C" fn SCConfigLoadFile(filename: *const c_char) -> *mut SCConfigValue {
    let filename = if let Ok(filename) = std::ffi::CStr::from_ptr(filename).to_str() {
        filename
    } else {
        return std::ptr::null_mut();
    };
    match crate::loader::load_file(filename) {
        Ok(config) => {
            let value = Box::into_raw(Box::new(config));
            Box::into_raw(Box::new(SCConfigValue::new(value)))
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// # Safety
///
/// `filename` must be a valid C string
#[no_mangle]
pub unsafe extern "C" fn SCConfigLoadString(
    input: *const c_char, len: usize,
) -> *mut SCConfigValue {
    let input = std::slice::from_raw_parts(input as *const u8, len);
    let input = if let Ok(input) = std::str::from_utf8(input) {
        input
    } else {
        return std::ptr::null_mut();
    };

    match crate::loader::load_string(input, "<string>") {
        Ok(config) => {
            let value = Box::into_raw(Box::new(config));
            Box::into_raw(Box::new(SCConfigValue::new(value)))
        }
        Err(err) => {
	    // TODO: Get an error code or error string back to C.
            println!("error: failed to load yaml string: {}", err);
            std::ptr::null_mut()
        }
    }
}

/// # Safety
///
/// `target` and `source` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn SCConfigMerge(target: &mut SCConfigValue, source: &mut SCConfigValue) {
    crate::merge(&mut *target.value, &*source.value);
}
