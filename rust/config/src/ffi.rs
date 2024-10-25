// SPDX-FileCopyrightText: Copyright (C) 2024 Open Information Security Foundation
// SPDX-License-Identifier: MIT

use std::{
    cell::RefCell,
    collections::HashMap,
    ffi::{CStr, CString},
    os::raw::c_char,
    sync::{Mutex, RwLock},
};

use lazy_static::lazy_static;
use saphyr::{Hash, Yaml};

thread_local! {
    static LAST_ERR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

lazy_static! {
    #[no_mangle]
    static ref GLOBAL: RwLock<Yaml> = RwLock::new(Yaml::Hash(Hash::new()));
    static ref CSTRINGS: Mutex<HashMap<String, CString>> = Mutex::new(HashMap::new());
}

//pub struct SuriConfigYamlHashIter(linked_hash_map::Iter<'static, Yaml, Yaml>);

// Converts a Rust &str to CString, store it in CSTRINGS and return a *mut c_char.
fn get_cstring(s: &str) -> Result<*const c_char, Box<dyn std::error::Error>> {
    let cstring = CString::new(s)?;
    let mut cstrings = CSTRINGS.lock().unwrap();
    cstrings.insert(s.to_string(), cstring);
    let s = cstrings.get(s).unwrap();
    Ok(s.as_ptr())
}

#[no_mangle]
pub unsafe extern "C" fn SuriConfigSetGlobal(yaml: *mut Yaml) {
    let yaml = Box::from_raw(yaml);
    let mut global = GLOBAL.write().unwrap();
    *global = *yaml;
}

#[no_mangle]
pub unsafe extern "C" fn SuriConfigLoadFromFile(filename: *const c_char) -> *mut Yaml {
    unsafe fn load_from_file(filename: *const c_char) -> Result<Yaml, Box<dyn std::error::Error>> {
        let filename = CStr::from_ptr(filename).to_str()?;
        crate::load_from_file(filename)
    }

    match load_from_file(filename) {
        Ok(yaml) => Box::into_raw(Box::new(yaml)),
        Err(err) => {
            let err = CString::new(format!("{:?}", err)).unwrap();
            LAST_ERR.with(|last_err|{
                *last_err.borrow_mut() = Some(err);
            });
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn SuriConfigLastErr() -> *const c_char {
    LAST_ERR.with(|last_err| {
        let last_err = last_err.borrow_mut();
        if let Some(err) = last_err.as_ref() {
            err.as_ptr()
        } else {
            std::ptr::null()
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn SuriConfigFree(yaml: *mut Yaml) {
    std::mem::drop(Box::from_raw(yaml));
}

#[no_mangle]
pub unsafe extern "C" fn SuriConfGet(name: *const c_char, vptr: *mut *const c_char) -> bool {
    pub unsafe fn conf_get(
        name: *const c_char, vptr: *mut *const c_char,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let name = CStr::from_ptr(name).to_str()?;
        let global = GLOBAL.read().unwrap();
        if let Some(node) = crate::get(&global, name) {
            if let Some(display) = crate::display(node) {
                *vptr = get_cstring(&display)?;
            }
        }
        Ok(())
    }

    conf_get(name, vptr).is_ok()
}
