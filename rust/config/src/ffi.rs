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

use crate::{get_node, DEFAULT, SuricataYaml};
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::sync::Mutex;
use yaml_rust::Yaml;

lazy_static! {
    static ref CSTRINGS: Mutex<HashMap<String, CString>> = Mutex::new(HashMap::new());
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn NewConfGet(key: *const c_char, vptr: *mut *const c_char) -> c_int {
    let key = match CStr::from_ptr(key).to_str() {
        Ok(key) => key,
        Err(_) => return -1,
    };

    let root = DEFAULT.read().unwrap();
    let node = get_node(&*root, key).unwrap();
    if let Yaml::String(s) = node {
        let mut cstrings = CSTRINGS.lock().unwrap();
        match cstrings.get(s) {
            Some(s) => {
                *vptr = s.as_ptr();
            }
            None => {
                let cstring = CString::new(s.clone()).unwrap();
                cstrings.insert(s.clone(), cstring);
                *vptr = cstrings.get(s).unwrap().as_ptr();
            }
        }
        return 0;
    }
    -1
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn ConfGetInt(key: *const c_char, vptr: *mut i64) -> c_int {
    let key = match CStr::from_ptr(key).to_str() {
        Ok(key) => key,
        Err(_) => return 0,
    };
    let root = DEFAULT.read().unwrap();
    if let Some(node) = get_node(&*root, key) {
        if let Some(n) = node.as_i64() {
            *vptr = n;
            return 1;
        }
    }
    0
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "C" fn RsConfSet(key: *const c_char, value: *const c_char) -> c_int {
    let key = match CStr::from_ptr(key).to_str() {
        Ok(cs) => cs,
        Err(_) => return 0,
    };
    let value = match CStr::from_ptr(value).to_str() {
        Ok(cs) => cs,
        Err(_) => return 0,
    };
    let mut root = DEFAULT.write().unwrap();
    if root.set_from_str(key, value) {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{loader, set_default};

    #[test]
    fn test_ffi_conf_get() {
        let doc = r#"
        simple: value
        nested:
            aaa: bbb
        "#;
        let config = loader::load_from_str(doc).unwrap().pop().unwrap();
        set_default(config);

        let key = CString::new("nested.aaa").unwrap();
        let mut value: *const c_char = std::ptr::null();
        let rc = unsafe { NewConfGet(key.as_ptr(), &mut value) };
        assert_eq!(rc, 0);
        assert_ne!(value, std::ptr::null());
        let expected = CString::new("bbb").unwrap();
        let actual = unsafe { CString::from_raw(value as *mut _) };
        assert_eq!(expected, actual);
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
        assert_eq!(rc, 1);
        assert_eq!(vptr, 999);
    }
}
