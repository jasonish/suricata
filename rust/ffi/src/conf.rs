/* Copyright (C) 2017-2026 Open Information Security Foundation
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

//! Suricata configuration wrappers.

use crate::SCLogDebug;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::str;

use suricata_sys::sys::{
    SCConfGet, SCConfGetChildValue, SCConfGetChildValueBool, SCConfGetFirstNode, SCConfGetNextNode,
    SCConfGetNode, SCConfGetValueNode, SCConfNode, SCConfNodeLookupChild,
    SCConfNodeLookupChildValue,
};

pub fn conf_get_node(key: &str) -> Option<ConfNode> {
    let key = CString::new(key).ok()?;

    let node = unsafe { SCConfGetNode(key.as_ptr()) };
    if node.is_null() {
        None
    } else {
        Some(ConfNode::wrap(node))
    }
}

// Return the string value of a configuration value.
pub fn conf_get(key: &str) -> Option<&str> {
    let ckey = CString::new(key).ok()?;
    let mut vptr: *const c_char = ptr::null();

    if unsafe { SCConfGet(ckey.as_ptr(), &mut vptr) } != 1 {
        SCLogDebug!("Failed to find value for key {}", key);
        return None;
    }

    if vptr.is_null() {
        SCLogDebug!("Failed to find value for key {}", key);
        return None;
    }

    str::from_utf8(unsafe { CStr::from_ptr(vptr).to_bytes() }).ok()
}

// Return the value of key as a boolean. A value that is not set is
// the same as having it set to false.
pub fn conf_get_bool(key: &str) -> bool {
    matches!(conf_get(key), Some("1" | "yes" | "true" | "on"))
}

/// Wrap a Suricata ConfNode and expose some of its methods with a
/// Rust friendly interface.
#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct ConfNode(*const SCConfNode);

impl ConfNode {
    pub fn wrap(conf: *const SCConfNode) -> Self {
        Self(conf)
    }

    pub fn as_ptr(&self) -> *const SCConfNode {
        self.0
    }

    pub fn get_child_node(&self, key: &str) -> Option<ConfNode> {
        let key = CString::new(key).ok()?;
        let node = unsafe { SCConfNodeLookupChild(self.0, key.as_ptr()) };
        if node.is_null() {
            None
        } else {
            Some(ConfNode::wrap(node))
        }
    }

    pub fn lookup_child_value(&self, key: &str) -> Option<&str> {
        let key = CString::new(key).ok()?;
        let vptr = unsafe { SCConfNodeLookupChildValue(self.0, key.as_ptr()) };
        if vptr.is_null() {
            return None;
        }

        str::from_utf8(unsafe { CStr::from_ptr(vptr).to_bytes() }).ok()
    }

    pub fn first(&self) -> Option<ConfNode> {
        let node = unsafe { SCConfGetFirstNode(self.0) };
        if node.is_null() {
            None
        } else {
            Some(ConfNode::wrap(node))
        }
    }

    pub fn next(&self) -> Option<ConfNode> {
        let node = unsafe { SCConfGetNextNode(self.0) };
        if node.is_null() {
            None
        } else {
            Some(ConfNode::wrap(node))
        }
    }

    pub fn value(&self) -> &str {
        let vptr = unsafe { SCConfGetValueNode(self.0) };
        if vptr.is_null() {
            return "";
        }

        str::from_utf8(unsafe { CStr::from_ptr(vptr).to_bytes() }).unwrap_or("")
    }

    pub fn get_child_value(&self, key: &str) -> Option<&str> {
        let key = CString::new(key).ok()?;
        let mut vptr: *const c_char = ptr::null();

        if unsafe { SCConfGetChildValue(self.0, key.as_ptr(), &mut vptr) } != 1 {
            return None;
        }

        if vptr.is_null() {
            return None;
        }

        str::from_utf8(unsafe { CStr::from_ptr(vptr).to_bytes() }).ok()
    }

    pub fn get_child_bool(&self, key: &str) -> bool {
        let key = match CString::new(key) {
            Ok(key) => key,
            Err(_) => return false,
        };
        let mut val: c_int = 0;

        if unsafe { SCConfGetChildValueBool(self.0, key.as_ptr(), &mut val) } != 1 {
            return false;
        }

        val == 1
    }
}
