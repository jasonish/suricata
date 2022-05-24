use crate::loader::Error;
use crate::{load_from_file, ConfValue};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr::slice_from_raw_parts;

pub const CONFIG_LOADER_ERR_SIZE: usize = 8192;

/// Error codes as simple integers for passing back to C should specical action need to be
/// taken on the type of error.
#[repr(u8)]
pub enum ConfigLoaderErr {
    Io = 1,
    Scan,
    NotAFile,
}

impl From<&Error> for ConfigLoaderErr {
    fn from(other: &Error) -> Self {
        match other {
            Error::IoError(_) => Self::Io,
            Error::YamlScanError(_) => Self::Scan,
            Error::NotAFile(_) => Self::NotAFile,
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn RsConfGet(
    node: *const ConfValue, name: *const c_char, vptr: *mut *const c_char,
) -> bool {
    let name = CStr::from_ptr(name);
    let name = name.to_str().unwrap();
    let node = &*(node as *const ConfValue);
    match node.get_node(name) {
        Some(ConfValue::String(s)) => {
            *vptr = s.as_cptr();
            true
        }
        _ => {
            *vptr = std::ptr::null_mut();
            false
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn SuricataConfigFromFilename(
    filename: *const c_char, errp: *mut c_char, errcode: *mut ConfigLoaderErr,
) -> *const ConfValue {
    let filename = CStr::from_ptr(filename).to_str().unwrap();
    match load_from_file(filename) {
        Ok(node) => Box::into_raw(Box::new(node)),
        Err(err) => {
            // Got any better ideas on returning the error to C with meaningful context?
            *errcode = ConfigLoaderErr::from(&err);
            let err_out = slice_from_raw_parts(errp, CONFIG_LOADER_ERR_SIZE as usize) as *mut u8;
            let msg = CString::new(err.to_string()).unwrap();
            let bytes = msg.as_bytes_with_nul();
            let len = CONFIG_LOADER_ERR_SIZE.min(bytes.len());
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), err_out, len);
            if len == CONFIG_LOADER_ERR_SIZE {
                let ep = err_out.offset(CONFIG_LOADER_ERR_SIZE as isize - 1);
                *ep = 0;
            }
            std::ptr::null()
        }
    }
}
