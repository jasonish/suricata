use crate::Node;
use std::ffi::CStr;
use std::os::raw::c_char;

#[no_mangle]
pub unsafe extern "C" fn RsConfGet(
    node: *const Node,
    name: *const c_char,
    vptr: *mut *const c_char,
) -> bool {
    let name = CStr::from_ptr(name);
    let name = name.to_str().unwrap();
    let node = &*(node as *const Node);
    match node.get_node(name) {
        Some(Node::String(s)) => {
            *vptr = s.as_cptr();
            true
        }
        _ => {
            *vptr = std::ptr::null_mut();
            false
        }
    }
}
