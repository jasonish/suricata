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

use std::ffi::CString;
use std::os::raw::c_void;

use suricata_sys::sys::{
    Flow, FlowStorageId, SCFlowGetStorageById, SCFlowSetStorageById, SCFlowStorageRegister,
};

pub fn register<T>(name: &str) -> Result<FlowStorageId, &'static str> {
    let name = Box::new(
        CString::new(name).map_err(|_| "flow storage name contains an interior NUL byte")?,
    );
    let name = Box::into_raw(name);
    let id = unsafe { SCFlowStorageRegister(name.cast(), Some(free::<T>)) };
    if id.id < 0 {
        drop(unsafe { Box::from_raw(name) });
        Err("failed to register flow storage")
    } else {
        Ok(id)
    }
}

/// Store a value in flow-local storage.
///
/// # Safety
///
/// `f` must point to a valid `Flow`, and `id` must have been registered for
/// values of type `T`.
pub unsafe fn set_by_id<T>(f: *mut Flow, id: FlowStorageId, v: T) -> Result<(), &'static str> {
    let ptr = Box::into_raw(Box::new(v));
    if unsafe { SCFlowSetStorageById(f, id, ptr.cast()) } == 0 {
        Ok(())
    } else {
        unsafe {
            drop(Box::from_raw(ptr));
        }
        Err("failed to set flow storage")
    }
}

/// Borrow a value from flow-local storage.
///
/// # Safety
///
/// `f` must point to a valid `Flow`, `id` must have been registered for values
/// of type `T`, and the returned reference must not outlive the stored value.
pub unsafe fn get_by_id<'a, T>(f: *mut Flow, id: FlowStorageId) -> Option<&'a mut T> {
    unsafe { SCFlowGetStorageById(f, id).cast::<T>().as_mut() }
}

unsafe extern "C" fn free<T>(ptr: *mut c_void) {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr as *mut T));
    }
}
