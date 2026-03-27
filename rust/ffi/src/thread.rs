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

use std::os::raw::c_void;

use suricata_sys::sys::SCThreadRegisterInitCallback;
use suricata_sys::sys::ThreadVars;

/// Register a thread init callback.
///
/// The callback is invoked once for each thread initialized during
/// Suricata startup.
///
/// # Example
///
/// ```no_run
/// use suricata_ffi::thread;
///
/// thread::register_init_callback(|_tv| {
///     // thread-local initialization can happen here
/// }).expect("failed to register thread init callback");
/// ```
///
/// # Safety
///
/// The callback receives a raw pointer from Suricata. This pointer is
/// only valid for the duration of the callback invocation and must not
/// be stored.
///
/// The callback must not panic.
pub fn register_init_callback<F>(callback: F) -> Result<(), &'static str>
where
    F: Fn(*mut ThreadVars) + Send + Sync + 'static,
{
    let user = Box::into_raw(Box::new(callback)) as *mut c_void;
    if unsafe { SCThreadRegisterInitCallback(Some(callback_wrapper::<F>), user) } {
        Ok(())
    } else {
        unsafe {
            drop(Box::from_raw(user as *mut F));
        }
        Err("Failed to register thread init callback")
    }
}

unsafe extern "C" fn callback_wrapper<F>(tv: *mut ThreadVars, user: *mut c_void)
where
    F: Fn(*mut ThreadVars) + Send + Sync + 'static,
{
    let callback = &*(user as *const F);
    callback(tv);
}
