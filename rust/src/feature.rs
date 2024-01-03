/* Copyright (C) 2023 Open Information Security Foundation
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

//! Rust bindings to the "feature" API.

/// Check for a feature returning true if found.
#[cfg(not(test))]
pub fn requires(feature: &str) -> bool {
    use std::ffi::CString;
    use std::os::raw::c_char;

    extern "C" {
        fn RequiresFeature(feature: *const c_char) -> bool;
    }

    if let Ok(feature) = CString::new(feature) {
        unsafe { RequiresFeature(feature.as_ptr()) }
    } else {
        false
    }
}

/// Mock version of requires for Rust unit tests.
///
/// Any feature starting with "true" will be returned as true,
/// otherwise false is returned.
#[cfg(test)]
pub fn requires(feature: &str) -> bool {
    return feature.starts_with("true");
}
