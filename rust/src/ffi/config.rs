/* Copyright (C) 2022 Open Information Security Foundation
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

use std::ffi::CStr;
use std::os::raw::c_char;

#[no_mangle]
pub unsafe extern "C" fn config_load_yaml(filename: *const c_char) -> bool {
    let filename = match CStr::from_ptr(filename).to_str() {
        Ok(cs) => cs,
        Err(err) => {
            SCLogError!("Failed to convert C filename to UTF-8: {:?}", err);
            return false
        },
    };

    let config = match suricata_config::loader::load_from_file(filename) {
        Ok(mut docs) => docs.pop().unwrap(),
        Err(err) => {
            SCLogError!("Failed to load {}: {:?}", filename, err);
            return false;
        }
    };
    suricata_config::set_default(config);
    true
}