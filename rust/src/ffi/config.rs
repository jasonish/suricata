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

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use suricata_config::{LoaderError, Yaml};

pub const SC_CONFIG_ERRBUF_SIZE: usize = 4096;

#[no_mangle]
pub unsafe extern "C" fn ScLoadYaml2(filename: *const c_char, errbuf: *mut c_char) -> *mut Yaml {
    let filename = match CStr::from_ptr(filename).to_str() {
        Ok(cs) => cs,
        Err(err) => {
            SCLogError!("Failed to convert C filename to UTF-8: {:?}", err);
            return std::ptr::null_mut();
        }
    };

    let config = match suricata_config::loader::load_from_file(filename) {
        Ok(mut docs) => docs.pop().unwrap(),
        Err(err) => {
            let error = match err {
                LoaderError::NotAFile(_) => "Provided filename is not a file".to_string(),
                LoaderError::YamlScanError { filename, source } => {
                    let error = format!(
                        "YAML scan error at line {}, col {}",
                        source.marker().line(),
                        source.marker().col()
                    );

                    // Include the filename if there is one, the error could originate
                    // from an include.
                    if let Some(filename) = filename {
                        format!("{}, filename={}", error, filename)
                    } else {
                        error
                    }
                }
                _ => {
                    format!("{:?}", err)
                }
            };
            let error = CString::new(error).unwrap();
            let size = std::cmp::min(error.as_bytes_with_nul().len(), SC_CONFIG_ERRBUF_SIZE);
            std::ptr::copy_nonoverlapping(error.as_ptr(), errbuf, size);
            return std::ptr::null_mut();
        }
    };
    Box::into_raw(Box::new(config)) as *const _ as *mut _
}

#[no_mangle]
pub unsafe extern "C" fn ScFreeYaml(yaml: *mut Yaml) {
    let _ = Box::from_raw(yaml);
}
