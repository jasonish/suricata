/* Copyright (C) 2018 Open Information Security Foundation
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

use std;

named!(pub parse_gopher_request<String>,
       do_parse!(
           request: map_res!(take_until_and_consume!("\r\n"), std::str::from_utf8) >>
           (request.to_string())));

#[cfg(test)]
mod tests {

    use nom::*;
    use super::*;

    #[test]
    fn test_parse_gopher_request() {
        let buf = b"/Links\r\n";
        let result = parse_gopher_request(buf);
        assert_eq!(result, IResult::Done(&b""[..], "/Links".to_string()));
    }
}
