/* Copyright (C) 2021 Open Information Security Foundation
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
use crate::core::*;
use std;

/* we are in mode of parsing a command's data.  Used when we are parsing tls
 * or accepting the rfc 2822 mail after DATA command */
pub const SMTP_PARSER_STATE_COMMAND_DATA_MODE: u8 = 0x01;

/* Various SMTP commands
 * We currently have var-ified just STARTTLS and DATA, since we need to them
 * for state transitions.  The rest are just indicate as OTHER_CMD.  Other
 * commands would be introduced as and when needed */
pub const SMTP_COMMAND_STARTTLS: u8 = 1;
pub const SMTP_COMMAND_DATA: u8 = 2;
pub const SMTP_COMMAND_BDAT: u8 = 3;
pub const SMTP_COMMAND_DATA_MODE: u8 = 4;
pub const SMTP_COMMAND_OTHER_CMD: u8 = 5;

pub const SMTP_COMMAND_BUFFER_STEPS: u16 = 5;

#[no_mangle]
pub extern "C" fn set_min_inspect_depth(flow: *const std::os::raw::c_void, ctnt_min_size: u32,
    ts_data_cnt: u64, ts_last_ds: u64, dir: u16, trigger_reassembly: bool)
{
    let flow = unsafe { cast_pointer!(flow, Flow) };

    let depth: u64 = ctnt_min_size as u64 + ts_data_cnt - ts_last_ds;
    if trigger_reassembly == true {
        sc_app_layer_parser_trigger_raw_stream_reassembly(flow, dir as i32);
    }
    SCLogDebug!("StreamTcpReassemblySetMinInspectDepth STREAM_TOSERVER: {}", depth);
    let protoctx = flow.get_protoctx();
    unsafe { StreamTcpReassemblySetMinInspectDepth(protoctx, dir, depth as u32) };
}

#[no_mangle]
pub unsafe extern "C" fn handle_fragmented_lines(input: *mut *const u8,
    input_len: *mut i32, ts_db: *mut *const u8,
    ts_cur_line_db: u8, ts_db_len: *mut i32) -> i32
{
    let buf_len = input_len as usize;
    let buf = build_slice!(input, buf_len);
    let mut its_db;
    let lf_idx = buf.to_vec().iter().position(|c| *c == &0x0a);
    match lf_idx {
        Some(_idx) => {
            if ts_cur_line_db == 0 {
                its_db = Vec::new();
                its_db.extend_from_slice(buf);
                *ts_db_len = buf_len as i32;
                // TODO never seem to assign its_db to anything here
            } else {
                its_db = build_slice!(ts_db, ts_db_len as usize).to_vec();
                its_db.extend_from_slice(&buf);
                *ts_db = *its_db.as_ptr();
                let slice = &buf[buf_len..];
                *input = *slice.as_ptr();
                *input_len = 0 as i32;
            }
        }
        None => { return -1; }
    }
    lf_idx.unwrap() as i32
}

#[no_mangle]
pub unsafe extern "C" fn rs_smtp_clear_parser(cur_line_lf_seen: *mut u8, cur_line_db: *mut u8,
    db: *mut *mut *const u8, db_len: *mut i32, cur_line: *mut *mut *const u8, cur_line_len: *mut i32)
{
    if *cur_line_lf_seen == 1 {
        *cur_line_lf_seen = 0;
        if *cur_line_db == 1 {
            *cur_line_db = 0;
            // TODO free obj here asked Jason
            **db = std::ptr::null();
            *db_len = 0;
            **cur_line = std::ptr::null();
            *cur_line_len = 0;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_smtp_handle_frag_lines(lf_idx: *const u8, cur_line_db: *mut u8,
    db: *mut *mut *const u8, input_len: *mut i32, input: *mut *mut *const u8, db_len: *mut i32) -> i32
{
    let mut its_db;
    let buf_len = *input_len as usize;
    let buf = *input;
    let buf = build_slice!(buf, buf_len);
    if lf_idx.is_null() {
        if *cur_line_db == 0 {
            its_db = Vec::new(); // Can't use with_capacity as realloc is done later
            *cur_line_db = 1;
            its_db.extend_from_slice(buf);
            **db = *its_db.as_ptr();
            *db_len = buf_len as i32;
        } else {
            let idb = *db;
            let idb_len = *db_len;
            its_db = build_slice!(idb, idb_len as usize).to_vec();
            its_db.extend_from_slice(&buf);
            *db = its_db.as_mut_ptr();
            let slice = &buf[buf_len..];
            **input = *slice.as_ptr();
            *input_len = 0 as i32;
            return -1;
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rs_smtp_handle_lf_idx(cur_line_lf_seen: *mut u8, cur_line_db: *mut u8,
    db: *mut *mut *const u8, db_len: *mut i32, input: *mut *mut *const u8, lf_idx: *mut u8,
    cur_line_delim_len: *mut u8, cur_line: *mut *mut *const u8, cur_line_len: *mut i32,
    input_len: *mut i32) -> i32
{
    let mut its_db;
    let buf = *input;
    let buf_len = *input_len as usize;
    let mut buf = build_slice!(buf, buf_len).to_vec();
    *cur_line_lf_seen = 1;
    if *cur_line_db == 1 {
        let idb = *db;
        let mut idb_len = *db_len;
        its_db = build_slice!(idb, idb_len as usize).to_vec();
        its_db.extend_from_slice(&buf);
        if idb_len > 1 && *its_db[(idb_len - 2) as usize] == 0x0D {
            idb_len -= 2;
            *cur_line_delim_len = 2;
        } else {
            idb_len -= 1;
            *cur_line_delim_len = 1;
        }
        *cur_line = idb;
        *cur_line_len = idb_len;
    } else {
        *cur_line = buf.as_mut_ptr();
        *cur_line_len = (*lf_idx - *buf[0]) as i32;
        if *buf[0] != *lf_idx && *lf_idx - 1 == 0x0D { // TODO Maybe FIX
            *cur_line_len -= 1;
            *cur_line_delim_len = 2;
        } else {
            *cur_line_delim_len = 1;
        }
    }
    *input_len -= (*lf_idx - *buf[0] + 1) as i32;
    *input = buf[(*lf_idx + 1) as usize..].as_mut_ptr();

    0
}

#[no_mangle]
pub unsafe extern "C" fn rs_smtp_set_cmd_buflen(cmds_cnt: u16, cmd_buflen: *mut u16,
    cmds: *mut *mut *const u8) -> i8
{
    if cmds_cnt >= *cmd_buflen {
        let mut inc = SMTP_COMMAND_BUFFER_STEPS;
        if *cmd_buflen + SMTP_COMMAND_BUFFER_STEPS > u16::MAX {
            inc = u16::MAX - *cmd_buflen;
        }
        let mut tmp = Vec::with_capacity((*cmd_buflen + inc) as usize);
        *cmds = tmp.as_mut_ptr();
        *cmd_buflen += inc;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rs_smtp_set_decoder_event(cmds_cnt: *mut u16,
    cmds: *mut *mut *const u8) -> i8
{
    let cmd_pos = (*cmds_cnt - 1) as usize;
    let cmd_list = *cmds;
    let buf = build_slice!(cmd_list, (cmd_pos + 1) as usize);
    if *cmds_cnt >= 1 && ((*(*buf)[cmd_pos] == SMTP_COMMAND_STARTTLS as u8) ||
        (*buf[cmd_pos] == SMTP_COMMAND_DATA)) {
        return 0;
    }
    -1
}

#[no_mangle]
pub unsafe extern "C" fn rs_smtp_set_cmd_into_buffer(cmds: *mut *mut *const u8,
    cmds_cnt: *mut u16, cmd: *const u8) -> i8
{
    let cmd_pos = *cmds_cnt as usize;
    let cmd_list = *cmds;
    let mut buf = build_slice!(cmd_list, cmd_pos).to_vec();
    if *cmds_cnt + 1 > u16::MAX {
        SCLogDebug!("Buffer Overflow");
        return -1;
    }
    buf.push(cmd);
    *cmds = buf[..].as_mut_ptr();
    *cmds_cnt += 1;
    0
}

#[no_mangle]
pub unsafe extern "C" fn rs_smtp_process_cmd_bdat(cur_line_len: i32 /* should be u32*/, cur_line_delim_len: u8,
    bdat_chunk_idx: *mut u32, bdat_chunk_len: u32, parser_state: *mut u8) -> i8
{
    *bdat_chunk_idx += cur_line_len as u32 + cur_line_delim_len as u32;
    if *bdat_chunk_idx > bdat_chunk_len {
        *parser_state &= !SMTP_PARSER_STATE_COMMAND_DATA_MODE;
        return -1;
    } else if *bdat_chunk_idx == bdat_chunk_len {
        *parser_state &= !SMTP_PARSER_STATE_COMMAND_DATA_MODE;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rs_smtp_parse_cmd_bdat(cur_line_len: i32, cur_line: *mut *mut *const u8,
    bdat_chunk_len: *mut u32) -> i8
{
    let buf = *cur_line;
    let buf = build_slice!(buf, cur_line_len as usize).to_vec();
    let buf: Vec<u8> = buf.iter().map(|v| *v as u8).collect();
    let i = buf.iter().position(|&x| char::from(x) != ' ').unwrap();
    if i == 4 || i == cur_line_len as usize {
        // decoder event
        return -1;
    }
    //let bufs = CStr::from_ptr(**cur_line);
    let s = match std::str::from_utf8(&buf) {
        Ok(v) => v,
        Err(e) => {
            SCLogError!("Invalid UTF-8 sequence: {}", e);
            return -1;
        },
    };
    match s.split_whitespace().collect::<Vec<_>>()[0].parse::<u32>() {
        Ok(val) => {
            *bdat_chunk_len = val;
        }
        _ => {
            // decoder event
            return -1;
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rs_smtp_parse_cmd_w_param(cur_line_len: i32, cur_line: *mut *mut *const u8,
    pref: u8, target: *mut *mut *const u8, target_len: *mut u16) -> i8
{
    let buf = *cur_line;
    let buf = build_slice!(buf, cur_line_len as usize).to_vec();
    let buf: Vec<u8> = buf.iter().map(|v| *v as u8).collect();
    let i = buf[(pref + 1) as usize..].iter().position(|&x| char::from(x) != ' ').unwrap();
    /* rfc1870: with the size extension the mail from can be followed by an option.
    We use the space separator to detect it. */
    let spc_i = buf[i as usize..].iter().position(|&x| char::from(x) == ' ').unwrap();
    let mut fin_target = Vec::new();
    fin_target.extend_from_slice(&buf[..spc_i - i + 1]);
//    fin_target.push('\0'); TODO figure out how to add a null char
    let mut fin_target: Vec<*const u8> = fin_target.iter().map(|v| v as *const u8).collect();
    *target = fin_target.as_mut_ptr();
    *target_len = (spc_i - i) as u16;
    0
}

#[no_mangle]
pub unsafe extern "C" fn rs_smtp_nonewtx(parser_state: u8, cur_line: *mut *mut *const u8,
    cur_line_len: i32) -> i8
{
    let buf = *cur_line;
    let buf = build_slice!(buf, cur_line_len as usize).to_vec();
    let buf: Vec<u8> = buf.iter().map(|v| *v as u8).collect();
    let s = match std::str::from_utf8(&buf) {
        Ok(v) => v,
        Err(e) => {
            SCLogError!("Invalid UTF-8 sequence: {}", e);
            return -1;
        },
    };
    if parser_state & SMTP_PARSER_STATE_COMMAND_DATA_MODE == 0 {
        if cur_line_len >= 4 && s.to_lowercase().eq("rset") {
            return 1;
        } else if cur_line_len >= 4 && s.to_lowercase().eq("quit") {
            return 1;
        }
    }
    0
}
