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
use core::{self, ALPROTO_UNKNOWN, AppProto, Flow};
use libc;
use log::*;
use std::mem::transmute;
use applayer::{self, LoggerFlags};
use parser::*;
use std::ffi::CString;
use nom;
use super::parser;

static mut ALPROTO_GOPHER: AppProto = ALPROTO_UNKNOWN;

pub struct GopherTransaction {
    tx_id: u64,
    pub request: Option<String>,
    pub response: Option<String>,
    pub directory_listing: bool,

    logged: LoggerFlags,
    de_state: Option<*mut core::DetectEngineState>,
    events: *mut core::AppLayerDecoderEvents,
}

impl GopherTransaction {
    pub fn new() -> GopherTransaction {
        GopherTransaction {
            tx_id: 0,
            request: None,
            response: None,
            logged: LoggerFlags::new(),
            de_state: None,
            events: std::ptr::null_mut(),
            directory_listing: false,
        }
    }

    pub fn free(&mut self) {
        if self.events != std::ptr::null_mut() {
            core::sc_app_layer_decoder_events_free_events(&mut self.events);
        }
        if let Some(state) = self.de_state {
            core::sc_detect_engine_state_free(state);
        }
    }
}

impl Drop for GopherTransaction {
    fn drop(&mut self) {
        self.free();
    }
}

pub struct GopherState {
    tx_id: u64,
    request_buffer: Vec<u8>,
    response_buffer: Vec<u8>,
    transactions: Vec<GopherTransaction>,
}

impl GopherState {
    pub fn new() -> Self {
        Self {
            tx_id: 0,
            request_buffer: Vec::new(),
            response_buffer: Vec::new(),
            transactions: Vec::new(),
        }
    }

    // Free a transaction by ID.
    fn free_tx(&mut self, tx_id: u64) {
        let len = self.transactions.len();
        let mut found = false;
        let mut index = 0;
        for i in 0..len {
            let tx = &self.transactions[i];
            if tx.tx_id == tx_id + 1 {
                found = true;
                index = i;
                break;
            }
        }
        if found {
            self.transactions.remove(index);
        }
    }

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&GopherTransaction> {
        for tx in &mut self.transactions {
            if tx.tx_id == tx_id + 1 {
                return Some(tx);
            }
        }
        return None;
    }

    fn new_tx(&mut self) -> GopherTransaction {
        let mut tx = GopherTransaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        return tx;
    }

    fn find_request(&mut self) -> Option<&mut GopherTransaction> {
        for tx in &mut self.transactions {
            if tx.response.is_none() {
                return Some(tx);
            }
        }
        None
    }

    fn parse_request(&mut self, input: &[u8]) -> bool {
        // We're not interested in empty requests.
        if input.len() == 0 {
            return true;
        }

        // Perform buffering in the request data, even though its
        // probably not needed for Rust.
        self.request_buffer.extend(input);

        let tmp: Vec<u8>;
        let mut current = {
            tmp = self.request_buffer.split_off(0);
            tmp.as_slice()
        };

        while current.len() > 0 {
            match parser::parse_gopher_request(current) {
                nom::IResult::Done(rem, request) => {
                    current = rem;
                    let mut tx = self.new_tx();
                    if request.len() == 0 {
                        tx.directory_listing = true;
                    }
                    tx.request = Some(request);
                    self.transactions.push(tx);
                }
                nom::IResult::Incomplete(_) => {
                    self.request_buffer.extend_from_slice(current);
                    break;
                }
                nom::IResult::Error(_) => {
                    return false;
                }
            }
        }

        return true;
    }

    fn parse_response(&mut self, input: &[u8]) -> bool {
        if input.len() == 0 {
            if self.response_buffer.len() > 0 {
                let buf = self.response_buffer.split_off(0);
                match self.find_request() {
                    Some(tx) => {
                        let response = std::str::from_utf8(&buf);
                        tx.response = Some(response.unwrap().to_string());
                    }
                    _ => {}
                }
            }
        } else {
            self.response_buffer.extend(input);
        }

        return true;
    }

    fn tx_iterator(
        &mut self,
        min_tx_id: u64,
        state: &mut u64,
    ) -> Option<(&GopherTransaction, u64, bool)> {
        let mut index = *state as usize;
        let len = self.transactions.len();

        while index < len {
            let tx = &self.transactions[index];
            if tx.tx_id < min_tx_id + 1 {
                index += 1;
                continue;
            }
            *state = index as u64 + 1;
            return Some((tx, tx.tx_id - 1, (len - index) > 1));
        }

        return None;
    }
}

/// Probe to see if this input looks like a request or response.
///
/// For the purposes of this gopher things will be kept simple. The
/// protocol is text based with the leading text being the length of
/// the message in bytes. So simply make sure the first character is
/// between "1" and "9".
fn probe(input: &[u8]) -> bool {
    input.len() > 0
}

// C exports.

export_tx_get_detect_state!(
    rs_gopher_tx_get_detect_state,
    GopherTransaction
);
export_tx_set_detect_state!(
    rs_gopher_tx_set_detect_state,
    GopherTransaction
);

/// C entry point for a probing parser.
#[no_mangle]
pub extern "C" fn rs_gopher_probing_parser(
    _flow: *const Flow,
    input: *const libc::uint8_t,
    input_len: u32,
) -> AppProto {
    // Need at least 2 bytes.
    if input_len > 1 && input != std::ptr::null_mut() {
        let slice = build_slice!(input, input_len as usize);
        if probe(slice) {
            return unsafe { ALPROTO_GOPHER };
        }
    }
    return ALPROTO_UNKNOWN;
}

#[no_mangle]
pub extern "C" fn rs_gopher_state_new() -> *mut libc::c_void {
    let state = GopherState::new();
    let boxed = Box::new(state);
    return unsafe { transmute(boxed) };
}

#[no_mangle]
pub extern "C" fn rs_gopher_state_free(state: *mut libc::c_void) {
    // Just unbox...
    let _drop: Box<GopherState> = unsafe { transmute(state) };
}

#[no_mangle]
pub extern "C" fn rs_gopher_state_tx_free(
    state: *mut libc::c_void,
    tx_id: libc::uint64_t,
) {
    let state = cast_pointer!(state, GopherState);
    state.free_tx(tx_id);
}

#[no_mangle]
pub extern "C" fn rs_gopher_parse_request(
    _flow: *const Flow,
    state: *mut libc::c_void,
    pstate: *mut libc::c_void,
    input: *const libc::uint8_t,
    input_len: u32,
    _data: *const libc::c_void,
    _flags: u8,
) -> i8 {
    let eof = unsafe {
        if AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF) > 0 {
            true
        } else {
            false
        }
    };

    if eof {
        // If needed, handled EOF, or pass it into the parser.
    }

    let state = cast_pointer!(state, GopherState);
    let buf = build_slice!(input, input_len as usize);
    if state.parse_request(buf) {
        return 1;
    }
    return -1;
}

#[no_mangle]
pub extern "C" fn rs_gopher_parse_response(
    _flow: *const Flow,
    state: *mut libc::c_void,
    pstate: *mut libc::c_void,
    input: *const libc::uint8_t,
    input_len: u32,
    _data: *const libc::c_void,
    _flags: u8,
) -> i8 {
    let _eof = unsafe {
        if AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF) > 0 {
            true
        } else {
            false
        }
    };
    let state = cast_pointer!(state, GopherState);
    let buf = build_slice!(input, input_len as usize);
    if state.parse_response(buf) {
        return 1;
    }
    return -1;
}

#[no_mangle]
pub extern "C" fn rs_gopher_state_get_tx(
    state: *mut libc::c_void,
    tx_id: libc::uint64_t,
) -> *mut libc::c_void {
    let state = cast_pointer!(state, GopherState);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return unsafe { transmute(tx) };
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_gopher_state_get_tx_count(
    state: *mut libc::c_void,
) -> libc::uint64_t {
    let state = cast_pointer!(state, GopherState);
    return state.tx_id;
}

#[no_mangle]
pub extern "C" fn rs_gopher_state_progress_completion_status(
    _direction: libc::uint8_t,
) -> libc::c_int {
    // This parser uses 1 to signal transaction completion status.
    return 1;
}

#[no_mangle]
pub extern "C" fn rs_gopher_tx_get_alstate_progress(
    tx: *mut libc::c_void,
    _direction: libc::uint8_t,
) -> libc::c_int {
    let tx = cast_pointer!(tx, GopherTransaction);

    // Transaction is done if we have a response.
    if tx.response.is_some() {
        return 1;
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_gopher_tx_get_logged(
    _state: *mut libc::c_void,
    tx: *mut libc::c_void,
) -> u32 {
    let tx = cast_pointer!(tx, GopherTransaction);
    return tx.logged.get();
}

#[no_mangle]
pub extern "C" fn rs_gopher_tx_set_logged(
    _state: *mut libc::c_void,
    tx: *mut libc::c_void,
    logged: libc::uint32_t,
) {
    let tx = cast_pointer!(tx, GopherTransaction);
    tx.logged.set(logged);
}

#[no_mangle]
pub extern "C" fn rs_gopher_state_get_events(
    state: *mut libc::c_void,
    tx_id: libc::uint64_t,
) -> *mut core::AppLayerDecoderEvents {
    let state = cast_pointer!(state, GopherState);
    match state.get_tx(tx_id) {
        Some(tx) => tx.events,
        _ => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn rs_gopher_state_get_event_info(
    _event_name: *const libc::c_char,
    _event_id: *mut libc::c_int,
    _event_type: *mut core::AppLayerEventType,
) -> libc::c_int {
    return -1;
}

#[no_mangle]
pub extern "C" fn rs_gopher_state_get_tx_iterator(
    _ipproto: libc::uint8_t,
    _alproto: AppProto,
    state: *mut libc::c_void,
    min_tx_id: libc::uint64_t,
    _max_tx_id: libc::uint64_t,
    istate: &mut libc::uint64_t,
) -> applayer::AppLayerGetTxIterTuple {
    let state = cast_pointer!(state, GopherState);
    match state.tx_iterator(min_tx_id, istate) {
        Some((tx, out_tx_id, has_next)) => {
            let c_tx = unsafe { transmute(tx) };
            let ires = applayer::AppLayerGetTxIterTuple::with_values(
                c_tx,
                out_tx_id,
                has_next,
            );
            return ires;
        }
        None => {
            return applayer::AppLayerGetTxIterTuple::not_found();
        }
    }
}

/// Get the request buffer for a transaction from C.
///
/// No required for parsing, but an example function for retrieving a
/// pointer to the request buffer from C for detection.
#[no_mangle]
pub extern "C" fn rs_gopher_get_request_buffer(
    tx: *mut libc::c_void,
    buf: *mut *const libc::uint8_t,
    len: *mut libc::uint32_t,
) -> libc::uint8_t
{
    let tx = cast_pointer!(tx, GopherTransaction);
    if let Some(ref request) = tx.request {
        if request.len() > 0 {
            unsafe {
                *len = request.len() as libc::uint32_t;
                *buf = request.as_ptr();
            }
            return 1;
        }
    }
    return 0;
}

/// Get the response buffer for a transaction from C.
#[no_mangle]
pub extern "C" fn rs_gopher_get_response_buffer(
    tx: *mut libc::c_void,
    buf: *mut *const libc::uint8_t,
    len: *mut libc::uint32_t,
) -> libc::uint8_t
{
    let tx = cast_pointer!(tx, GopherTransaction);
    if let Some(ref response) = tx.response {
        if response.len() > 0 {
            unsafe {
                *len = response.len() as libc::uint32_t;
                *buf = response.as_ptr();
            }
            return 1;
        }
    }
    return 0;
}

// Parser name as a C style string.
const PARSER_NAME: &'static [u8] = b"gopher\0";

#[no_mangle]
pub unsafe extern "C" fn rs_gopher_register_parser() {
    let default_port = CString::new("[70]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const libc::c_char,
        default_port: default_port.as_ptr(),
        ipproto: libc::IPPROTO_TCP,
        probe_ts: rs_gopher_probing_parser,
        probe_tc: rs_gopher_probing_parser,
        min_depth: 0,
        max_depth: 16,
        state_new: rs_gopher_state_new,
        state_free: rs_gopher_state_free,
        tx_free: rs_gopher_state_tx_free,
        parse_ts: rs_gopher_parse_request,
        parse_tc: rs_gopher_parse_response,
        get_tx_count: rs_gopher_state_get_tx_count,
        get_tx: rs_gopher_state_get_tx,
        tx_get_comp_st: rs_gopher_state_progress_completion_status,
        tx_get_progress: rs_gopher_tx_get_alstate_progress,
        get_tx_logged: Some(rs_gopher_tx_get_logged),
        set_tx_logged: Some(rs_gopher_tx_set_logged),
        get_de_state: rs_gopher_tx_get_detect_state,
        set_de_state: rs_gopher_tx_set_detect_state,
        get_events: Some(rs_gopher_state_get_events),
        get_eventinfo: Some(rs_gopher_state_get_event_info),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_mpm_id: None,
        set_tx_mpm_id: None,
        get_files: None,
        get_tx_iterator: Some(rs_gopher_state_get_tx_iterator),
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(
        ip_proto_str.as_ptr(),
        parser.name,
    ) != 0
    {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_GOPHER = alproto;
        if AppLayerParserConfParserEnabled(
            ip_proto_str.as_ptr(),
            parser.name,
        ) != 0
        {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogNotice!("Rust gopher parser registered.");
    } else {
        SCLogNotice!("Protocol detector and parser disabled for GOPHER.");
    }
}
