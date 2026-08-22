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

use std::marker::PhantomData;

use suricata_sys::sys::{self, SCPacketGetFlow, SCPacketGetTCPHeader};

/// A read-only wrapper around an opaque Suricata `Packet` pointer.
pub struct Packet<'a> {
    packet: *const sys::Packet,
    _marker: PhantomData<&'a sys::Packet>,
}

impl<'a> Packet<'a> {
    /// Wrap a raw `Packet` pointer.
    ///
    /// # Safety
    ///
    /// `packet` must be a valid packet pointer for the lifetime of this
    /// wrapper.
    pub unsafe fn from_ptr(packet: *const sys::Packet) -> Self {
        Self {
            packet,
            _marker: PhantomData,
        }
    }

    /// Return the packet's flow pointer, or null if it has no flow.
    pub fn flow_ptr(&self) -> *const sys::Flow {
        unsafe { SCPacketGetFlow(self.packet) }
    }

    /// Return the complete decoded TCP header, including TCP options.
    pub fn tcp_header(&self) -> Option<&[u8]> {
        let mut len = 0u16;
        let ptr = unsafe { SCPacketGetTCPHeader(self.packet, &mut len) };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { std::slice::from_raw_parts(ptr, usize::from(len)) })
        }
    }
}
