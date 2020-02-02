// Copyright 2016 Brian Smith.
// Portions Copyright (c) 2016, Google Inc.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use crate::encrypt::polyfill::slice::u32_from_le_u8;
use crate::encrypt::{c, error};
use core;

pub type Key = [u32; KEY_LEN_IN_BYTES / 4];

/*pub fn key_from_bytes(key_bytes: &[u8; KEY_LEN_IN_BYTES]) -> Key {
	let mut key = [0u32; KEY_LEN_IN_BYTES / 4];
	for (key_u32, key_u8_4) in key.iter_mut().zip(key_bytes.chunks(4)) {
		*key_u32 = u32_from_le_u8(slice_as_array_ref!(key_u8_4, 4).unwrap());
	}
	key
}*/

#[inline]
pub fn chacha20_xor_in_place(key: &Key, counter: &Counter, in_out: &mut [u8]) {
	chacha20_xor_inner(
		key,
		counter,
		in_out.as_ptr(),
		in_out.len(),
		in_out.as_mut_ptr(),
	);
}

pub fn chacha20_xor_overlapping(
	key: &Key,
	counter: &Counter,
	in_out: &mut [u8],
	in_prefix_len: usize,
) {
	// XXX: The x86 and at least one branch of the ARM assembly language
	// code doesn't allow overlapping input and output unless they are
	// exactly overlapping. TODO: Figure out which branch of the ARM code
	// has this limitation and come up with a better solution.
	//
	// https://rt.openssl.org/Ticket/Display.html?id=4362
	let len = in_out.len() - in_prefix_len;
	if cfg!(any(target_arch = "arm", target_arch = "x86")) && in_prefix_len != 0 {
		unsafe {
			core::ptr::copy(in_out[in_prefix_len..].as_ptr(), in_out.as_mut_ptr(), len);
		}
		chacha20_xor_in_place(key, &counter, &mut in_out[..len]);
	} else {
		chacha20_xor_inner(
			key,
			counter,
			in_out[in_prefix_len..].as_ptr(),
			len,
			in_out.as_mut_ptr(),
		);
	}
}

#[inline]
pub fn chacha20_xor_inner(
	key: &Key,
	counter: &Counter,
	input: *const u8,
	in_out_len: usize,
	output: *mut u8,
) {
	debug_assert!(core::mem::align_of_val(key) >= 4);
	debug_assert!(core::mem::align_of_val(counter) >= 4);
	unsafe {
		GFp_ChaCha20_ctr32(output, input, in_out_len, key, counter);
	}
}

pub type Counter = [u32; 4];

#[inline]
pub fn make_counter(nonce: &[u8; NONCE_LEN], counter: u32) -> Counter {
	[
		counter.to_le(),
		u32_from_le_u8(slice_as_array_ref!(&nonce[0..4], 4).unwrap()),
		u32_from_le_u8(slice_as_array_ref!(&nonce[4..8], 4).unwrap()),
		u32_from_le_u8(slice_as_array_ref!(&nonce[8..12], 4).unwrap()),
	]
}

extern "C" {
	fn GFp_ChaCha20_ctr32(
		out: *mut u8,
		in_: *const u8,
		in_len: c::size_t,
		key: &Key,
		counter: &Counter,
	);
}

pub const KEY_LEN_IN_BYTES: usize = 256 / 8;

pub const NONCE_LEN: usize = 12; /* 96 bits */
