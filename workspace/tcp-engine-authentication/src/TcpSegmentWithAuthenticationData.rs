// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Abstraction of logic to use Authentication data.
pub trait TcpSegmentWithAuthenticationData
{
	/// Returns an `options_data_pointer`.
	#[inline(always)]
	fn write_md5_option(previously_reserved_space_options_data_pointer: usize, digest: [u8; 16]) -> usize;
	
	/// "2. the TCP header, excluding options, and assuming a checksum of zero".
	#[inline(always)]
	fn secure_hash_fixed_header(&self, hasher: &mut impl Digest);
	
	/// "3. the TCP segment data (if any)".
	#[inline(always)]
	fn secure_hash_payload_data(&self, hasher: &mut impl Digest, padded_options_size: usize, payload_size: usize);
}
