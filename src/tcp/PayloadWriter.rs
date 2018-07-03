// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


trait PayloadWriter
{
	/// Writes payload for a segment.
	/// Should write up to `maximum_payload_size_unless_a_zero_window_probe` bytes unless writing a zero window probe, in which case `maximum_payload_size_unless_a_zero_window_probe` will be zero but it is permissible to write one (garbage) byte.
	#[inline(always)]
	fn write(&self, segment_payload_starts_at_pointer: NonNull<u8>, maximum_payload_size_unless_a_zero_window_probe: u32) -> usize;
}
