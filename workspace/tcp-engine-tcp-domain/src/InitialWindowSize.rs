// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Initial window size choices.
#[derive(Default, Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct InitialWindowSize;

impl InitialWindowSize
{
	#[doc(hidden)]
	pub const Raw: NetworkEndianU16 = NetworkEndianU16::Maximum;
	
	/// RFC 7323, Section 2.2: "The window field in a segment where the SYN bit is set (i.e., a <SYN> or <SYN,ACK>) MUST NOT be scaled".
	pub const Segment: SegmentWindowSize = SegmentWindowSize(::std::u16::MAX);
	
	#[doc(hidden)]
	pub const TrueWindow: WindowSize = WindowSize::new(65_535);
	
	/// Preferred shift for a 256kb buffer.
	pub const Shift: WindowScaleOption = WindowScaleOption::BufferSizeOf256Kb;
}
