// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// RFC 6691, Section 2: "When calculating the value to put in the TCP MSS option, the MTU value SHOULD be decreased by only the size of the fixed IP and TCP headers and SHOULD NOT be decreased to account for any possible IP or TCP options".
///
/// Maximum Segment Size is also called 'MSS'.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[repr(C, packed)]
pub struct MaximumSegmentSizeOption(MaximumSegmentSize);

impl Default for MaximumSegmentSizeOption
{
	#[inline(always)]
	fn default() -> Self
	{
		const MaximumOf536BigEndian: [u8; 2] = [2, 24];
		
		MaximumSegmentSizeOption(MaximumSegmentSize::from(NetworkEndianU16::from_network_endian(MaximumOf536BigEndian)))
	}
}

impl From<u16> for MaximumSegmentSizeOption
{
	#[inline(always)]
	fn from(value: u16) -> Self
	{
		MaximumSegmentSizeOption(MaximumSegmentSize::from(NetworkEndianU16::from_native_endian(value)))
	}
}

impl From<NetworkEndianU16> for MaximumSegmentSizeOption
{
	#[inline(always)]
	fn from(value: NetworkEndianU16) -> Self
	{
		MaximumSegmentSizeOption(MaximumSegmentSize::from(value))
	}
}

impl From<MaximumSegmentSize> for MaximumSegmentSizeOption
{
	#[inline(always)]
	fn from(value: MaximumSegmentSize) -> Self
	{
		MaximumSegmentSizeOption(value)
	}
}

impl MaximumSegmentSizeOption
{
	#[doc(hidden)]
	pub const Kind: u8 = 2;
	
	#[doc(hidden)]
	pub const KnownLength: usize = 4;
	
	/// To native endian.
	#[inline(always)]
	pub fn to_native_endian(self) -> u16
	{
		self.0.to_native_endian()
	}
}
