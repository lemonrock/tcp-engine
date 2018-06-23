// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// RFC 879, Section 3, Paragraph 2: "The MSS counts only data octets in the segment, it does not count the TCP header or the IP header".
///
/// Maximum Segment Size is also called 'MSS'.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[repr(C, packed)]
pub(crate) struct MaximumSegmentSizeOption(NetworkEndianU16);

impl Default for MaximumSegmentSizeOption
{
	#[inline(always)]
	fn default() -> Self
	{
		const MaximumOf536BigEndian: [u8; 2] = [2, 24];
		
		MaximumSegmentSizeOption(NetworkEndianU16::from_network_endian(MaximumOf536BigEndian))
	}
}

impl MaximumSegmentSizeOption
{
	pub(crate) const Kind: u8 = 2;
	
	pub(crate) const KnownLength: usize = 4;
	
	/// Based on the Link MTU of AX.25 packet radio (256) which is believed to be the smallest MTU on the internet as of 2003.
	///
	/// `256 - size_of(IPv4 header) - size_of(TCP header)`, ie 216.
	///
	/// Which is 0x00D8 in big endian.
	pub(crate) const InternetProtocolVersion4Minimum: Self = MaximumSegmentSizeOption(NetworkEndianU16::from_network_endian([0x00, 0xD8]));
	
	/// RFC 879, Section 1: "The default TCP Maximum Segment Size is 536".
	///
	/// RFC 6691 Section 2: "The MTU value SHOULD be decreased by only the size of the fixed IP and TCP headers and SHOULD NOT be decreased to account for any possible IP or TCP options".
	///
	/// In effect, for IPv4 it is `576 - size_of(IPv4 header) - size_of(TCP header)`, ie 536.
	///
	/// Which is 0x0218 in big endian.
	pub(crate) const InternetProtocolVersion4Default: Self = MaximumSegmentSizeOption(NetworkEndianU16::from_network_endian([0x02, 0x18]));
	
	/// RFC 2460 Section 5, First Paragraph mandates a MTU of 1280.
	///
	/// `1280 - size_of(IPv6 header) - size_of(TCP header)`, ie 1220.
	///
	/// Which is 0x04C4 in big endian.
	pub(crate) const InternetProtocolVersion6Minimum: Self = MaximumSegmentSizeOption(NetworkEndianU16::from_network_endian([0x04, 0xC4]));
	
	#[inline(always)]
	pub(crate) fn to_native_endian(self) -> u16
	{
		self.0.to_native_endian()
	}
}
