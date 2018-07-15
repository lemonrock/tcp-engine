// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Maximum Segment Size, MSS.
///
/// A newtype wrapper around a network-endian u16.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct MaximumSegmentSize(NetworkEndianU16);

impl From<NetworkEndianU16> for MaximumSegmentSize
{
	#[inline(always)]
	fn from(value: NetworkEndianU16) -> Self
	{
		MaximumSegmentSize(value)
	}
}

impl Into<NetworkEndianU16> for MaximumSegmentSize
{
	#[inline(always)]
	fn into(self) -> NetworkEndianU16
	{
		self.0
	}
}

impl From<u16> for MaximumSegmentSize
{
	#[inline(always)]
	fn from(value: u16) -> Self
	{
		MaximumSegmentSize(NetworkEndianU16::from_native_endian(value))
	}
}

impl Into<u16> for MaximumSegmentSize
{
	#[inline(always)]
	fn into(self) -> u16
	{
		self.0.to_native_endian()
	}
}

impl MaximumSegmentSize
{
	/// RFC 6691 Section 2: "The MTU value SHOULD be decreased by only the size of the fixed IP and TCP headers and SHOULD NOT be decreased to account for any possible IP or TCP options".
	///
	/// In effect, for IPv4 it is `576 - size_of(IPv4 header) - size_of(TCP header)`,
	/// ie 536.
	///
	/// Which is 0x0218 in big endian.
	pub const Default: Self = MaximumSegmentSize(NetworkEndianU16::from_network_endian([0x02, 0x18]));
	
	/// Based on the Link MTU of AX.25 packet radio (256) which is believed to be the smallest MTU on the internet as of 2003.
	///
	/// `256 - size_of(IPv4 header) - size_of(TCP header)`,
	/// ie 216.
	///
	/// Which is 0x00D8 in big endian.
	pub const InternetProtocolVersion4Minimum: Self = MaximumSegmentSize(NetworkEndianU16::from_network_endian([0x00, 0xD8]));
	
	/// Based on RFC 4821 Section 7.2 Paragraph 2
	///
	/// `1024 - size_of(IPv4 header) - size_of(TCP header)`,
	/// ie 984.
	///
	/// Which is 0x0400 in big endian.
	pub const InternetProtocolVersion4MinimumAsPerRfc4821: Self = MaximumSegmentSize(NetworkEndianU16::from_network_endian([0x04, 0x00]));
	
	/// RFC 2460 Section 5, First Paragraph: Mandates a MTU of 1280.
	///
	/// `1280 - size_of(IPv6 header) - size_of(TCP header)`,
	/// ie 1220.
	///
	/// Which is 0x03D8 in big endian.
	pub const InternetProtocolVersion6Minimum: Self = MaximumSegmentSize(NetworkEndianU16::from_network_endian([0x03, 0xD8]));
	
	/// New instance.
	#[inline(always)]
	pub const fn new(value: NetworkEndianU16) -> Self
	{
		MaximumSegmentSize(value)
	}
	
	/// To native endian.
	#[inline(always)]
	pub fn to_native_endian(self) -> u16
	{
		self.0.to_native_endian()
	}
}
