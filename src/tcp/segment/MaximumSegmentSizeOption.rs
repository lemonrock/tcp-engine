// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// RFC 6691, Section 2: "When calculating the value to put in the TCP MSS option, the MTU value SHOULD be decreased by only the size of the fixed IP and TCP headers and SHOULD NOT be decreased to account for any possible IP or TCP options".
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

impl From<u16> for MaximumSegmentSizeOption
{
	#[inline(always)]
	fn from(value: u16) -> Self
	{
		MaximumSegmentSizeOption(NativeEndianU16::from_native_endian(value))
	}
}

impl MaximumSegmentSizeOption
{
	pub(crate) const Kind: u8 = 2;
	
	pub(crate) const KnownLength: usize = 4;
	
	/// RFC 6691 Section 2: "The MTU value SHOULD be decreased by only the size of the fixed IP and TCP headers and SHOULD NOT be decreased to account for any possible IP or TCP options".
	///
	/// In effect, for IPv4 it is `576 - size_of(IPv4 header) - size_of(TCP header)`,
	/// ie 536.
	///
	/// Which is 0x0218 in big endian.
	pub(crate) const Default: Self = MaximumSegmentSizeOption(NetworkEndianU16::from_network_endian([0x02, 0x18]));
	
	/// Based on the Link MTU of AX.25 packet radio (256) which is believed to be the smallest MTU on the internet as of 2003.
	///
	/// `256 - size_of(IPv4 header) - size_of(TCP header)`,
	/// ie 216.
	///
	/// Which is 0x00D8 in big endian.
	pub(crate) const InternetProtocolVersion4Minimum: Self = MaximumSegmentSizeOption(NetworkEndianU16::from_network_endian([0x00, 0xD8]));
	
	/// Based on RFC 4821 Section 7.2 Paragraph 2
	///
	/// `1024 - size_of(IPv4 header) - size_of(TCP header)`,
	/// ie 984.
	///
	/// Which is 0x0400 in big endian.
	pub(crate) const InternetProtocolVersion4MinimumAsPerRfc4821: Self = MaximumSegmentSizeOption(NetworkEndianU16::from_network_endian([0x04, 0x00]));
	
	/// RFC 2460 Section 5, First Paragraph: Mandates a MTU of 1280.
	///
	/// `1280 - size_of(IPv6 header) - size_of(TCP header)`,
	/// ie 1220.
	///
	/// Which is 0x03D8 in big endian.
	pub(crate) const InternetProtocolVersion6Minimum: Self = MaximumSegmentSizeOption(NetworkEndianU16::from_network_endian([0x03, 0xD8]));
	
	#[inline(always)]
	pub(crate) fn to_native_endian(self) -> u16
	{
		self.0.to_native_endian()
	}
	
	#[inline(always)]
	pub(crate) fn maximum_segment_size_to_send_to_remote<TCBA: TransmissionControlBlockAbstractions>(their_maximum_segment_size_options: Option<Self>, interface: &Interface<TCBA>, remote_internet_protocol_address: &TCBA::Address)
	{
		let maximum_segment_size_option = match their_maximum_segment_size_options
		{
			None => TCBA::Address::DefaultMaximumSegmentSizeOptionIfNoneSpecified,
			
			Some(their_maximum_segment_size) => their_maximum_segment_size,
		};
		
		Self::maximum_segment_size_to_send_to_remote_u16(maximum_segment_size_option.to_native_endian(), interface, remote_internet_protocol_address)
	}
	
	#[inline(always)]
	pub(crate) fn maximum_segment_size_to_send_to_remote_u16<TCBA: TransmissionControlBlockAbstractions>(their_maximum_segment_size: u16, interface: &Interface<TCBA>, remote_internet_protocol_address: &TCBA::Address)
	{
		min(their_maximum_segment_size, interface.our_current_maximum_segment_size_without_fragmentation(remote_internet_protocol_address))
	}
}
