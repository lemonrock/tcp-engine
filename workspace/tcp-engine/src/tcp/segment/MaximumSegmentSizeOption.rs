// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// RFC 6691, Section 2: "When calculating the value to put in the TCP MSS option, the MTU value SHOULD be decreased by only the size of the fixed IP and TCP headers and SHOULD NOT be decreased to account for any possible IP or TCP options".
///
/// Maximum Segment Size is also called 'MSS'.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
#[repr(C, packed)]
pub(crate) struct MaximumSegmentSizeOption(pub(crate) NetworkEndianU16);

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
			None => TCBA::Address::DefaultMaximumSegmentSizeIfNoneSpecified,
			
			Some(their_maximum_segment_size_option) => their_maximum_segment_size_option.0,
		};
		
		Self::maximum_segment_size_to_send_to_remote_u16(maximum_segment_size_option.to_native_endian(), interface, remote_internet_protocol_address)
	}
	
	#[inline(always)]
	pub(crate) fn maximum_segment_size_to_send_to_remote_u16<TCBA: TransmissionControlBlockAbstractions>(their_maximum_segment_size: u16, interface: &Interface<TCBA>, remote_internet_protocol_address: &TCBA::Address)
	{
		min(their_maximum_segment_size, interface.our_current_maximum_segment_size_without_fragmentation(remote_internet_protocol_address))
	}
}
