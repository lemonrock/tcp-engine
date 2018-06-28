// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// A pseudo-header.
#[repr(C, packed)]
pub struct InternetProtocolVersion6PseudoHeader
{
	source_internet_protocol_version_6_address: NetworkEndianU128,
	destination_internet_protocol_version_6_address: NetworkEndianU128,
	layer_4_packet_size: NetworkEndianU32,
	reserved: [u8; 3],
	layer_4_protocol_number: u8,
}

impl InternetProtocolVersion6PseudoHeader
{
	#[inline(always)]
	pub(crate) const fn new(source_internet_protocol_version_6_address: &NetworkEndianU128, destination_internet_protocol_version_6_address: &NetworkEndianU128, layer_4_protocol_number: u8, layer_4_packet_size: u32) -> Self
	{
		Self
		{
			source_internet_protocol_version_6_address: *source_internet_protocol_version_6_address,
			destination_internet_protocol_version_6_address: *destination_internet_protocol_version_6_address,
			layer_4_packet_size: NetworkEndianU32::from_native_endian(layer_4_packet_size),
			reserved: unsafe { zeroed() },
			layer_4_protocol_number,
		}
	}
	
	#[inline(always)]
	pub(crate) fn secure_hash(digester: &mut impl Md5Digest, source_internet_protocol_version_4_address: &NetworkEndianU32, destination_internet_protocol_version_4_address: &NetworkEndianU32, layer_4_protocol_number: u8, layer_4_packet_size: u16)
	{
		digester.input(source_internet_protocol_version_4_address.bytes());
		digester.input(destination_internet_protocol_version_4_address.bytes());
		digester.input(NetworkEndianU32::from_native_endian(layer_4_packet_size).bytes());
		digester.input(&[0, 0, 0]);
		digester.input(&[layer_4_protocol_number]);
	}
}
