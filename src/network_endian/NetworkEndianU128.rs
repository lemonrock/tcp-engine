// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Modelled as a packed 16-byte array rather than u128 u32 because (a) it is not native endian and (b) its alignment is not necessary 16 bytes (it's actually 1).
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(C, packed)]
pub(crate) struct NetworkEndianU128([u8; 16]);

impl PartialOrd for NetworkEndianU128
{
	#[inline(always)]
	fn partial_cmp(&self, other: &Rhs) -> Option<Ordering>
	{
		u128::from_be(u128::from_bytes(self.0)).partial_cmp(u128::from_be(u128::from_bytes(other.0)))
	}
}

impl Ord for NetworkEndianU128
{
	#[inline(always)]
	fn cmp(&self, other: &Rhs) -> Ordering
	{
		u128::from_be(u128::from_bytes(self.0)).cmp(u128::from_be(u128::from_bytes(other.0)))
	}
}

impl NetworkEndian for NetworkEndianU128
{
	#[inline(always)]
	fn bytes(&self) -> &[u8]
	{
		&self.0[..]
	}
}

impl InternetProtocolAddress for NetworkEndianU128
{
	const MinimumPathMaximumTransmissionUnitSize: u16 = 1280;
	
	const DefaultPathMaximumTransmissionUnitSize: u16 = Self::MinimumPathMaximumTransmissionUnitSize;
	
	#[cfg(feature = "increase-ipv6-mss-acceptable-minimum-to-1220")] const SmallestAcceptableMaximumSegmentSizeOption: MaximumSegmentSizeOption = MaximumSegmentSizeOption::InternetProtocolVersion6Minimum;
	#[cfg(not(feature = "increase-ipv6-mss-acceptable-minimum-to-1220"))] const SmallestAcceptableMaximumSegmentSizeOption: MaximumSegmentSizeOption = MaximumSegmentSizeOption::Default;
	
	const DefaultMaximumSegmentSizeOptionIfNoneSpecified: MaximumSegmentSizeOption = Self::SmallestAcceptableMaximumSegmentSizeOption;
	
	const SmallestLayer3HeaderSize: u16 = 40;
	
	const OffsetOfAddressInsideInternetProtocolPacket: usize = 8;
	
	#[inline(always)]
	fn sorted_common_maximum_segment_sizes() -> &'static [u16]
	{
		// Values are chosen based on RFC 2460, Section 8.3:
		//
		// "MSS must be computed as the maximum packet size minus 60".
		//
		// Since the minimum MTU is 1280, the smallest possible MSS is 1220.
		//
		// Remaining values guess-timated.
		&[
			Self::DefaultPathMaximumTransmissionUnitSize - Self::MaximumTransmissionUnitToTcpMaximumSegmentSizeReduction,
			1480 - Self::MaximumTransmissionUnitToTcpMaximumSegmentSizeReduction,
			1500 - Self::MaximumTransmissionUnitToTcpMaximumSegmentSizeReduction,
			9000 - Self::MaximumTransmissionUnitToTcpMaximumSegmentSizeReduction,
			// TODO: Maximum ethernet MTU
		]
	}
	
	#[inline(always)]
	fn calculate_internet_protocol_tcp_check_sum(source_internet_protocol_address: &Self, destination_internet_protocol_address: &Self, internet_packet_payload_pointer: NonNull<u8>, layer_4_packet_size: usize) -> Rfc1071CompliantCheckSum
	{
		Rfc1071CompliantCheckSum::internet_protocol_version_6_tcp_check_sum(source_internet_protocol_address, destination_internet_protocol_address, internet_packet_payload_pointer, layer_4_packet_size)
	}
	
	#[inline(always)]
	fn write_to_hash<H: Hasher>(&self, hasher: &mut H)
	{
		hasher.write_u128(unsafe { transmute_copy(&self.0) })
	}
	
	type PseudoHeader = InternetProtocolVersion6PseudoHeader;
	
	#[inline(always)]
	fn pseudo_header(source_internet_protocol_address: &Self, destination_internet_protocol_address: &Self, layer_4_protocol_number: u8, layer_4_packet_size: usize) -> Self::PseudoHeader
	{
		Self::PseudoHeader::new(source_internet_protocol_address, destination_internet_protocol_address, layer_4_protocol_number, layer_4_packet_size as u32)
	}
	
	#[inline(always)]
	fn secure_hash(digester: &mut impl Md5Digest, source_internet_protocol_address: &Self, destination_internet_protocol_address: &Self, layer_4_protocol_number: u8, layer_4_packet_size: usize)
	{
		Self::PseudoHeader::secure_hash(digester, source_internet_protocol_address, destination_internet_protocol_address, layer_4_protocol_number, layer_4_packet_size as u32)
	}
}

impl NetworkEndianU128
{
	const SmallestTcpHeader: u16 = size_of::<TcpFixedHeader>() as u16;
	
	const MaximumTransmissionUnitToTcpMaximumSegmentSizeReduction: u16 = Self::SmallestLayer3HeaderSize + Self::SmallestTcpHeader;
	
	#[inline(always)]
	pub(crate) const fn from_network_endian(network_endian: [u8; 16]) -> Self
	{
		NetworkEndianU128(network_endian)
	}

	#[inline(always)]
	pub(crate) fn to_native_endian(self) -> u128
	{
		u128::from_be(self.big_endian_from_bytes())
	}

	#[inline(always)]
	pub(crate) fn from_native_endian(native_endian: u128) -> Self
	{
		NetworkEndianU128(native_endian.to_be().to_bytes())
	}

	#[inline(always)]
	fn big_endian_from_bytes(self) -> u128
	{
		u128::from_bytes(self.0)
	}
}
