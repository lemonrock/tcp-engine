// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Modelled as a packed 4-byte array rather than an u32 because (a) it is not native endian and (b) its alignment is not necessary 4 bytes (it's actually 1).
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(C, packed)]
pub struct NetworkEndianU32([u8; NetworkEndianU32::AddressLength]);

impl PartialOrd for NetworkEndianU32
{
	#[inline(always)]
	fn partial_cmp(&self, other: &Rhs) -> Option<Ordering>
	{
		u32::from_be(u32::from_bytes(self.0)).partial_cmp(u32::from_be(u32::from_bytes(other.0)))
	}
}

impl Ord for NetworkEndianU32
{
	#[inline(always)]
	fn cmp(&self, other: &Rhs) -> Ordering
	{
		u32::from_be(u32::from_bytes(self.0)).cmp(u32::from_be(u32::from_bytes(other.0)))
	}
}

impl NetworkEndian for NetworkEndianU32
{
	#[inline(always)]
	fn bytes(&self) -> &[u8]
	{
		&self.0[..]
	}
}

impl InternetProtocolAddress for NetworkEndianU32
{
	const MinimumPathMaximumTransmissionUnitSize: u16 = 68;
	
	#[cfg(feature = "rfc-4821-minimum-ipv4-path-mtu")] const DefaultPathMaximumTransmissionUnitSize: u16 = 1024;
	#[cfg(not(feature = "rfc-4821-minimum-ipv4-path-mtu"))] const DefaultPathMaximumTransmissionUnitSize: u16 = 576;
	
	#[cfg(feature = "increase-ipv4-mss-acceptable-minimum-to-1024")] const SmallestAcceptableMaximumSegmentSizeOption: MaximumSegmentSizeOption = MaximumSegmentSizeOption::InternetProtocolVersion4MinimumAsPerRfc4821;
	#[cfg(not(feature = "increase-ipv6-mss-acceptable-minimum-to-1024"))] const SmallestAcceptableMaximumSegmentSizeOption: MaximumSegmentSizeOption = MaximumSegmentSizeOption::InternetProtocolVersion4Minimum;
	
	const DefaultMaximumSegmentSizeOptionIfNoneSpecified: MaximumSegmentSizeOption = Self::SmallestAcceptableMaximumSegmentSizeOption;
	
	const SmallestLayer3HeaderSize: u16 = 20;
	
	const AddressLength: usize = 4;
	
	const OffsetOfAddressInsideInternetProtocolPacket: usize = 12;
	
	#[inline(always)]
	fn explicit_congestion_notification(start_of_layer_3_packet: NonNull<u8>) -> ExplicitCongestionNotification
	{
		const Offset: isize = 1;
		
		let traffic_class = unsafe { *start_of_layer_3_packet.as_ptr().offset(1) };
		
		unsafe { transmute(traffic_class & 0b11) }
	}
	
	#[inline(always)]
	fn sorted_common_maximum_segment_sizes() -> &'static [u16]
	{
		// Values are chosen based on research done in the paper "An Analysis of TCP Maximum Segment Sizes", Shane Alcock and Richard Nelson, 2011.
		// Table is from FreeBSD.
		&[
			// 0∙2%
			216,

			// 0∙3%
			536,

			// 5%
			1200,

			// 7%
			1360,

			// 7%
			1400,

			// 20%
			1440,

			// 15%
			1452,

			// 45%
			1460,
		]
		// An alternative table from Linux, based on the same research paper.
		//&[
		//	// Values lower than 536 are rare (< 0∙2%)
		//	536,
		//
		//	// Values in the range 537 - 1299 inclusive account for < 1∙5% of observations.
		//	1300,
		//
		//	// Values in the range 1300 - 1349 inclusive account for between 15% to 20% of observations.
		//	// Most of these values are probably due to the use of PPPoE.
		//	1440,
		//
		//	// The most common value, between 30% - 46% of all connections. Values in excess of this are very rare (< 0∙04%)
		//	1460,
		//]
	}
	
	#[inline(always)]
	fn calculate_internet_protocol_tcp_check_sum(source_internet_protocol_address: &Self, destination_internet_protocol_address: &Self, internet_packet_payload_pointer: NonNull<u8>, layer_4_packet_size: usize) -> Rfc1141CompliantCheckSum
	{
		Rfc1141CompliantCheckSum::internet_protocol_version_4_tcp_check_sum(source_internet_protocol_address, destination_internet_protocol_address, internet_packet_payload_pointer, layer_4_packet_size)
	}
	
	#[inline(always)]
	fn write_to_hash<H: Hasher>(&self, hasher: &mut H)
	{
		hasher.write_u32(unsafe { transmute_copy(&self.0) })
	}
	
	type PseudoHeader = InternetProtocolVersion4PseudoHeader;
	
	#[inline(always)]
	fn pseudo_header(source_internet_protocol_address: &Self, destination_internet_protocol_address: &Self, layer_4_protocol_number: u8, layer_4_packet_size: usize) -> Self::PseudoHeader
	{
		Self::PseudoHeader::new(source_internet_protocol_address, destination_internet_protocol_address, layer_4_protocol_number, layer_4_packet_size as u16)
	}
	
	#[inline(always)]
	fn secure_hash(digester: &mut impl Md5Digest, source_internet_protocol_address: &Self, destination_internet_protocol_address: &Self, layer_4_protocol_number: u8, layer_4_packet_size: usize)
	{
		Self::PseudoHeader::secure_hash(digester, source_internet_protocol_address, destination_internet_protocol_address, layer_4_protocol_number, layer_4_packet_size as u16)
	}
}

impl NetworkEndianU32
{
	pub(crate) const Zero: Self = NetworkEndianU32([0, 0, 0, 0]);
	
	pub(crate) const TopBitSetOnly: Self = NetworkEndianU32([128, 0, 0, 0]);
	
	#[inline(always)]
	pub(crate) const fn from_network_endian(network_endian: [u8; 4]) -> Self
	{
		NetworkEndianU32(network_endian)
	}
	
	#[inline(always)]
	pub(crate) fn to_native_endian(self) -> u32
	{
		u32::from_be(self.big_endian_from_bytes())
	}
	
	#[inline(always)]
	pub(crate) fn from_native_endian(native_endian: u32) -> Self
	{
		NetworkEndianU32(native_endian.to_be().to_bytes())
	}
	
	#[inline(always)]
	pub(crate) fn is_not_zero(self) -> bool
	{
		self != Self::Zero
	}
	
	#[inline(always)]
	fn big_endian_from_bytes(self) -> u32
	{
		u32::from_bytes(self.0)
	}
}
