// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// An Internet Protocol version 4 or version 6 address handling stub.
pub trait InternetProtocolAddress: NetworkEndian
{
	/// Minimum "PathMTU" (or just "MTU").
	///
	/// 68 for Internet Protocol version 4, although practically, 254 (AX.25 packet radio) is the smallest known.
	/// 1280 for Internet Protocol version 6.
	const MinimumPathMaximumTransmissionUnitSize: u16;
	
	/// Default "PathMTU" (or just "MTU").
	///
	/// 576 for Internet Protocol version 4, although RFC 4821 Section 7.2 Paragraph 2: "Given today's technologies, a value of 1024 bytes is probably safe enough suggests that it's "probably safe enough" to assume minimal MTU of 1,024".
	/// 1280 for Internet Protocol version 6.
	const DefaultPathMaximumTransmissionUnitSize: u16;
	
	/// Minimum TCP maximum segment size option.
	///
	/// 216 for Internet Protocol version 4 (based on the "MTU" of AX.25 packet radio).
	/// 1220 for Internet Protocol version 6 when the option "increase-ipv6-mss-default-to-1220" is specified, otherwise 536.
	const SmallestAcceptableMaximumSegmentSize: MaximumSegmentSize;
	
	/// Default TCP maximum segment size option.
	///
	/// Strictly speaking, this should always be 536, however, on IPv6, it really should have a floor which is the same as SmallestAcceptableMaximumSegmentSize (1220).
	const DefaultMaximumSegmentSizeIfNoneSpecified: MaximumSegmentSize;
	
	/// Smallest header size.
	///
	/// 20 for Internet Protocol version 4.
	/// 40 for Internet Protocol version 6.
	const SmallestLayer3HeaderSize: u16 = 40;
	
	/// Address length in octets.
	///
	/// * 4 for Internet Protocol version 4.
	/// * 16 for Internet Protocol version 6.
	const AddressLength: usize;
	
	/// Excludes the ethernet header (or any other layer 2 transport).
	///
	/// * 12 for Internet Protocol version 4.
	/// * 8 for Internet Protocol version 6.
	const OffsetOfAddressInsideInternetProtocolPacket: usize;
	
	/// Extracts Explicit Congestion Notification (ECN).
	#[inline(always)]
	fn explicit_congestion_notification(start_of_layer_3_packet: NonNull<u8>) -> ExplicitCongestionNotification;
	
	/// A sorted table of maximum segment sizes.
	///
	/// Should not occupy more than 8 entries.
	#[inline(always)]
	fn sorted_common_maximum_segment_sizes() -> &'static [u16];
	
	/// A sorted table of window scales.
	///
	/// Should not occupy more than 7 entries.
	#[inline(always)]
	fn sorted_common_window_scales() -> &'static [u8]
	{
		// Distribution based on "WSCALE values histograms", Allman, 2012.
		// Note that values 3, 5 and 9 - 14 are absent as they are very rare.
		&[
			// 10% by host, 11% by connection.
			0,
			
			// 10% by host, 4% by connection.
			1,
			
			// 35% by host, 5% by connection.
			2,
			
			// 5% by host, 5% by connection.
			4,
			
			// 6% by host, 18% by connection.
			6,
			
			// 14% by host, 49% by connection.
			7,
			
			// 10% by host, 3% by connection.
			8,
		]
	}
	
	#[doc(hidden)]
	#[inline(always)]
	fn decode_maximum_segment_size_index(data: u32) -> Result<u16, ()>
	{
		let table = Self::sorted_common_maximum_segment_sizes();
		debug_assert_ne!(table.len(), 0, "sorted_common_maximum_segment_sizes table can not be empty");
		debug_assert!(table.len() <= 8, "sorted_common_maximum_segment_sizes table can not have more than 8 entries");
		
		let index = (data & 0x00FF) as usize;
		
		if unlikely!(index >= table.len())
		{
			Err(())
		}
		else
		{
			Ok(*unsafe { table.get_unchecked(index) })
		}
	}
	
	/// Calculates an internet protocol TCP check sum.
	#[inline(always)]
	fn calculate_internet_protocol_tcp_check_sum(source_internet_protocol_address: &Self, destination_internet_protocol_address: &Self, internet_packet_payload_pointer: NonNull<u8>, layer_4_packet_size: usize) -> Rfc1141CompliantCheckSum;
	
	#[doc(hidden)]
	#[inline(always)]
	fn secure_hash(digester: &mut impl Digest, source_internet_protocol_address: &Self, destination_internet_protocol_address: &Self, layer_4_protocol_number: Layer4ProtocolNumber, layer_4_packet_size: usize);
}

impl InternetProtocolAddress for NetworkEndianU32
{
	const MinimumPathMaximumTransmissionUnitSize: u16 = 68;
	
	#[cfg(feature = "rfc-4821-minimum-ipv4-path-mtu")] const DefaultPathMaximumTransmissionUnitSize: u16 = 1024;
	#[cfg(not(feature = "rfc-4821-minimum-ipv4-path-mtu"))] const DefaultPathMaximumTransmissionUnitSize: u16 = 576;
	
	#[cfg(feature = "increase-ipv4-mss-acceptable-minimum-to-1024")] const SmallestAcceptableMaximumSegmentSize: MaximumSegmentSize = MaximumSegmentSize::InternetProtocolVersion4MinimumAsPerRfc4821;
	#[cfg(not(feature = "increase-ipv6-mss-acceptable-minimum-to-1024"))] const SmallestAcceptableMaximumSegmentSize: MaximumSegmentSize = MaximumSegmentSize::InternetProtocolVersion4Minimum;
	
	const DefaultMaximumSegmentSizeIfNoneSpecified: MaximumSegmentSize = Self::SmallestAcceptableMaximumSegmentSize;
	
	const SmallestLayer3HeaderSize: u16 = 20;
	
	const AddressLength: usize = 4;
	
	const OffsetOfAddressInsideInternetProtocolPacket: usize = 12;
	
	#[inline(always)]
	fn explicit_congestion_notification(start_of_layer_3_packet: NonNull<u8>) -> ExplicitCongestionNotification
	{
		const Offset: isize = 1;
		
		let traffic_class = unsafe { *start_of_layer_3_packet.as_ptr().offset(Offset) };
		
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
		InternetProtocolVersion4PseudoHeader::internet_protocol_version_4_tcp_check_sum(source_internet_protocol_address, destination_internet_protocol_address, internet_packet_payload_pointer, layer_4_packet_size)
	}
	
	#[inline(always)]
	fn secure_hash(digester: &mut impl Digest, source_internet_protocol_address: &Self, destination_internet_protocol_address: &Self, layer_4_protocol_number: Layer4ProtocolNumber, layer_4_packet_size: usize)
	{
		InternetProtocolVersion4PseudoHeader::secure_hash(digester, source_internet_protocol_address, destination_internet_protocol_address, layer_4_protocol_number, layer_4_packet_size as u16)
	}
}

impl InternetProtocolAddress for NetworkEndianU128
{
	const MinimumPathMaximumTransmissionUnitSize: u16 = 1280;
	
	const DefaultPathMaximumTransmissionUnitSize: u16 = Self::MinimumPathMaximumTransmissionUnitSize;
	
	#[cfg(feature = "increase-ipv6-mss-acceptable-minimum-to-1220")] const SmallestAcceptableMaximumSegmentSize: MaximumSegmentSize = MaximumSegmentSize::InternetProtocolVersion6Minimum;
	#[cfg(not(feature = "increase-ipv6-mss-acceptable-minimum-to-1220"))] const SmallestAcceptableMaximumSegmentSize: MaximumSegmentSize = MaximumSegmentSize::Default;
	
	const DefaultMaximumSegmentSizeIfNoneSpecified: MaximumSegmentSize = Self::SmallestAcceptableMaximumSegmentSize;
	
	const SmallestLayer3HeaderSize: u16 = 40;
	
	const AddressLength: usize = 16;
	
	const OffsetOfAddressInsideInternetProtocolPacket: usize = 8;
	
	#[inline(always)]
	fn explicit_congestion_notification(start_of_layer_3_packet: NonNull<u8>) -> ExplicitCongestionNotification
	{
		const TrafficClassBits: u32 = 20;
		const TrafficClassMask: u32 = 0b1111_1111 << TrafficClassBits;
		
		let version_traffic_class_flow_label = u32::from_be(unsafe { *(start_of_layer_3_packet.as_ptr() as *mut u32) });
		let traffic_class = ((version_traffic_class_flow_label & TrafficClassMask) >> TrafficClassBits) as u8;
		
		unsafe { transmute(traffic_class & 0b11) }
	}
	
	#[inline(always)]
	fn sorted_common_maximum_segment_sizes() -> &'static [u16]
	{
		const SmallestTcpHeader: u16 = 20;
		
		const MaximumTransmissionUnitToTcpMaximumSegmentSizeReduction: u16 = NetworkEndianU128::SmallestLayer3HeaderSize + SmallestTcpHeader;
		
		
		// Values are chosen based on RFC 2460, Section 8.3:
		//
		// "MSS must be computed as the maximum packet size minus 60".
		//
		// Since the minimum MTU is 1280, the smallest possible MSS is 1220.
		//
		// Remaining values guess-timated.
		&[
			Self::DefaultPathMaximumTransmissionUnitSize - MaximumTransmissionUnitToTcpMaximumSegmentSizeReduction,
			1480 - MaximumTransmissionUnitToTcpMaximumSegmentSizeReduction,
			1500 - MaximumTransmissionUnitToTcpMaximumSegmentSizeReduction,
			9000 - MaximumTransmissionUnitToTcpMaximumSegmentSizeReduction,
		]
	}
	
	#[inline(always)]
	fn calculate_internet_protocol_tcp_check_sum(source_internet_protocol_address: &Self, destination_internet_protocol_address: &Self, internet_packet_payload_pointer: NonNull<u8>, layer_4_packet_size: usize) -> Rfc1141CompliantCheckSum
	{
		InternetProtocolVersion6PseudoHeader::internet_protocol_version_6_tcp_check_sum(source_internet_protocol_address, destination_internet_protocol_address, internet_packet_payload_pointer, layer_4_packet_size)
	}
	
	#[inline(always)]
	fn secure_hash(digester: &mut impl Digest, source_internet_protocol_address: &Self, destination_internet_protocol_address: &Self, layer_4_protocol_number: Layer4ProtocolNumber, layer_4_packet_size: usize)
	{
		InternetProtocolVersion6PseudoHeader::secure_hash(digester, source_internet_protocol_address, destination_internet_protocol_address, layer_4_protocol_number, layer_4_packet_size as u32)
	}
}
