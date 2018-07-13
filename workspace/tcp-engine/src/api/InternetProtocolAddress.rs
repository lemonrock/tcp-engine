// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
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
	const SmallestAcceptableMaximumSegmentSizeOption: MaximumSegmentSizeOption;
	
	/// Default TCP maximum segment size option.
	///
	/// Strictly speaking, this should always be 536, however, on IPv6, it really should have a floor which is the same as SmallestAcceptableMaximumSegmentSizeOption (1220).
	const DefaultMaximumSegmentSizeOptionIfNoneSpecified: MaximumSegmentSizeOption;
	
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
		
		if unlikely(index >= table.len())
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
	fn write_to_hash<H: Hasher>(&self, hasher: &mut H);
	
	#[doc(hidden)]
	type PseudoHeader: Sized;
	
	#[doc(hidden)]
	#[inline(always)]
	fn pseudo_header(source_internet_protocol_address: &Self, destination_internet_protocol_address: &Self, layer_4_protocol_number: u8, layer_4_packet_size: usize) -> Self::PseudoHeader;
	
	#[doc(hidden)]
	#[inline(always)]
	fn secure_hash(digester: &mut impl Md5Digest, source_internet_protocol_address: &Self, destination_internet_protocol_address: &Self, layer_4_protocol_number: u8, layer_4_packet_size: usize);
}

