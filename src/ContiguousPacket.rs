// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// A contiguous packet.
pub trait ContiguousPacket: Copy
{
	/// Obtains the source Internet Protocol (IP) version 4 or version 6 address.
	#[inline(always)]
	fn source_internet_protocol_address<Address: InternetProtocolAddress>(self) -> &Address;
	
	/// Obtains the source Internet Protocol (IP) version 4 or version 6 address.
	#[inline(always)]
	fn destination_internet_protocol_address<Address: InternetProtocolAddress>(self) -> &Address;
	
	/// Override this to make use of the explanation, for example, by putting it into a circular ring buffer for debugging purposes.
	#[inline(always)]
	fn drop_packet(self, _explanation: &'static str)
	{
		self.free_packet()
	}
	
	/// DPDK: `PacketBufferExt.free_direct_contiguous_packet()`.
	#[inline(always)]
	fn free_packet(self);
	
	/// DPDK: `PacketBufferExt.packet_length_if_contiguous()`.
	#[inline(always)]
	fn packet_length(self) -> usize;
	
	/// DPDK: `PacketBufferExt.offset_into_data()`.
	#[inline(always)]
	fn offset_into_data<T>(self, offset: usize) -> NonNull<T>;
	
	/// This is the size of the options of the IPv4 header or the size of the IPv6 header extension headers.
	///
	/// It does not include the ethernet frame header overhead or the trailing ethernet frame check sequence (CRC).
	#[inline(always)]
	fn internet_protocol_options_or_extension_headers_additional_overhead(self) -> u16;
	
	/// Sets IPv4 total_length or for IPv6 modifies payload_length_including_extension_headers in a packet.
	#[inline(always)]
	fn set_layer_4_payload_length<Address: InternetProtocolAddress>(self, layer_4_payload_length: usize);
	
	/// Obtains the explicit congestion notification of this packet.
	#[inline(always)]
	fn explicit_congestion_notification<Address: InternetProtocolAddress>(self) -> ExplicitCongestionNotification;
	
	/// Sets the explicit congestion notification (ECN) code point to ECT 0, 0b10.
	#[inline(always)]
	fn set_explicit_congestion_notification_state_ect_0<Address: InternetProtocolAddress>(self);
	
	/// Sets the explicit congestion notification (ECN) code point to 0b00.
	#[inline(always)]
	fn set_explicit_congestion_notification_state_off<Address: InternetProtocolAddress>(self);
}
