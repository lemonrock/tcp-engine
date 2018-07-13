// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// A network packet.
///
/// When received, it is considered to be contiguous.
pub trait NetworkPacket
{
	/// Internet protocol packet offset.
	#[inline(always)]
	fn internet_protocol_packet_offset(&self) -> usize;
	
	/// Layer 3 packet offset.
	#[inline(always)]
	fn layer_4_packet_offset<Address: InternetProtocolAddress>(&self) -> usize;
	
	#[doc(hidden)]
	#[inline(always)]
	fn source_internet_protocol_address<Address: InternetProtocolAddress>(&self) -> &Address
	{
		self.offset_into_packet_headers_reference::<Address>(self.internet_protocol_packet_offset() + Address::OffsetOfAddressInsideInternetProtocolPacket)
	}
	
	#[doc(hidden)]
	#[inline(always)]
	fn explicit_congestion_notification<Address: InternetProtocolAddress>(&self) -> ExplicitCongestionNotification
	{
		Address::explicit_congestion_notification(self.offset_into_packet_headers::<u8>(self.internet_protocol_packet_offset()))
	}
	
	#[doc(hidden)]
	#[inline(always)]
	fn offset_into_packet_headers_reference<T>(&self, offset: usize) -> &T
	{
		unsafe { & * self.offset_into_packet_headers(offset).as_ptr() }
	}
	
	/// A non-null pointer to an offset in the data.
	#[inline(always)]
	fn offset_into_packet_headers<T>(&self, offset: usize) -> NonNull<T>;
	
	
	
	// Remaining functions are for when SENDING.
	
	/// ?
	fn attach_payload(&self);
	// rust_rte_pktmbuf_attach_extbuf(); - but a bit more complex.
	
	/// This is the size of the options of the IPv4 header or the size of the IPv6 header extension headers.
	///
	/// It does not include the ethernet frame header overhead or the trailing ethernet frame check sequence (FCS, also known as Ethernet CRC).
	#[inline(always)]
	fn internet_protocol_options_or_extension_headers_additional_overhead<Address: InternetProtocolAddress>(&self) -> u16;
	
	/// Sets IPv4 total_length or for IPv6 modifies payload_length_including_extension_headers in a packet.
	#[inline(always)]
	fn set_layer_4_payload_length<Address: InternetProtocolAddress>(&mut self, layer_4_payload_length: usize);
	
	/// Sets the explicit congestion notification (ECN) code point to ECT 0, 0b10.
	#[inline(always)]
	fn set_explicit_congestion_notification_state_ect_0<Address: InternetProtocolAddress>(&mut self);
}
