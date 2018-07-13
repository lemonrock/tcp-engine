// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// A network packet.
///
/// When received, it is considered to be contiguous.
pub trait NetworkPacket
{
	#[inline(always)]
	fn internet_protocol_packet_offset(&self) -> usize;
	
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
	fn explicit_congestion_notification<Address: InternetProtocolAddress>(&self, internet_protocol_packet_offset: usize) -> ExplicitCongestionNotification
	{
		Address::explicit_congestion_notification(self.offset_into_packet_headers::<u8>(self.internet_protocol_packet_offset()))
	}
	
	#[doc(hidden)]
	#[inline(always)]
	fn offset_into_data_reference<T>(&self, offset: usize) -> &T
	{
		unsafe { & * self.offset_into_packet_headers(offset).as_ptr() }
	}
	
	/// A non-null pointer to an offset in the data.
	#[inline(always)]
	fn offset_into_data<T>(&self, offset: usize) -> NonNull<T>;
	
	
	
	// Remaining functions are for when SENDING.
	
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

/// A DPDK contiguous packet.
///
/// Probably a wrapper around NonNull<rte_mbuf>.
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct DpdkNetworkPacket
{
	rte_mbuf: NonNull<rte_mbuf>,
	
	/// Usually 14 bytes, but can be more because of VLANs, QinQ, etc.
	ethernet_frame_overhead: usize,
	
	options_overhead: u16,
	
	payload_length: u16,
}

impl NetworkPacket for DpdkNetworkPacket
{
	#[inline(always)]
	fn internet_protocol_packet_offset(&self) -> usize
	{
		self.ethernet_frame_overhead
	}
	
	#[inline(always)]
	fn layer_4_packet_offset<Address: InternetProtocolAddress>(&self) -> usize
	{
		xxx
	}
	
	/// Similar to implementation of DPDK's `rte_pktmbuf_mtod_offset()`.
	#[inline(always)]
	fn offset_into_data<T>(self, offset: usize) -> NonNull<T>
	{
		let pointer = self.buffer_address() + (self.segment_buffer_reserved_head_room() as usize) + self.offset_to_ethernet_payload + offset;
		unsafe { NonNull::new_unchecked(pointer as *mut T) }
	}
	
}

impl Drop for DpdkNetworkPacket
{
	#[inline(always)]
	fn drop(&mut self)
	{
		unsafe { rust_rte_pktmbuf_free(self.pointer()) }
	}
}

impl DpdkNetworkPacket
{
	fn internet_protocol_version_6_packet(&mut self)
	{
		#[repr(C, packed)]
		struct InternetProtocolVersion6PacketHeader
		{
			/// Version, traffic class and flow label bit fields.
			version_and_traffic_class_and_flow_label: [u8; 4],
			payload_length_including_extension_headers: NetworkByteOrderEndianU16,
			next_header: u8,
			hop_limits: u8,
			source_address: NetworkEndianU128,
			destination_address: NetworkEndianU128,
			extension_header_or_payload: PhantomData<u8>,
		}
		
		let internet_protocol_version_6_packet_header = self.offset_into_data_reference::<InternetProtocolVersion6PacketHeader>(0);
		
		// only if contiguous, no .next();
		self.data_length();
		
	}
	
	
	#[inline(always)]
	fn new(rte_mbuf: NonNull<rte_mbuf>, ethernet_frame_overhead: usize, is_internet_protocol_version_6: bool) -> Result<Self, &'static str>
	{
		let mut this = Self
		{
			rte_mbuf,
			ethernet_frame_overhead,
			options_overhead: 0,
			payload_length: 0,
		};
		
		if is_internet_protocol_version_6
		{
			const MinimumInternetProtocolVersion6PacketHeaderLength: u16 = 40;
			
			if this.ethernet_frame_overhead + length < MinimumInternetProtocolVersion6PacketHeaderLength
			{
				return Err("IPv6 packet too short")
			}
			
			let extended_headers_and_payload_length = u16::from_be(*this.offset_into_data_reference::<u16>(4));
			if extended_headers_and_payload_length == 0
			{
				return Err("Jumbo Payloads are not supported")
			}
			
			
			let mut next_header_type = *this.offset_into_data_reference::<u8>(5);
			
			
			
			let mut header_pointer = x;
			
			
			
			
			let mut seen_hop_by_hop_options = false;
			let mut seen_routing = false;
			
			
			
			// See RFC 8200.
			// This logic is a bit naff and needs to be a bit more robust.
			match next_header_type
			{
				// Hop-by-Hop options.
				0 =>
				{
					if seen_hop_by_hop_options
					{
						return Err("Duplicate hop-by-hop options header")
					}
					
					// minimum of 8 bytes.
					
					if this.ethernet_frame_overhead + length < (MinimumInternetProtocolVersion6PacketHeaderLength + 8)
					{
						return Err("Hop-by-hop options header is too short")
					}
					
					
					
					seen_hop_by_hop_options = true;
				}
				
				// Destination Options (before routing header).
				60 => (),
				
				// Destination Options (before upper-layer header).
				//60 => return Err("Encapsulating Security Payload (ESP) not supported"),
				
				// Routing.
				43 =>
				{
					if seen_routing
					{
						return Err("Duplicate routing header")
					}
					
					// minimum of 2 bytes.
					
					seen_routing = true;
				}
				
				// Fragment.
				44 => return Err("Fragment header not supported"),
				
				// Authentication Header (AH).
				51 => return Err("Authentication Header (AH) not supported"),
				
				// Encapsulating Security Payload (ESP).
				52 => return Err("Encapsulating Security Payload (ESP) header not supported"),
				
				// No Next Header.
				59 => return Err("No next header"),
				
				// Mobility.
				135 => return Err("Mobility header not supported"),
				
				// Host Identity Protocol v2 (HIPv2).
				139 => return Err("Host Identity Protocol v2 (HIPv2) header not supported"),
				
				// Shim6 Protocol.
				140 => return Err("Shim6 Protocol header not supported"),
				
				253 | 254 => return Err("Experimentation headers not supported"),
			}
		}
		else
		{
			const MinimumInternetProtocolVersion6PacketHeaderLength: u16 = 20;
			
			if this.ethernet_frame_overhead + length < MinimumInternetProtocolVersion6PacketHeaderLength
			{
				return Err("IPv4 packet too short")
			}
			
			let internet_header_length = ((*this.offset_into_data_reference::<u8>(0)) & 0x0F << 2) as u16;
			let total_length = u16::from_be(*this.offset_into_data_reference::<u16>(2));
			this.options_overhead = internet_header_length - 20;
			this.payload_length = (internet_header_length - total_length);
		}
		
		Ok(this)
	}
	
	#[inline(always)]
	fn buffer_address(&self) -> usize
	{
		self.reference().buf_addr as usize
	}
	
	/// Data length.
	///
	/// Amount of data 'payload' in segment buffer, always equal to or less than `segment_buffer_length()`.
	///
	/// Is equivalent to `self.segment_buffer_length() - self.segment_buffer_reserved_head_room() - self.segment_buffer_tail_room()`.
	///
	/// Also known as `data_len`.
	#[inline(always)]
	fn data_length(&self) -> u16
	{
		self.reference().data_len
	}
	
	/// Segment buffer length.
	///
	/// Also known as `buf_len`.
	///
	/// Size of this buffer.
	#[inline(always)]
	fn segment_buffer_length(&self) -> u16
	{
		self.reference().buf_len
	}
	
	/// Head room.
	///
	/// The length of the part at the start of the segment buffer that is reserved for header data.
	///
	/// The actual data 'payload' starts after this offset in the segment buffer.
	#[inline(always)]
	fn segment_buffer_reserved_head_room(&self) -> u16
	{
		self.reference().data_off
	}
	
	/// Tail room.
	///
	/// The amount of space (unused bytes) at the end of the segment buffer in this packet that could be used for data 'payload'.
	#[inline(always)]
	fn segment_buffer_tail_room(&self) -> u16
	{
		let packet = self.reference();
		let tail_offset = self.segment_buffer_reserved_head_room() + self.data_length();
		self.segment_buffer_length() - tail_offset
	}
	
	#[inline(always)]
	fn reference(&self) -> &rte_mbuf
	{
		unsafe { & * self.pointer() }
	}
	
	#[inline(always)]
	fn pointer(&self) -> *mut rte_mbuf
	{
		self.rte_mbuf.as_ptr()
	}
}
