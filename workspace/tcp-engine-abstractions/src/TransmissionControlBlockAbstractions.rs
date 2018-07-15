// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Abstractions so that a TransmissionControlBlock can be used with different platforms and network stacks.
pub trait TransmissionControlBlockAbstractions: Sized
{
	/// Type of tcp receiver creator.
	type EventsReceiverCreator: TransmissionControlBlockEventsReceiverCreator;
	
	/// Internet Protocol Address.
	type Address: InternetProtocolAddress;
	
	/// The type of contiguous packet created.
	type Packet: NetworkPacket;
	
	/// Assumes the packet creator already has references to source and destination ethernet addresses.
	///
	/// Returns a reference to the packet and a pointer to the layer 4 payload.
	///
	/// If it can't create a packet, returns an error.
	///
	/// A newly created packet should have its ECN bits set to zero (0).
	///
	/// RFC 7323, Section 5.7 requires that Internet Protocol version 4 packets have the Do Not Fragment (DF) bit set in their header to provide maximum protection for the PAWS algorithm.
	#[inline(always)]
	fn create_packet(&self, source_internet_protocol_address: &Self::Address, destination_internet_protocol_address: &Self::Address, layer_4_protocol: u8) -> Result<(Self::Packet, NonNull<u8>), ()>;
	
	/// Assumes the packet creator already has references to source and destination ethernet addresses.
	///
	/// Internally, the packet creator must flip the source and destination internet protocol addresses (and probably also the ethernet addresses).
	///
	/// Reuses a reference to an existing packet; this is because allocation (eg by malloc) of a new packet can be relatively expensive, and also, under heavy load, memory might not be easy to come by.
	///
	/// A reused packet should have its ECN bits set to zero (0).
	///
	/// Returns a pointer to the layer 4 payload.
	#[inline(always)]
	fn reuse_packet_reversing_source_and_destination_addresses(&self, layer_4_protocol: u8, packet: Self::Packet) -> NonNull<u8>;
	
	
	/// Enqueue a packet for outbound transmission.
	///
	/// If full, then the queue should try to transmit to the network card as many packets as possible, eg using DPDK `TransmitQueue::transmit_packets_in_a_burst`. In practice, an implementation is free to transmit whenever it wants; it need not maintain an outbound queue (although that is likely to be inefficient).
	///
	/// This may require the use of an UnsafeCell, RefCell or the like for internal mutation.
	///
	/// Sending or enqueuing a packet should eventually result in its reference count being decremented. In DPDK, this is done by the poll mode driver.
	#[inline(always)]
	fn enqueue_packet_transmitting_if_full(&self, packet: Self::Packet);
	
	/// Immediately transmit all enqueue packets.
	#[inline(always)]
	fn transmit_all_enqueued_packets(&self);
	
	
	
	#[doc(hidden)]
	#[inline(always)]
	fn maximum_segment_size_to_send_to_remote(&self, their_maximum_segment_size_options: Option<MaximumSegmentSizeOption>, remote_internet_protocol_address: &Self::Address) -> u16
	{
		let their_maximum_segment_size = match their_maximum_segment_size_options
		{
			None => Self::Address::DefaultMaximumSegmentSizeIfNoneSpecified.to_native_endian(),
			
			Some(their_maximum_segment_size_option) => their_maximum_segment_size_option.to_native_endian(),
		};
		
		self.maximum_segment_size_to_send_to_remote_u16(their_maximum_segment_size, remote_internet_protocol_address)
	}
	
	#[doc(hidden)]
	#[inline(always)]
	fn maximum_segment_size_to_send_to_remote_u16(&self, their_maximum_segment_size: u16, remote_internet_protocol_address: &Self::Address) -> u16
	{
		min(their_maximum_segment_size, self.maximum_segment_size_without_fragmentation(remote_internet_protocol_address))
	}
	
	#[doc(hidden)]
	#[inline(always)]
	fn maximum_segment_size_without_fragmentation(&self, remote_internet_protocol_address: &Self::Address) -> u16
	{
		// RFC 6691, Section 2: "When calculating the value to put in the TCP MSS option, the MTU value SHOULD be decreased by only the size of the fixed IP and TCP headers and SHOULD NOT be decreased to account for any possible IP or TCP options; conversely, the sender MUST reduce the TCP data length to account for any IP or TCP options that it is including in the packets that it sends.
		// ... the goal is to avoid IP-level fragmentation of TCP packets".
		
		let path_maximum_transmission_unit = self.current_path_maximum_transmission_unit(remote_internet_protocol_address);
		
		debug_assert!(path_maximum_transmission_unit >= Self::Address::MinimumPathMaximumTransmissionUnitSize, "path_maximum_transmission_unit '{}' is less than MinimumPathMaximumTransmissionUnitSize '{}'", path_maximum_transmission_unit, Self::Address::MinimumPathMaximumTransmissionUnitSize);
		
		let minimum_overhead_excluding_ip_options_ip_headers_and_tcp_options = Self::Address::SmallestLayer3HeaderSize + (size_of::<TcpFixedHeader>() as u16);
		
		debug_assert!(path_maximum_transmission_unit > minimum_overhead_excluding_ip_options_ip_headers_and_tcp_options, "path_maximum_transmission_unit '{}' is equal to or less than packet_headers_length_excluding_tcp_options '{}'", path_maximum_transmission_unit, minimum_overhead_excluding_ip_options_ip_headers_and_tcp_options);
		path_maximum_transmission_unit - minimum_overhead_excluding_ip_options_ip_headers_and_tcp_options
	}
	
	/// Used specifically when setting TCP maximum segment size option.
	///
	/// Intended to be implemented as a combination of a cache of `PathMTU` and a set of known, fixed values, perhaps implemented using a routing table such as `IpLookupTable` (in the crate `treebitmap`).
	///
	/// A suitable cache is `LeastRecentlyUsedCacheWithExpiry`.
	///
	/// If there is no specific entry in the cache, an implementation can use `Self::Address::DefaultPathMaximumTransmissionUnitSize`.
	///
	/// Note also the advice of RFC 2923 Section 2.3: "The MSS should be determined based on the MTUs of the interfaces on the system".
	#[inline(always)]
	fn current_path_maximum_transmission_unit(&self, remote_internet_protocol_address: &Self::Address) -> u16;
}
