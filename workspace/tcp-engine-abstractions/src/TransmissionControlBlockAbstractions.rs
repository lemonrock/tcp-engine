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
	
	/// The type of table.
	type PMTUTable: PathMaximumTransmissionUnitTable<Self::Address>;
	
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
}
