// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Abstractions so that a TransmissionControlBlock can be used with different platforms and network stacks.
pub trait TransmissionControlBlockAbstractions: Sized
{
	/// Type of events receiver creator.
	type EventsReceiverCreator: TransmissionControlBlockEventsReceiverCreator;
	
	/// Internet Protocol Address.
	type Address: InternetProtocolAddress;
	
	/// The type of contiguous packet created.
	type Packet: ContiguousPacket;
	
	/// Assumes the packet creator already has references to source and destination ethernet addresses.
	///
	/// Returns a reference to the packet and a pointer to the layer 4 payload.
	///
	/// If it can't create a packet, returns an error.
	///
	/// RFC 7323, Section 5.7 requires that Internet Protocol version 4 packets have the Do Not Fragment (DF) bit set in their header to provide maximum protection for the PAWS algorithm.
	#[inline(always)]
	fn create_packet(&self, source_internet_protocol_address: &Address, destination_internet_protocol_address: &Address, layer_4_protocol: u8) -> Result<(Self::Packet, NonNull<u8>), ()>;
	
	/// Assumes the packet creator already has references to source and destination ethernet addresses.
	///
	/// Internally, the packet creator must flip the source and destination internet protocol addresses (and probably also the ethernet addresses).
	///
	/// Reuses a reference to an existing packet; this is because allocation (eg by malloc) of a new packet can be relatively expensive, and also, under heavy load, memory might not be easy to come by.
	///
	/// Returns a pointer to the layer 4 payload.
	#[inline(always)]
	fn reuse_packet_reversing_source_and_destination_addresses(&self, layer_4_protocol: u8, packet: Self::Packet) -> NonNull<u8>;
	
	/// Used specifically when setting TCP maximum segment size option.
	///
	/// Intended to be implemented as a combination of a cache of `PathMTU` and a set of known, fixed values, perhaps implemented using a routing table such as `IpLookupTable` (in the crate `treebitmap`).
	///
	/// A suitable cache is `LeastRecentlyUsedCacheWithExpiry`.
	///
	/// If there is no specific entry in the cache, an implementation can use `Self::Address::DefaultPathMaximumTransmissionUnitSize`.
	#[inline(always)]
	fn current_path_maximum_transmission_unit(&self, remote_internet_protocol_address: &Self::Address) -> u16;
}
