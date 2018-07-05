// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// A DPDK contiguous packet.
///
/// Probably a wrapper around NonNull<rte_mbuf>.
#[derive(Debug, Copy, Clone)]
pub struct DpdkContiguousPacket(*mut ());

impl ContiguousPacket for DpdkContiguousPacket
{
	#[inline(always)]
	fn source_internet_protocol_address<Address: InternetProtocolAddress>(self) -> &Address
	{
		const SizeOfEthernetHeader: usize = 6 + 6 + 2;
		
		unsafe { &* (((self.0 as usize) + SizeOfEthernetHeader + Address::OffsetOfAddressInsideInternetProtocolPacket) as *mut Address) }
	}
	
	#[inline(always)]
	fn decrement_reference_count(self)
	{
		// Decrement the rte_mbuf refcnt; if it is 1 then call `PacketBufferExt.free_direct_contiguous_packet()`.
		
		// There IS A CONFLICT with `DEV_TX_OFFLOAD_MBUF_FAST_FREE` being set, which requires refcnt == 1!!!
		unimplemented!()
	}
	
	#[inline(always)]
	fn packet_length(self) -> usize
	{
		// DPDK: `PacketBufferExt.packet_length_if_contiguous()`.
		unimplemented!()
	}
	
	#[inline(always)]
	fn offset_into_data<T>(self, _offset: usize) -> NonNull<T>
	{
		// DPDK: `PacketBufferExt.offset_into_data()`.
		unimplemented!()
	}
}
