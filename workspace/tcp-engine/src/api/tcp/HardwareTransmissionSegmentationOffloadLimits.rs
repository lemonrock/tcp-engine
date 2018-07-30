// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Limits to be applied when using hardware transmission segmentation offload.
///
/// Also known as Large Segmentation Offload (LSO), Transmission Segmentation Offload (TSO) and TCP Segmentation Offload (TSO).
///
/// To enable TCP segmentation offload when using DPDK:-
///
/// * Make sure the device or queue is enabled with `DEV_TX_OFFLOAD_TCP_TSO`, `DEV_TX_OFFLOAD_IPV4_CKSUM` and `DEV_TX_OFFLOAD_TCP_CKSUM`.
/// * Set the `PKT_TX_TCP_SEG` flag in `mbuf->ol_flags` (which also implies the flag `PKT_TX_TCP_CKSUM`).
/// * For internet protocol version 4, set the flags `PKT_TX_IPV4` and `PKT_TX_IP_CKSUM`.
/// * For internet protocol version 6, set the flag `PKT_TX_IPV6`.
/// * Set the `rte_mbuf` fields `tso_segsz`, `outer_l2_len` `outer_l3_len` `l2_len` `l3_len` and `l4_len`.
/// * Make sure the `rte_mbuf` field `nb_segs` is set.
///
/// See also DPDK's definition of `rte_validate_tx_offload()`.
///
/// For a software equivalent, see [Generic Send Offload (GSO)](https://doc.dpdk.org/guides/prog_guide/generic_segmentation_offload_lib.html), which currently only supports internet protocol version 4 (see `gso_tcp4_segment()` and `rte_gso_segment()`; after use functions TCP checksums may need to be re-computed).
/// If the input packet is GSO'd, its mbuf refcnt reduces by 1. Therefore, when all GSO segments are freed, the input packet is freed automatically. Hence software segmentation offload should occur before insertion in the retransmission queue. GSO logic could be re-implemented in Rust; there isn't a huge amount to it.
///
/// GSO takes an original packet and creates a packet chain (a singly-linked list) whose head is a packet with just header information (allocated from a direct pool), and whose subsequent elements are indirect packets (allocated from an indirect pool, and attached [with refcnting] to the original packet). One can think of indirect packets as 'views' or 'windows' into data.
///
/// Also explore `rte_pktmbuf_attach()` (in order to split header fields from payload or do partial re-transmits) and `rte_pktmbuf_attach_extbuf()` (which attaches an indirect buffer to an externally managed buffer of data, ie a buffer we allocate, which is auto-freed via a callback pointer on refcnt -> 0).
///
/// Sending data requires having a fixed-size array to 'write' packets into - and which can be checked for available capacity before doing work. This needs to be provided to 'process segment' and 'progress timers'. Alternatively it can be held in the interface, although mutability makes that a little unpleasant.
///
/// If we're doing reference counting, then we need to deal with queue drops appropriately.
///
///
/// CRAZY IDEA
///
/// - we allocate one GIANT external malloc'd (but NUMA-node local) buffer for send per connection
/// 	- we allocate all these up front (max no of TCBs x buffer size) - the memory is reserved; we only ever need to free it when dropping an Interface.
/// 	- we do the allocation just once, not per TCB, and then subdivide (we could even use compressed pointers). This makes malloc fragmentation much less likely, and lets us use monster huge pages, eg 1Gb huge pages.
///
/// - we use this GIANT buffer as a ring buffer, so a writing socket can 'wrap around'; each write call gets told a pointer and a maximum length; once we've written to the end, we start again at the beginning of the buffer. We just need to track oldest un-ack'd data so we don't start writing where data has yet to be ack'd.
///
/// - using attached external buffers which 'never die' (for all intents and purposes) means we don't have to pay a heavy callback overhead on freeing packets. Interestingly, we could use the callback 'on death' to add to a retransmission queue.
///
/// - instead of creating lots and lots of segments, we just have lots and lots of 'views' onto this buffer in the retransmission queue. These views have a start seq number, an end seq number and a timestamp, and potentially some IP header data (although we may wish to recreate some of that to save space).
/// - when transmitting, we create a packet chain, with a header packet, rte_mbuf.next = indirect_buffer.which_is_a_view_and_so_attached_to_external_GIANT_buffer
/// - this makes life much easier dealing with retransmissions
/// - in theory, we're supposed to retransmit everything if a receiver doesn't support SACK.
///
/// - we handle out-of-order AND overlapping ACKs (overlapping at start of sequence space and at end of sequence space). We 'split' these overlapping ACKs into two, and treat them seperately - one part is a likely duplicate, the other part is acceptable.
///
/// - we will need a sensible way to manage the GIANT ring buffer, as otherwise it can become 'full of holes'. Using bits to indicate free bytes adds 12.5% overhead.
///
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct HardwareTransmissionSegmentationOffloadLimits
{
	/// In DPDK, maps to the `struct rte_mbuf` field `tso_segsz`.
	///
	/// Different hardware has different limits:-
	///
	/// * Intel fm10k has 15.
	/// * Intel i40e has 256.
	/// * Intel igb has none.
	/// * AVF has 256.
	/// * QEDE has none.
	pub inclusive_minimum_maximum_segment_size: u16,
	
	/// In DPDK, maps to the `struct rte_mbuf` field `tso_segsz`.
	///
	/// Different hardware has different limits:-
	///
	/// * Intel fm10k has none (?really?).
	/// * Intel i40e has 9674.
	/// * Intel igb has 9216.
	/// * AVF has 9668.
	/// * QEDE has 9672.
	pub inclusive_maximum_maximum_segment_size: u16,
	
	/// In DPDK, maps to the `struct rte_mbuf` fields `outer_l2_len` `outer_l3_len` `l2_len` `l3_len` and `l4_len` summed together.
	///
	/// Different hardware has different limits:-
	///
	/// * Intel fm10k has 54.
	/// * Intel i40e has none.
	/// * Intel igb has none.
	/// * AVF has none.
	/// * QEDE has none.
	///
	/// In practice, the smallest header likely is 14 (Ethernet) + 20 (IPv4) + 20 (TCP), so this limit does not apply.
	pub inclusive_minimum_combined_layers_2_3_and_4_header_length: u16,
	
	/// In DPDK, maps to the `struct rte_mbuf` fields `outer_l2_len` `outer_l3_len` `l2_len` `l3_len` and `l4_len` summed together.
	///
	/// Different hardware has different limits:-
	///
	/// * Intel fm10k has 192.
	/// * Intel i40e has none.
	/// * Intel igb has 512.
	/// * AVF has none.
	/// * QEDE has none.
	pub inclusive_maximum_combined_layers_2_3_and_4_header_length: u16,
	
	/// In DPDK, maps to the `struct rte_mbuf` field `nb_segs`.
	///
	/// This is the number of subordinate ('chained') `rte_mbuf`s permitted.
	///
	/// Different hardware has different limits:-
	///
	/// * Intel fm10k has none (?really?).
	/// * Intel i40e has 8.
	/// * Intel igb has none.
	/// * AVF has 8.
	/// * QEDE has 254.
	///
	/// In practice, it is believed none actually imposes a limit of 255 rather than 65,535.
	///
	/// With the pragmatic limits of maximum MSS above, 8 segments is always enough for the 1220 byte IPv6 MSS.
	pub inclusive_maximum_number_of_segments: u16,
}
