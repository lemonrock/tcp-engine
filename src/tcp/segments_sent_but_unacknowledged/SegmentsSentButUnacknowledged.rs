// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Debug)]
pub(crate) struct SegmentsSentButUnacknowledged<TCBA: TransmissionControlBlockAbstractions>
{
	queue: BTreeMap<WrappingSequenceNumber, SegmentSentButUnacknowledged<TCBA>>,
}

impl<TCBA: TransmissionControlBlockAbstractions> Default for SegmentsSentButUnacknowledged<TCBA>
{
	#[inline(always)]
	fn default() -> Self
	{
		Self
		{
			queue: BTreeMap::new(),
		}
	}
}

impl<TCBA: TransmissionControlBlockAbstractions> SegmentsSentButUnacknowledged<TCBA>
{
	#[inline(always)]
	pub(crate) fn is_empty(&self) -> bool
	{
		self.queue.is_empty()
	}
	
	#[inline(always)]
	pub(crate) fn is_not_empty(&self) -> bool
	{
		!self.is_empty()
	}
	
	#[inline(always)]
	pub(crate) fn append(&mut self, packet: TCBA::Packet, our_tcp_segment: &mut TcpSegment<TCBA>, payload_size: usize, now: MonotonicMillisecondTimestamp)
	{
		let old = self.queue.insert(our_tcp_segment.SEQ(), SegmentSentButUnacknowledged::new(packet, our_tcp_segment, payload_size, now));
		debug_assert!(old.is_none(), "Overwrote an existing segment sent but unacknowledged");
	}
	
	#[inline(always)]
	pub(crate) fn segment_to_retransmit(&mut self) -> &mut SegmentSentButUnacknowledged<TCBA>
	{
		self.queue.values_mut().next().expect("When this method is used from the retransmission time out alarm, it is assumed there are unacknowledged segments")
	}
	
	// TODO: In-order vs not-in-order
	// TODO: partial ack (eg only acks SOME of the payload of a segment).
		// We could re-packetize; messy, potentially involves a memmove.
		// We could use multi-packet mbufs (a mbuf chain), with headers separate to data.
	
	// TODO: With received payload data, we need to place into a read queue if it is not yet appropriate.
	
	// TODO: What is the timestamp on a re-transmitted packet?
	
	
	// TODO: Combine multiple ACKs.
	// TODO: Send data on an ACK - call the event receiver, tell them the size of segment length we have - allow them to write some data to it.
	// TODO: Only for TCP Fast Open if this is the third part of a three-way handshake.
	// TODO: Create SACKs.
	// See RFC 2018 but also has 1 errata https://www.rfc-editor.org/errata_search.php?rfc=2018
	// TODO: Delayed ACKs (maximum delay is 0.5 seconds, maximum number of acks delayed is 2).
	
	// Partial acks are quite possible if we use DPDK's GSO (generic segmentation offload [in software]) or hardware TSO.
	
	#[inline(always)]
	pub(crate) fn remove_first_segment_sent_but_unacknowledged(&mut self, up_to_sequence_number: WrappingSequenceNumber) -> MonotonicMillisecondTimestamp
	{
	
	}
	
	
	#[inline(always)]
	pub(crate) fn remove_all_from_first_up_to(&mut self, up_to_sequence_number: WrappingSequenceNumber) -> Option<MonotonicMillisecondTimestamp>
	{
		let mut to_remove = ArrayVec::<[WrappingSequenceNumber; MaximumQueueDepth]>::new();
		
		let mut acknowledgment_timestamp = None;
		for segment in self.queue.values()
		{
			let end_sequence_number = segment.end_sequence_number();
			
			if end_sequence_number > up_to_sequence_number
			{
				break
			}
			
			if end_sequence_number == up_to_sequence_number
			{
				acknowledgment_timestamp = Some(segment.timestamp());
			}
			
			to_remove.push(segment.sequence_number());
		}
		
		for sequence_number in to_remove
		{
			self.queue.remove(sequence_number)
		}
		
		acknowledgment_timestamp
	}
}
