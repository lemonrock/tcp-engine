// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Debug)]
pub(crate) struct SegmentSentButUnacknowledged<TCBA: TransmissionControlBlockAbstractions>
{
	packet: TCBA::Packet,
	
	tcp_segment: NonNull<TcpSegment<TCBA>>,
	
	/// RFC 793, Glossary, Page 83: "The amount of sequence number space occupied by a segment, including any controls which occupy sequence space".
	segment_length: usize,
	
	timestamp: MonotonicMillisecondTimestamp,

	retransmissions: u8,
}

impl<TCBA: TransmissionControlBlockAbstractions> Drop for SegmentSentButUnacknowledged<TCBA>
{
	#[inline(always)]
	fn drop(&mut self)
	{
		self.packet.free_packet()
	}
}

impl<TCBA: TransmissionControlBlockAbstractions> SegmentSentButUnacknowledged<TCBA>
{
	#[inline(always)]
	fn new(packet: TCBA::Packet, tcp_segment: NonNull<TcpSegment<TCBA>>, segment_length: usize, now: MonotonicMillisecondTimestamp) -> Self
	{
		Self
		{
			packet,
			tcp_segment,
			segment_length,
			timestamp: now,
			retransmissions: 0,
		}
	}
	
	#[inline(always)]
	fn SEQ(&self) -> WrappingSequenceNumber
	{
		self.tcp_segment.SEQ()
	}
	
	#[inline(always)]
	fn segment_length(&self) -> usize
	{
		self.segment_length
	}
	
	#[inline(always)]
	fn end_sequence_number(&self) -> WrappingSequenceNumber
	{
		self.SEQ() + self.payload_length()
	}
	
	#[inline(always)]
	fn timestamp(&self) -> MonotonicMillisecondTimestamp
	{
		self.timestamp
	}
	
	#[inline(always)]
	fn increment_retransmissions_and_fail_if_maximum_reached(&mut self) -> bool
	{
		const MaximumRetransmissions: u8 = 8;
		
		self.retransmissions += 1;
		self.retransmissions == MaximumRetransmissions
	}
	
	#[inline(always)]
	fn clear_explicit_congestion_notifications_when_retransmitting(&mut self)
	{
		let tcp_segment = unsafe { self.tcp_segment.as_mut() };
		tcp_segment.clear_congestion_window_reduced_flag();
		
		// RFC 3168 Section 6.1.5 Paragraph 1: "... TCP implementations MUST NOT set either ECT codepoint (ECT(0) or ECT(1)) in the IP header for retransmitted data packets".
		self.packet.set_explicit_congestion_notification_state_off();
	}
	
	#[inline(always)]
	fn is_second_or_more_successive_time_out(&self) -> bool
	{
		self.retransmissions > 1
	}
}
