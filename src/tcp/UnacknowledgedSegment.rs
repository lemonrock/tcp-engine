// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Debug)]
pub(crate) struct UnacknowledgedSegment<TCBA: TransmissionControlBlockAbstractions>
{
	packet: TCBA::Packet,
	
	tcp_segment: NonNull<TcpSegment<TCBA>>,
	
	/// RFC 793, Glossary, Page 83: "The amount of sequence number space occupied by a segment, including any controls which occupy sequence space".
	segment_length: usize,
	
	timestamp: MonotonicMillisecondTimestamp,
}

impl<TCBA: TransmissionControlBlockAbstractions> Drop for UnacknowledgedSegment<TCBA>
{
	#[inline(always)]
	fn drop(&mut self)
	{
		self.packet.free_packet()
	}
}

impl<TCBA: TransmissionControlBlockAbstractions> UnacknowledgedSegment<TCBA>
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
}
