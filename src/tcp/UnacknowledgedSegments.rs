// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Debug)]
pub(crate) struct UnacknowledgedSegments<TCBA: TransmissionControlBlockAbstractions>
{
	combined_payload_size: usize,
	queue: BTreeMap<WrappingSequenceNumber, UnacknowledgedSegment<TCBA>>,
}

impl<TCBA: TransmissionControlBlockAbstractions> Default for UnacknowledgedSegments<TCBA>
{
	#[inline(always)]
	fn default() -> Self
	{
		Self
		{
			combined_payload_size: 0,
			queue: BTreeMap::new(),
		}
	}
}

const MaximumQueueDepth: usize = 16;

const MaximumCombinedPayloadSize: usize = 16 * 1_024;

impl<TCBA: TransmissionControlBlockAbstractions> UnacknowledgedSegments<TCBA>
{
	#[inline(always)]
	pub(crate) fn is_empty(&self) -> bool
	{
		self.queue.is_empty()
	}
	
	#[inline(always)]
	pub(crate) fn remove(&mut self, sequence_number: WrappingSequenceNumber)
	{
		if let Some(segment) = self.queue.remove(&sequence_number)
		{
			self.combined_payload_size -= segment.segment_length();
			drop(segment);
		}
	}
	
	#[inline(always)]
	pub(crate) fn remove_from_first_up_to(&mut self, up_to_sequence_number: WrappingSequenceNumber) -> usize
	{
		let mut to_remove = ArrayVec::<[WrappingSequenceNumber; MaximumQueueDepth]>::new();
		
		{
			let mut head = self.first();
			while head.is_some()
			{
				let segment = head.unwrap();
				let end_sequence_number = segment.end_sequence_number();
				
				if end_sequence_number > up_to_sequence_number
				{
					break
				}
				
				to_remove.push(segment.sequence_number());
				
				head = self.next_fast(end_sequence_number)
			}
		}
		
		let removed = to_remove.len();
		for sequence_number in to_remove
		{
			self.remove(sequence_number)
		}
		removed
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
			self.remove(sequence_number)
		}
		
		acknowledgment_timestamp
	}
	
	#[inline(always)]
	pub(crate) fn remove_all(&mut self)
	{
		self.queue.clear()
	}
	
	#[inline(always)]
	pub(crate) fn first(&self) -> Option<&S>
	{
		self.queue.values().next()
	}
	
	#[inline(always)]
	pub(crate) fn get(&self, sequence_number: WrappingSequenceNumber) -> Option<&S>
	{
		self.queue.get(&sequence_number)
	}
	
	#[inline(always)]
	pub(crate) fn next(&self, current: Option<&S>) -> Option<&S>
	{
		if let Some(segment) = current
		{
			self.next_fast(segment.end_sequence_number())
		}
		else
		{
			None
		}
	}
	
	#[inline(always)]
	pub(crate) fn next_fast(&self, current_end_sequence_number: WrappingSequenceNumber) -> Option<&S>
	{
		self.get(current_end_sequence_number)
	}
	
	/// Will not enqueue packets:-
	///
	/// * whose payload length is zero; in this case an error is returned;
	/// * when the queue depth or queue buffer size is full;
	/// * if the segment is already enqueued according to sequence number (but not payload length or timestamp).
	#[inline(always)]
	pub(crate) fn enqueue(&mut self, segment: S) -> Result<(), &'static str>
	{
		let segment_length = segment.segment_length();
		
		if segment_length == 0
		{
			return Err("payload length should not be zero")
		}
		
		if self.queue.len() == MaximumQueueDepth
		{
			return Err("maximum queue depth reached")
		}
		
		if self.combined_payload_size + segment_length > MaximumCombinedPayloadSize
		{
			return Err("maximum queue bytes reached")
		}
		
		self.combined_payload_size += segment_length;
		if self.queue.insert(segment.SEQ(), segment).is_none()
		{
			Ok(())
		}
		else
		{
			Err("would have replaced an existing entry")
		}
	}
}
