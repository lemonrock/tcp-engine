// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// A retransmission queue.
#[repr(C, packed)]
pub struct RetransmissionQueue
{
	queue: ManuallyDrop<[RetransmissionSegment; RetransmissionQueue::MaximumDepth]>,
	start: usize,
	depth: usize,
}

impl Drop for RetransmissionQueue
{
	#[inline(always)]
	fn drop(&mut self)
	{
		if needs_drop::<RetransmissionSegment>()
		{
			while self.depth != 0
			{
				let start_index = self.start_index();
				let retransmission_segment = self.get_mutable(start_index);
				unsafe { retransmission_segment.drop_in_place() }
				
				self.start += 1;
				self.depth -= 1;
			}
		}
	}
}

impl Debug for RetransmissionQueue
{
	#[inline(always)]
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
	{
		write!(f, "RetransmissionQueue()")
	}
}

impl Default for RetransmissionQueue
{
	#[inline(always)]
	fn default() -> Self
	{
		Self
		{
			queue: ManuallyDrop::new(unsafe { uninitialized() }),
			start: 0,
			depth: 0,
		}
	}
}

impl RetransmissionQueue
{
	const MaximumDepth: usize = 32;
	
	/// Acknowledged.
	#[inline(always)]
	pub fn acknowledged(&mut self, sequence_numbers_length: u32) -> Result<(u32, Option<MonotonicMillisecondTimestamp>, bool, bool), TooManySequenceNumbersAcknowledgedError>
	{
		use self::RetransmissionSegmentDecreaseSequenceNumberLengthOutcome::*;
		use self::TooManySequenceNumbersAcknowledgedError::*;
		
		debug_assert_ne!(sequence_numbers_length, 0, "remaining_sequence_number_length is zero");
		
		let mut total_remaining_sequence_number_length = sequence_numbers_length;
		let mut total_bytes_acknowledged = 0;
		let mut unretransmitted_segment_timestamp = None;
		let mut a_window_of_data_was_processed = false;
		let mut explicit_congestion_echo = false;
		
		loop
		{
			if self.is_empty()
			{
				return Err(TooManySequenceNumbersAcknowledged)
			}
			
			let outcome =
			{
				let retransmission_segment = self.oldest();
				let (bytes_acknowledged, outcome) = retransmission_segment.decrease_sequence_number_length(total_remaining_sequence_number_length, explicit_congestion_echo)?;
				
				total_bytes_acknowledged += bytes_acknowledged;
				
				if outcome == Partial
				{
					break
				}
				
				retransmission_segment.set_unretransmitted_segment_timestamp_if_unset(&mut unretransmitted_segment_timestamp);
				a_window_of_data_was_processed = true;
				retransmission_segment.set_explicit_congestion_echo(&mut explicit_congestion_echo);
				
				outcome
			};
			
			self.dequeue();
			
			match outcome
			{
				Exact => break,
				
				More { remaining_sequence_number_length } =>
				{
					total_remaining_sequence_number_length = remaining_sequence_number_length
				}
				
				Partial => unreachable!(),
			}
		}
		
		Ok((total_bytes_acknowledged, unretransmitted_segment_timestamp, a_window_of_data_was_processed, explicit_congestion_echo))
	}
	
	#[inline(always)]
	fn oldest(&mut self) -> &mut RetransmissionSegment
	{
		debug_assert!(self.is_empty(), "is empty");
		
		let start_index = self.start_index();
		unsafe { &mut * self.get_mutable(start_index) }
	}
	
	#[inline(always)]
	fn dequeue(&mut self)
	{
		debug_assert!(!self.is_empty(), "is already empty");
		
		self.start += 1;
		self.depth -= 1;
	}
	
	/// Enqueue.
	#[inline(always)]
	pub fn enqueue(&mut self, now: MonotonicMillisecondTimestamp, starts_at: WrappingSequenceNumber, data_length_excluding_length_of_synchronize_and_finish_controls: u32, flags: Flags)
	{
		debug_assert!(self.is_not_full(), "retransmission queue is full");
		
		let end_index = self.end_index();
		let item = self.get_mutable(end_index);
		unsafe { item.write_unaligned(RetransmissionSegment::new(now, starts_at, data_length_excluding_length_of_synchronize_and_finish_controls, flags)) }
		self.depth += 1
	}
	
	/// Is not full.
	#[inline(always)]
	pub fn is_not_full(&self) -> bool
	{
		!self.is_full()
	}
	
	/// Is full.
	#[inline(always)]
	pub fn is_empty(&self) -> bool
	{
		self.depth == 0
	}
	
	#[inline(always)]
	fn is_full(&self) -> bool
	{
		self.depth == Self::MaximumDepth
	}
	
	#[inline(always)]
	fn get_mutable(&mut self, index: usize) -> *mut RetransmissionSegment
	{
		unsafe { self.queue.get_unchecked_mut(index) }
	}
	
	#[inline(always)]
	fn start_index(&self) -> usize
	{
		self.start % Self::MaximumDepth
	}
	
	#[inline(always)]
	fn end_index(&self) -> usize
	{
		self.end() % Self::MaximumDepth
	}
	
	#[inline(always)]
	fn end(&self) -> usize
	{
		self.start + self.depth
	}
}
