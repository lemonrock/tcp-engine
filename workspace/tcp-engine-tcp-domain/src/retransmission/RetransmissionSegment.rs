// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// A retransmission segment.
#[repr(C, packed)]
pub struct RetransmissionSegment
{
	timestamp: MonotonicMillisecondTimestamp,
	starts_at: WrappingSequenceNumber,
	data_length_excluding_length_of_synchronize_and_finish_controls: u32,
	flags: Flags,
	
	has_been_retransmitted: bool,
	
	partially_acknowledged: bool,

	explicit_congestion_echo: bool,
}

impl Debug for RetransmissionSegment
{
	#[inline(always)]
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
	{
		write!(f, "RetransmissionSegment()")
	}
}

impl RetransmissionSegment
{
	/// Create a new instance.
	#[inline(always)]
	pub fn new(timestamp: MonotonicMillisecondTimestamp, starts_at: WrappingSequenceNumber, data_length_excluding_length_of_synchronize_and_finish_controls: u32, flags: Flags) -> Self
	{
		debug_assert!(flags.does_not_contain(Flags::Reset), "Flags should not contain Reset");
		debug_assert!(flags.does_not_contain(Flags::Urgent), "Flags should not contain Urgent");
		debug_assert!(flags.does_not_contain(Flags::Push), "Flags should not contain Push");
		debug_assert!(flags.does_not_contain(Flags::Synchronize) && flags.does_not_contain(Flags::Finish), "Flags should not contain Synchronize and Finish");
		
		if cfg!(debug_assertions)
		{
			if data_length_excluding_length_of_synchronize_and_finish_controls == 0
			{
				debug_assert!(flags.contains(Flags::Synchronize) || flags.contains(Flags::Finish), "data_length_excluding_length_of_synchronize_and_finish_controls can only be zero if either of the Synchronise or Finish flags is set");
			}
		}
		
		Self
		{
			timestamp,
			starts_at,
			data_length_excluding_length_of_synchronize_and_finish_controls,
			flags,
			
			has_been_retransmitted: false,
		
			partially_acknowledged: false,
		
			explicit_congestion_echo: false,
		}
	}
	
	/// RFC 793 Section 3.3 Page 26 Final Paragraph: "For sequence number purposes, the SYN is considered to occur before the first actual data octet of the segment in which it occurs, while the FIN is considered to occur after the last actual data octet in a segment in which it occurs".
	#[inline(always)]
	 fn decrease_sequence_number_length(&mut self, remaining_sequence_number_length: u32, explicit_congestion_echo: bool) -> Result<(u32, RetransmissionSegmentDecreaseSequenceNumberLengthOutcome), TooManySequenceNumbersAcknowledgedError>
	{
		use self::RetransmissionSegmentDecreaseSequenceNumberLengthOutcome::*;
		use self::TooManySequenceNumbersAcknowledgedError::*;
		
		debug_assert_ne!(remaining_sequence_number_length, 0, "remaining_sequence_number_length is zero");
		
		if explicit_congestion_echo
		{
			self.explicit_congestion_echo = explicit_congestion_echo;
		}
		
		let remaining_sequence_number_length = if unlikely!(self.flags.contains(Flags::Synchronize))
		{
			if unlikely!(remaining_sequence_number_length == 1)
			{
				return Ok((0, Exact))
			}
			
			self.flags.remove(Flags::Synchronize);
			
			remaining_sequence_number_length - 1
		}
		else
		{
			remaining_sequence_number_length
		};
		
		if self.data_length_excluding_length_of_synchronize_and_finish_controls > remaining_sequence_number_length
		{
			self.partially_acknowledged = true;
			self.data_length_excluding_length_of_synchronize_and_finish_controls -= remaining_sequence_number_length;
			unsafe { self.starts_at += remaining_sequence_number_length };
			
			return Ok((remaining_sequence_number_length, Partial))
		}
		let remaining_sequence_number_length = remaining_sequence_number_length - self.data_length_excluding_length_of_synchronize_and_finish_controls;
		
		let outcome = if unlikely!(self.flags.contains(Flags::Finish))
		{
			match remaining_sequence_number_length
			{
				0 => (self.data_length_excluding_length_of_synchronize_and_finish_controls, Partial),
				
				1 => (self.data_length_excluding_length_of_synchronize_and_finish_controls, Exact),
				
				_ => return Err(SequenceNumbersAfterFinishAcknowledged),
			}
		}
		else
		{
			if remaining_sequence_number_length == 0
			{
				(self.data_length_excluding_length_of_synchronize_and_finish_controls, Exact)
			}
			else
			{
				(self.data_length_excluding_length_of_synchronize_and_finish_controls, More { remaining_sequence_number_length })
			}
		};
		Ok(outcome)
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn set_unretransmitted_segment_timestamp_if_unset(&self, unretransmitted_segment_timestamp: &mut Option<MonotonicMillisecondTimestamp>)
	{
		if self.has_been_retransmitted || unretransmitted_segment_timestamp.is_some()
		{
			return
		}
		
		*unretransmitted_segment_timestamp = Some(self.timestamp)
	}
	
	#[allow(missing_docs)]
	#[inline(always)]
	pub fn set_explicit_congestion_echo(&self, explicit_congestion_echo: &mut bool)
	{
		if self.explicit_congestion_echo
		{
			*explicit_congestion_echo = true;
		}
	}
}
