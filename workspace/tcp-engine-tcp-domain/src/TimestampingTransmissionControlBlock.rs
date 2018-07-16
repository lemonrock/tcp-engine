// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Timestamping.
pub trait TimestampingTransmissionControlBlock<Address: InternetProtocolAddress>: StateTransmissionControlBlock + ConnectionIdentification<Address>
{
	/// RFC 7323, Section 3.2, Pages 12-13:-
	/// "Once TSopt has been successfully negotiated, that is both <SYN> and <SYN,ACK> contain TSopt, the TSopt MUST be sent in every non-<RST> segment for the duration of the connection, and SHOULD be sent in an <RST> segment.
	/// ...
	/// If a non-<RST> segment is received without a TSopt, a TCP SHOULD silently drop the segment".
	#[inline(always)]
	fn timestamps_are_required_in_all_segments_except_reset(&self) -> bool
	{
		self.debug_assert_action_is_only_valid_in_synchronized_states();
		
		self.get_field_timestamping().is_some()
	}
	
	/// RFC 7323.
	///
	/// update `Last.ACK.sent`.
	#[inline(always)]
	fn update_Last_ACK_sent(&mut self, ACK: WrappingSequenceNumber)
	{
		self.debug_assert_action_is_only_valid_in_synchronized_states();
		
		if let Some(timestamping) = self.get_mutable_field_timestamping().as_mut()
		{
			timestamping.update_Last_ACK_sent(ACK);
		}
	}
	
	/// Enable (strictly speaking, finish enabling) timestamping for a connection in the SynchronizeSent state.
	#[inline(always)]
	fn enable_timestamping(&mut self, timestamps_option: TimestampsOption)
	{
		self.debug_assert_action_is_only_valid_in_sychronize_sent_state();
		self.debug_assert_we_are_the_client();
		debug_assert!(self.get_field_timestamping().is_some(), "timestamping is enabled by default for SendSynchronize but we do not know TS_Recent until SYN-ACK arrives");
		
		self.get_mutable_field_timestamping().as_mut().unwrap().set_TS_Recent(timestamps_option.TSval)
	}
	
	/// Disable timestamping for a connection in the SynchronizeSent state.
	#[inline(always)]
	fn disable_timestamping(&mut self)
	{
		self.debug_assert_action_is_only_valid_in_sychronize_sent_state();
		self.debug_assert_we_are_the_client();
		
		*self.get_mutable_field_timestamping() = None
	}
	
	/// Write a TCP timestamping option if timestamping is enabled.
	#[inline(always)]
	fn write_timestamping_option(&self, options_data_pointer: usize, now: MonotonicMillisecondTimestamp) -> usize
	{
		if let Some(ref timestamping) = self.get_field_timestamping()
		{
			TcpSegment::write_timestamps_option(options_data_pointer, timestamping.normal_timestamps_option(now))
		}
		else
		{
			options_data_pointer
		}
	}
	
	/// Used by `macro processing_incoming_segments_4_1_check_sequence_number!()`.
	///
	/// Otherwise should not exist publically.
	#[inline(always)]
	fn timestamping_reference(&self) -> Option<&Timestamping>
	{
		self.get_field_timestamping().as_ref()
	}
	
	/// Make a measurement of round trip time (`RTT`) using timestamps if possible.
	#[inline(always)]
	fn measurement_of_round_trip_time_using_timestamps(&self, now: MonotonicMillisecondTimestamp, timestamps_option: Option<&TimestampsOption>) -> Option<MillisecondDuration>
	{
		if let Some(timestamping) = self.timestamping_reference()
		{
			// Missing a timestamps option (RFC 7323) is strictly only valid for Reset segments (eg ResetAcknowledgment).
			// There is also as of writing a check that timestamps are always present, but it may be relaxed for some non-compliant TCP stacks.
			if let Some(timestamps_option) = timestamps_option
			{
				return timestamping.measurement_of_round_trip_time(now, timestamps_option)
			}
		}
		
		None
	}
	
	#[doc(hidden)]
	#[inline(always)]
	fn get_field_timestamping(&self) -> &Option<Timestamping>;
	
	#[doc(hidden)]
	#[inline(always)]
	fn get_mutable_field_timestamping(&mut self) -> &mut Option<Timestamping>;
}
