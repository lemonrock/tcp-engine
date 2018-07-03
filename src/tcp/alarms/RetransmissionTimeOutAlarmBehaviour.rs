// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Default, Debug)]
pub(crate) struct RetransmissionTimeOutAlarmBehaviour<TCBA: TransmissionControlBlockAbstractions>
{
	retransmission_time_out: RetransmissionTimeOut,
}

impl<TCBA: TransmissionControlBlockAbstractions> AlarmBehaviour for RetransmissionTimeOutAlarmBehaviour<TCBA>
{
	/// RFC 1123 Section 4.2.1.7: Probing Zero Windows.
	///
	/// This is discussed in RC 793 Section 3.7 Page 42.
	///
	/// This is a succint precis of the section:-
	///
	/// "The transmitting host SHOULD send the first zero-window probe when a zero window has existed for the retransmission timeout period (see Section 4.2.2.15), and SHOULD [back off] the interval between successive probes up to a maximum interval.
	/// It is possible to combine retransmission time out with zero-window probing".
	#[inline(always)]
	fn process_alarm<TCBA: TransmissionControlBlockAbstractions>(transmission_control_block: &mut TransmissionControlBlock<TCBA>, interface: &Interface<TCBA>, _now: Tick) -> Option<TickDuration>
	{
		let unacknowledged_segment = transmission_control_block.next_unacknowledged_segment();
		
		if unacknowledged_segment.increment_retransmissions()
		{
			transmission_control_block.forcibly_close(interface);
			return None
		}
		
		{
			let this: &mut Self = transmission_control_block.retransmission_time_out_alarm.alarm_behaviour_mutable_reference();
			this.retransmission_time_out.back_off_after_expiry_of_retransmission_alarm();
		}
		
		transmission_control_block.reset_congestion_window_to_loss_window_because_retransmission_timed_out();
		
		if unacknowledged_segment.is_first_retransmission()
		{
			unacknowledged_segment.clear_explicit_congestion_notifications_when_retransmitting();
			
			transmission_control_block.rfc_5681_section_7_paragaph_6_set_ssthresh_to_half_of_flight_size_on_first_retransmission();
		}
		
		
		// TODO: Retransmit unack'd packet.
		
		/*
		
		RFC 6298
		
5.  Managing the RTO Timer

   An implementation MUST manage the retransmission timer(s) in such a
   way that a segment is never retransmitted too early, i.e., less than
   one RTO after the previous transmission of that segment.

   The following is the RECOMMENDED algorithm for managing the
   retransmission timer:

   (5.1) Every time a packet containing data is sent (including a
         retransmission), if the timer is not running, start it running
         so that it will expire after RTO seconds (for the current value
         of RTO).

   (5.2) When all outstanding data has been acknowledged, turn off the
         retransmission timer.

   (5.3) When an ACK is received that acknowledges new data, restart the
         retransmission timer so that it will expire after RTO seconds
         (for the current value of RTO).

   When the retransmission timer expires, do the following:

   (5.4) Retransmit the earliest segment that has not been acknowledged
         by the TCP receiver.

   (5.5) The host MUST set RTO <- RTO * 2 ("back off the timer").  The
         maximum value discussed in (2.5) above may be used to provide
         an upper bound to this doubling operation.

   (5.6) Start the retransmission timer, such that it expires after RTO
         seconds (for the value of RTO after the doubling operation
         outlined in 5.5).
		*/
		
		Some(this.retransmission_time_out.time_out())
	}
	
	#[inline(always)]
	fn alarm_wheel(alarms: &Alarms<TCBA>) -> &AlarmWheel<Self, TCBA>
	{
		alarms.retransmission_time_out_alarm_wheel()
	}
	
	#[inline(always)]
	fn offset_of_parent_alarm_from_transmission_control_block() -> usize
	{
		offset_of!(TransmissionControlBlock<TCBA>, retransmission_time_out_alarm)
	}
}

impl<TCBA: TransmissionControlBlockAbstractions> RetransmissionTimeOutAlarmBehaviour<TCBA>
{
	#[inline(always)]
	pub(crate) fn new<'a>(cached_congestion_data: &Ref<'a, CachedCongestionData>) -> Self
	{
		Self
		{
			retransmission_time_out: cached_congestion_data.retransmission_time_out(),
		}
	}
	
	#[inline(always)]
	pub(crate) fn time_out(&self) -> MillisecondDuration
	{
		self.retransmission_time_out.time_out()
	}
	
	#[inline(always)]
	pub(crate) fn adjust_retransmission_time_out_based_on_acknowledgments(&mut self, now: MonotonicMillisecondTimestamp, timestamp: MonotonicMillisecondTimestamp)
	{
		debug_assert!(now >= timestamp, "time has run backwards");
		
		let measurement_of_round_trip_time = now - timestamp;
		self.process_measurement_of_round_trip_time(measurement_of_round_trip_time)
	}
	
	#[inline(always)]
	pub(crate) fn process_measurement_of_round_trip_time(&mut self, measurement_of_round_trip_time: MillisecondDuration)
	{
		self.retransmission_time_out.process_measurement_of_round_trip_time(measurement_of_round_trip_time)
	}
}
