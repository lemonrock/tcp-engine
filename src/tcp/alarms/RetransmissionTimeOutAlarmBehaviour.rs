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
		let this: &mut Self = transmission_control_block.retransmission_time_out_alarm.alarm_behaviour;
		
		this.retransmission_time_out.back_off_after_expiry_of_retransmission_alarm();
		
		// TODO: Retransmit unack'd packets.
		
		let sack_permitted = false;
		
		// TODO: Implement F-RTO: https://tools.ietf.org/html/rfc5682#section-2 / section-3
		// 1) When the retransmission timer expires, retransmit the first unacknowledged segment and set SpuriousRecovery to FALSE.
		if sack_permitted
		{
			// Section 3
		}
		else
		{
			// Section 2
		}
		
		
		/*
		Upon a retransmission timeout, a conventional TCP sender assumes that
   outstanding segments are lost and starts retransmitting the
   unacknowledged segments.  When the retransmission timeout is detected
   to be spurious, the TCP sender should not continue retransmitting
   based on the timeout.  For example, if the sender was in congestion



Sarolahti, et al.           Standards Track                    [Page 11]


RFC 5682                         F-RTO                    September 2009


   avoidance phase transmitting new, previously unsent segments, it
   should continue transmitting previously unsent segments in congestion
   avoidance.

   There are currently two alternatives specified for a spurious timeout
   response algorithm, the Eifel Response Algorithm [LG05], and an
   algorithm for adapting the retransmission timeout after a spurious
   RTO [BBA06].  If no specific response algorithm is implemented, the
   TCP SHOULD respond to spurious timeout conservatively, applying the
   TCP congestion control specification [APB09].  Different response
   algorithms for spurious retransmission timeouts have been analyzed in
   some research papers [GL03, Sar03] and IETF documents [SL03].
		
		
		*/
		
		enum SpuriousRecoveryState
		{
			SPUR_TO,
			
			FALSE,
		}
		
		
		Some(this.retransmission_time_out.time_out())
	}
	
	#[inline(always)]
	fn alarm_wheel<TCBA: TransmissionControlBlockAbstractions>(alarms: &Alarms<TCBA>) -> &AlarmWheel<Self, TCBA>
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
