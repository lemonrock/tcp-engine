// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Default, Debug)]
pub(crate) struct RetransmissionTimeOutAlarmBehaviour<TCBA: TransmissionControlBlockAbstractions>
{
	retransmission_time_out: RetransmissionTimeOut,
}

impl<TCBA: TransmissionControlBlockAbstractions> AlarmBehaviour for RetransmissionTimeOutAlarmBehaviour<TCBA>
{
	#[inline(always)]
	fn process_alarm<TCBA: TransmissionControlBlockAbstractions>(transmission_control_block: &mut TransmissionControlBlock<TCBA>, interface: &Interface<TCBA>) -> Option<TickDuration>
	{
		let this: &mut Self = transmission_control_block.retransmission_time_out_alarm.alarm_behaviour;
		
		this.retransmission_time_out.back_off_after_expiry_of_retransmission_alarm();
		
		// TODO: Retransmit unack'd packets.
		
		// TODO: Implement F-RTO: https://tools.ietf.org/html/rfc5682#section-2
		
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
