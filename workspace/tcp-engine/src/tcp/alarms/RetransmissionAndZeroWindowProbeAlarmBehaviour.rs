// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Default, Debug)]
pub(crate) struct RetransmissionAndZeroWindowProbeAlarmBehaviour<TCBA: TransmissionControlBlockAbstractions>
{
	retransmission_time_out_data: RetransmissionTimeOutData,
}

impl<TCBA: TransmissionControlBlockAbstractions> AlarmBehaviour<TCBA> for RetransmissionAndZeroWindowProbeAlarmBehaviour<TCBA>
{
	#[inline(always)]
	fn process_alarm<TCBA: TransmissionControlBlockAbstractions>(transmission_control_block: &mut TransmissionControlBlock<TCBA>, interface: &Interface<TCBA>, now: Tick) -> Option<TickDuration>
	{
		if transmission_control_block.all_data_acknowledged()
		{
			if transmission_control_block.send_window_is_zero()
			{
				transmission_control_block.retransmit_zero_window_probe(interface, now)
			}
			else
			{
				None
			}
		}
		else
		{
			transmission_control_block.retransmit_data(interface, now)
		}
	}
	
	#[inline(always)]
	fn alarm_wheel(alarms: &Alarms<TCBA>) -> &AlarmWheel<Self, TCBA>
	{
		alarms.retransmission_and_zero_window_probe_alarm_wheel()
	}
	
	#[inline(always)]
	fn offset_of_parent_alarm_from_transmission_control_block() -> usize
	{
		offset_of!(TransmissionControlBlock<TCBA>, retransmission_and_zero_window_probe_alarm)
	}
}

impl<TCBA: TransmissionControlBlockAbstractions> RetransmissionAndZeroWindowProbeAlarmBehaviour<TCBA>
{
	#[inline(always)]
	pub(crate) fn new<'a>(recent_connection_data: &RecentConnectionData, is_for_non_synchronized_state: bool) -> Self
	{
		Self
		{
			retransmission_time_out_data: recent_connection_data.retransmission_time_out_data(),
		}
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
		self.retransmission_time_out_data.process_measurement_of_round_trip_time(measurement_of_round_trip_time)
	}
	
	#[inline(always)]
	pub(crate) fn increment_retransmissions(&mut self) -> Option<u8>
	{
		self.retransmission_time_out_data.increment_retransmissions()
	}
	
	#[inline(always)]
	pub(crate) fn reset_retransmissions(&mut self) -> Option<u8>
	{
		self.retransmission_time_out_data.reset_retransmissions()
	}
	
	#[inline(always)]
	pub(crate) fn retransmission_time_out_data_reference(&self) -> &RetransmissionTimeOutData
	{
		&self.retransmission_time_out_data
	}
	
	#[inline(always)]
	pub(crate) fn retransmission_time_out(&self, state: State) -> MillisecondDuration
	{
		self.retransmission_time_out_data_reference().retransmission_time_out(state)
	}
	
	#[inline(always)]
	pub(crate) fn smoothed_round_trip_time_and_round_trip_time_variance(&self) -> (MillisecondDuration, MillisecondDuration)
	{
		self.retransmission_time_out_data_reference().smoothed_round_trip_time_and_round_trip_time_variance()
	}
	
	#[inline(always)]
	pub(crate) fn entering_established_state(&mut self)
	{
		self.retransmission_time_out_data.entering_established_state()
	}
}
