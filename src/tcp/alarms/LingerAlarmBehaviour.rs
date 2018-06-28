// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Default, Debug)]
pub(crate) struct LingerAlarmBehaviour<TCBA: TransmissionControlBlockAbstractions>;

impl<TCBA: TransmissionControlBlockAbstractions> AlarmBehaviour for LingerAlarmBehaviour<TCBA>
{
	#[inline(always)]
	fn process_alarm<TCBA: TransmissionControlBlockAbstractions>(transmission_control_block: &mut TransmissionControlBlock<TCBA>, interface: &Interface<TCBA>, now: Tick) -> Option<TickDuration>
	{
		if transmission_control_block.is_state_before_closing_or_time_wait()
		{
			let SND = transmission_control_block.SND;
			interface.send_reset_without_packet_to_reuse(transmission_control_block, SND.NXT);
		}
		
		transmission_control_block.close(interface, now.to_milliseconds());
		
		None
	}
	
	#[inline(always)]
	fn alarm_wheel<TCBA: TransmissionControlBlockAbstractions>(alarms: &Alarms<TCBA>) -> &AlarmWheel<Self, TCBA>
	{
		alarms.linger_alarm_wheel()
	}
	
	#[inline(always)]
	fn offset_of_parent_alarm_from_transmission_control_block() -> usize
	{
		offset_of!(TransmissionControlBlock<TCBA>, linger_alarm)
	}
}
