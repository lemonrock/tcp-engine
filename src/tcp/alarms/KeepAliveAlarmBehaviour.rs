// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Default, Debug)]
pub(crate) struct KeepAliveAlarmBehaviour<TCBA: TransmissionControlBlockAbstractions>
{
	last_acknowledgment_occurred_at: Tick,
	number_of_keep_alive_probes_sent_once_keep_alive_time_expired: u8,
}

impl<TCBA: TransmissionControlBlockAbstractions> AlarmBehaviour for KeepAliveAlarmBehaviour<TCBA>
{
	#[inline(always)]
	fn process_alarm<TCBA: TransmissionControlBlockAbstractions>(transmission_control_block: &mut TransmissionControlBlock<TCBA>, interface: &Interface<TCBA>) -> Option<TickDuration>
	{
		let this: &mut Self = transmission_control_block.keep_alive_alarm.alarm_behaviour;
		
		debug_assert!(transmission_control_block.is_state_after_exchange_of_synchronized(), "state is not yet Established or later");
		
		let ticks_since_last_peer_activity_on_the_connection =
		{
			let now = Tick::now();
			let last_acknowledgment_occurred_at = this.last_acknowledgment_occurred_at;
			debug_assert!(now >= last_acknowledgment_occurred_at, "now '{:?}' is before last_acknowledgment_occurred_at '{:?}'", now, last_acknowledgment_occurred_at);
			last_acknowledgment_occurred_at - now
		};
		
		let alarms = interface.alarms();
		
		if ticks_since_last_peer_activity_on_the_connection >= alarms.keep_alive_time
		{
			let number_of_keep_alive_probes_sent_once_keep_alive_time_expired = this.number_of_keep_alive_probes_sent_once_keep_alive_time_expired;
			if number_of_keep_alive_probes_sent_once_keep_alive_time_expired == alarms.inclusive_maximum_number_of_keep_alive_probes
			{
				transmission_control_block.forcibly_close(interface);
				return None
			}
			else
			{
				if unlikely(interface.send_probe_without_packet_to_reuse(transmission_control_block).is_err())
				{
					transmission_control_block.forcibly_close(interface);
					return None
				}
				this.number_of_keep_alive_probes_sent_once_keep_alive_time_expired += 1;
			}
			
			Some(alarms.keep_alive_interval)
		}
		else
		{
			this.number_of_keep_alive_probes_sent_once_keep_alive_time_expired = 0;
			
			Some(alarms.keep_alive_time)
		}
	}
	
	#[inline(always)]
	fn alarm_wheel<TCBA: TransmissionControlBlockAbstractions>(alarms: &Alarms<TCBA>) -> &AlarmWheel<Self, TCBA>
	{
		alarms.keep_alive_alarm_wheel()
	}
	
	#[inline(always)]
	fn offset_of_parent_alarm_from_transmission_control_block() -> usize
	{
		offset_of!(TransmissionControlBlock<TCBA>, keep_alive_alarm)
	}
}

impl<TCBA: TransmissionControlBlockAbstractions> KeepAliveAlarmBehaviour<TCBA>
{
	#[inline(always)]
	pub(crate) fn record_last_acknowledgment_occurred_at(&mut self, now: MonotonicMillisecondTimestamp)
	{
		self.last_acknowledgment_occurred_at = now
	}
}
