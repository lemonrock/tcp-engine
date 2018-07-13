// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


// With a tick size of 128 ms, this gives just over 65 seconds, ie just over one minute.
pub(crate) const NumberOfRingSlotsForAlarmsSoonToGoOffCompilerHack: usize = 512;

pub(crate) struct AlarmWheel<AB: AlarmBehaviour, TCBA: TransmissionControlBlockAbstractions>
{
	last_called_at: Cell<Tick>,
	alarms_which_expire_soon_ring: [AlarmList<AB, TCBA>; NumberOfRingSlotsForAlarmsSoonToGoOffCompilerHack],
}

impl<AB: AlarmBehaviour, TCBA: TransmissionControlBlockAbstractions> AlarmWheel<AB, TCBA>
{
	const NumberOfRingSlotsForAlarmsSoonToGoOff: usize = NumberOfRingSlotsForAlarmsSoonToGoOffCompilerHack;
	
	pub(crate) const InclusiveMaximumGoesOffInTicks: TickDuration = TickDuration::new((Self::NumberOfRingSlotsForAlarmsSoonToGoOff - 1) as u64);
	
	#[inline(always)]
	pub(crate) fn new(now: Tick) -> Self
	{
		Self
		{
			last_called_at:
			{
				debug_assert_ne!(now, Tick::Zero, "now can not be zero");
				Cell::new(now - 1)
			},
			
			alarms_which_expire_soon_ring: Default::default(),
		}
	}
	
	/// Alarms are added approximately, but will always go off at the `goes_off_in_ticks`.
	///
	/// Internally, if an alarm goes off at a time greater than the number of slots in the alarm wheel, it will be scheduled to go off as far as possible and then be rescheduled; internally, a remainder (in ticks) is kept to deduce when this should be.
	///
	/// The remainder may be compressed; if so, a maximum remainder of 65,535 ticks is possible (just over 2 hours); this caps alarms to (65,535 + 512) ticks x 128 ms tick size => c. just over 2 hours 20 mins.
	///
	/// If more than one alarm is added at the same tick, then the alarm added *later* will go off before the alarm added *earlier*.
	///
	/// `goes_off_in_ticks` is not calculated from 'now' but from whenever `progress()` was last called at. As long as `progress()` is being called frequently, and at least every tick, then this has no impact.
	///
	/// Alarms where `goes_off_in_ticks` is zero are *not* executed immediately but when `progress` is called next (and at least one tick has elapsed) *except* when an alarm was rescheduled and the progress loop has not yet reached 'now'.
	#[inline(always)]
	pub(crate) fn schedule_alarm(&self, goes_off_in_ticks: TickDuration, alarm_to_schedule: &mut Alarm<AB, TCBA>)
	{
		debug_assert!(alarm_to_schedule.is_cancelled(), "alarm_to_schedule is already scheduled");
		
		let (minimum_goes_off_in_ticks, ring_slot_index) =
		{
			let goes_off_in_ticks = min(goes_off_in_ticks, Self::InclusiveMaximumGoesOffInTicks);
			let goes_off_at = self.last_called_at.get() + goes_off_in_ticks;
			(goes_off_in_ticks, goes_off_at.ring_slot_index(Self::NumberOfRingSlotsForAlarmsSoonToGoOff))
		};
		
		{
			if goes_off_in_ticks > minimum_goes_off_at
			{
				let remainder = goes_off_in_ticks - minimum_goes_off_at;
				alarm_to_schedule.set_remainder(remainder);
			}
			else
			{
				alarm_to_schedule.set_remainder(TickDuration::Zero);
			}
		}
		
		self.push_alarm(ring_slot_index, alarm_to_schedule);
	}
	
	/// Ideally, once this once per tick.
	///
	/// * if called twice or more tick, nothing happens;
	/// * if called after more than `Self::NumberOfRingSlotsForAlarmsSoonToGoOff / 2` ticks,then alarms which are rescheduled may go off early;
	#[inline(always)]
	pub(crate) fn progress(&self, now: Tick, interface: &Interface<TCBA>)
	{
		let last_called_at = self.last_called_at.get();
		debug_assert!(last_called_at <= now, "last_called_at '{:?}' is greater than now '{:?}' which should be impossible if monotonically increasing", last_called_at, now);
		
		let number_of_ticks_which_have_elapsed_since_last_called = now - last_called_at;
		
		if likely(number_of_ticks_which_have_elapsed_since_last_called.is_zero())
		{
			return
		}
		
		// This MUST be updated before expiring alarms are executed, in case an expiring alarm wishes to reschedule.
		self.last_called_at.set(now);
		
		let just_after_last_called_at = last_called_at + 1;
		let mut ring_slot_index = just_after_last_called_at.ring_slot_index(Self::NumberOfRingSlotsForAlarmsSoonToGoOff);
		let mut expired_tick = just_after_last_called_at;
		while expired_tick <= now
		{
			let alarm_list = self.get_expiring_soon_alarm_list(ring_slot_index);
			alarm_list.expired(interface, now);
			ring_slot_index = ring_slot_index.wrapping_add(1);
			expired_tick += 1;
		}
	}
	
	#[inline(always)]
	fn push_alarm(&self, ring_slot_index: usize, alarm_to_schedule: &mut Alarm<AB, TCBA>)
	{
		let alarm_list = self.get_expiring_soon_alarm_list(ring_slot_index);
		
		alarm_to_schedule.set_ring_slot_index(ring_slot_index);
		
		alarm_list.push(alarm_to_schedule);
	}
	
	#[inline(always)]
	fn get_expiring_soon_alarm_list(&self, ring_slot_index: usize) -> &AlarmList<AB, TCBA>
	{
		unsafe { self.alarms_which_expire_soon_ring.get_unchecked(ring_slot_index) }
	}
}
