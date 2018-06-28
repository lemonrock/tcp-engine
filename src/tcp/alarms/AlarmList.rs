// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
struct AlarmList<AB: AlarmBehaviour, TCBA: TransmissionControlBlockAbstractions>
{
	head: Cell<*mut Alarm<AB, TCBA>>,
}

impl <AB: AlarmBehaviour, TCBA: TransmissionControlBlockAbstractions> Default for AlarmList<AB, TCBA>
{
	#[inline(always)]
	fn default() -> Self
	{
		Self::Empty
	}
}

impl<AB: AlarmBehaviour, TCBA: TransmissionControlBlockAbstractions> AlarmList<AB, TCBA>
{
	const Empty: Self = Self
	{
		head: Cell::new(null_mut()),
	};
	
	#[inline(always)]
	pub(crate) fn push(&self, alarm_to_schedule: &mut Alarm<AB, TCBA>)
	{
		debug_assert!(alarm_to_schedule.is_cancelled(), "alarm_to_schedule is already scheduled");
		
		let old_head = self.head();
		let new_head = alarm_to_schedule as *mut Alarm<AB, TCBA>;
		
		debug_assert_ne!(old_head, new_head, "current head and the alarm_to_schedule can not be the same");
		
		alarm_to_schedule.set_next(old_head);
		alarm_to_schedule.set_previous(null_mut());
		
		if old_head.is_not_null()
		{
			old_head.dereference_unchecked().set_previous(new_head);
		}
		self.set_head(new_head);
	}
	
	#[inline(always)]
	pub(crate) fn expired(&self, interface: &Interface<TCBA>, now: Tick)
	{
		let mut expired_alarm_pointer = self.head();
		
		// Must be done before expiring alarms are executed in case an alarm reschedules itself into this same list (unlikely, but possible).
		self.set_head(null_mut());
		
		while expired_alarm_pointer.is_not_null()
		{
			expired_alarm_pointer.dereference_unchecked().expired(interface, now);
			
			expired_alarm_pointer = expired_alarm.next()
		}
	}
	
	#[inline(always)]
	pub(crate) fn set_next_of_head(&self, next: *mut Alarm<AB, TCBA>)
	{
		self.head().dereference_unchecked().set_next(next)
	}
	
	#[inline(always)]
	fn head(&self) -> *mut Alarm<AB, TCBA>
	{
		self.head.get()
	}
	
	#[inline(always)]
	fn set_head(&self, head: *mut Alarm<AB, TCBA>)
	{
		self.head.set(head);
	}
}
