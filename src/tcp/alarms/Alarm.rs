// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Debug)]
pub(crate) struct Alarm<AB: AlarmBehaviour, TCBA: TransmissionControlBlockAbstractions>
{
	// Only valid when scheduled.
	next: *mut Alarm<AB, TCBA>,
	
	// Only valid when scheduled.
	previous: *mut Alarm<AB, TCBA>,
	
	compressed_ring_slot_index: u16,
	
	// The number of ticks this alarm goes off in after it is expired by the AlarmWheel.
	// Only required for alarms that exceed 512 ticks (c. 65 seconds with a 128ms tick size).
	compressed_remainder: u16,

	alarm_behaviour: AB,
}

impl<AB: AlarmBehaviour, TCBA: TransmissionControlBlockAbstractions> Default for Alarm<AB, TCBA>
{
	#[inline(always)]
	fn default() -> Self
	{
		Self
		{
			next: unsafe { uninitialized() },
			previous: unsafe { uninitialized() },
			compressed_ring_slot_index: Self::RingSlotIndexForUnscheduledAlarm,
			compressed_reschedule_slot_indices: 0,
			alarm_behaviour: AB::default(),
		}
	}
}

impl<AB: AlarmBehaviour, TCBA: TransmissionControlBlockAbstractions> Alarm<AB, TCBA>
{
	const RingSlotIndexForUnscheduledAlarm: u16 = (NumberOfRingSlotsForAlarmsSoonToGoOffCompilerHack + 1) as u16;
	
	#[inline(always)]
	pub(crate) fn alarm_behaviour_mutable_reference(&mut self) -> &mut AB
	{
		&mut self.alarm_behaviour
	}
	
	#[inline(always)]
	pub(crate) fn is_scheduled(&self) -> bool
	{
		debug_assert!(self.compressed_ring_slot_index <= Self::RingSlotIndexForUnscheduledAlarm, "Invalid value for compressed_ring_slot_index '{}'", self.compressed_ring_slot_index);
		
		self.compressed_ring_slot_index != Self::RingSlotIndexForUnscheduledAlarm
	}
	
	#[inline(always)]
	pub(crate) fn is_cancelled(&self) -> bool
	{
		debug_assert!(self.compressed_ring_slot_index <= Self::RingSlotIndexForUnscheduledAlarm, "Invalid value for compressed_ring_slot_index '{}'", self.compressed_ring_slot_index);
		
		self.compressed_ring_slot_index == Self::RingSlotIndexForUnscheduledAlarm
	}
	
	#[inline(always)]
	fn reset(&mut self)
	{
		self.compressed_ring_slot_index = Self::RingSlotIndexForUnscheduledAlarm;
	}
	
	#[inline(always)]
	fn transmission_control_block_mutable_reference(&mut self) -> &mut TransmissionControlBlock<TCBA>
	{
		let raw_pointer = ((self as *mut Self as usize) - AB::offset_of_parent_alarm_from_transmission_control_block()) as *mut TransmissionControlBlock<TCBA>;
		unsafe { &mut * raw_pointer }
	}
	
	#[inline(always)]
	pub(crate) fn set_remainder(&mut self, remainder: TickDuration)
	{
		let remainder: u64 = remainder.into();
		
		self.compressed_remainder = if remainder > (::std::u16::MAX as u64)
		{
			::std::u16::MAX
		}
		else
		{
			remainder as u16
		};
	}
	
	#[inline(always)]
	pub(crate) fn schedule(&mut self, alarms: &Alarms<TCBA>, goes_off_in_ticks: TickDuration)
	{
		debug_assert!(self.is_cancelled(), "alarm is already scheduled");
		
		let alarm_wheel = AB::alarm_wheel(alarms);
		
		alarm_wheel.schedule_alarm(goes_off_in_ticks, self);
	}
	
	#[inline(always)]
	pub(crate) fn expired(&mut self, interface: &Interface<TCBA>, now: Tick)
	{
		if self.compressed_remainder != 0
		{
			self.schedule(interface.alarms(), TickDuration::new(self.compressed_remainder as u64));
			return
		}
		
		self.reset();
		
		let transmission_control_block = self.transmission_control_block_mutable_reference();
		let reschedule_goes_off_in_ticks = AB::process_alarm(transmission_control_block, interface, now);
		if let Some(reschedule_goes_off_in_ticks) = reschedule_goes_off_in_ticks
		{
			self.schedule(interface.alarms(), reschedule_goes_off_in_ticks)
		}
	}
	
	#[inline(always)]
	pub(crate) fn cancel(&mut self, alarms: &Alarms<TCBA>)
	{
		if self.is_cancelled()
		{
			return
		}
		
		let next = self.next();
		let previous = self.previous();
		
		let is_head_of_an_alarm_list = previous.is_null();
		
		if is_head_of_an_alarm_list
		{
			let alarm_wheel = AB::alarm_wheel(alarms);
			let alarm_list = alarm_wheel.get_expiring_soon_alarm_list(self.ring_slot_index());
			
			alarm_list.set_next_of_head(next);
		}
		else
		{
			previous.dereference_unchecked().set_next(next)
		}
		
		self.reset();
	}
	
	#[inline(always)]
	fn next(&self) -> *mut Self
	{
		self.next
	}
	
	#[inline(always)]
	fn set_next(&self, next: *mut Self)
	{
		self.next = next
	}
	
	#[inline(always)]
	fn previous(&self) -> *mut Self
	{
		self.previous
	}
	
	#[inline(always)]
	fn set_previous(&self, previous: *mut Self)
	{
		self.previous = previous
	}
	
	#[inline(always)]
	fn ring_slot_index(&self) -> usize
	{
		self.compressed_ring_slot_index as usize
	}
	
	#[inline(always)]
	fn set_ring_slot_index(&self, ring_slot_index: usize)
	{
		debug_assert!((ring_slot_index as u16) < Self::RingSlotIndexForUnscheduledAlarm, "ring_slot_index '{}' is too big", ring_slot_index);
		
		self.compressed_ring_slot_index = ring_slot_index as u16
	}
	
	#[inline(always)]
	fn dereference_unchecked<'a>(this: *mut Self) -> &'a mut T
	{
		unsafe { &mut * this }
	}
}
