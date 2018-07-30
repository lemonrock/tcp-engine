// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


pub(crate) trait AlarmBehaviour<TCBA: TransmissionControlBlockAbstractions>: Sized + Debug
{
	#[inline(always)]
	fn process_alarm(transmission_control_block: &mut TransmissionControlBlock<TCBA>, interface: &Interface<TCBA>, now: Tick) -> Option<TickDuration>;
	
	#[inline(always)]
	fn alarm_wheel(alarms: &Alarms<TCBA>) -> &AlarmWheel<Self, TCBA>;
	
	#[inline(always)]
	fn offset_of_parent_alarm_from_transmission_control_block() -> usize;
}
