// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// This alarm serves several purposes:-
///
/// * Before the state becomes synchronized (ie SynchronizeSent), it aborts connections that have exceed an user time out but does not send a Reset;
/// * When the state is Established, FinishWait1, FinishWait2 or CloseWait (and, the phantom state, SynchronizeRecevied), it aborts connection that have exceeded an user time out and sends a Reset;
/// * When the state is Closing or LastAcknowledgment it aborts connections that have exceed the last measured retransmission time out but does not send a Reset;
/// * When the state is TimeWait, it closes connections when the TimeWait time has expired (this is supposed to be 2 * MSL, the Maximum Segment Lifetime, which is 2 minutes, but that is far too long in a modern network)
///
/// This timer is complementary to the keep-alive timer.
#[derive(Default, Debug)]
pub(crate) struct UserTimeOutAlarmBehaviour<TCBA: TransmissionControlBlockAbstractions>;

impl<TCBA: TransmissionControlBlockAbstractions> AlarmBehaviour<TCBA> for UserTimeOutAlarmBehaviour<TCBA>
{
	#[inline(always)]
	fn process_alarm(transmission_control_block: &mut TransmissionControlBlock<TCBA>, interface: &Interface<TCBA>, now: Tick) -> Option<TickDuration>
	{
		transmission_control_block.abort(interface, now.to_milliseconds());
		
		None
	}
	
	#[inline(always)]
	fn alarm_wheel(alarms: &Alarms<TCBA>) -> &AlarmWheel<Self, TCBA>
	{
		alarms.user_time_out_alarm_wheel()
	}
	
	#[inline(always)]
	fn offset_of_parent_alarm_from_transmission_control_block() -> usize
	{
		offset_of!(TransmissionControlBlock<TCBA>, user_time_out_alarm)
	}
}

impl<TCBA: TransmissionControlBlockAbstractions> UserTimeOutAlarmBehaviour<TCBA>
{
	// TODO: change this as state changes.
	xxxx
}
