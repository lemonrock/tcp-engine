// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Debug)]
struct Alarms<TCBA: TransmissionControlBlockAbstractions>
{
	retransmission_time_out_alarm_wheel: AlarmWheel<RetransmissionTimeOutAlarmBehaviour, TCBA>,
	
	keep_alive_alarm_wheel: AlarmWheel<KeepAliveAlarmBehaviour, TCBA>,
	
	/// After how long a period are keep-alive probes invoked to verify that an idle connection is still alive.
	///
	/// After this time expires, up to `inclusive_maximum_number_of_keep_alive_probes` keep-alive probes are sent every `interval`.
	/// The number sent is tracked in `number_of_keep_alive_probes_sent_once_keep_alive_time_expired`.
	///
	/// If the remote system is still reachable and functioning, it acknowledges the keep-alive probe by sending a response `Acknowledgment` to the keep-alive probe.
	///
	/// Once a response `Acknowledgment` is received:-
	/// * the delay until the next keep-alive transmission is set to `time`.
	/// * the `number_of_keep_alive_probes_sent_once_keep_alive_time_expired` is reset to zero.
	///
	/// On Linux this is the socket option `TCP_KEEPIDLE`.
	/// On Windows this is the registry entry `KeepAliveTime` and defaults to two hours. However, the current alarm logic does not support alarms after 51.2 seconds.
	///
	/// Many modern high-availability systems use much lower values, eg 6 seconds, 5 seconds, etc.
	///
	/// Defaults to ten (10) seconds.
	pub(crate) keep_alive_time: TickDuration,
	
	/// This parameter determines the interval between TCP keep-alive probes until a response is received.
	///
	/// Defaults to one (1) second.
	///
	/// On Linux this is the socket option `TCP_KEEPINTVL`.
	/// On Windows this is the registry entry `KeepAliveInterval`.
	pub(crate) keep_alive_interval: TickDuration,
	
	/// If this number of keep-alive probes have gone unanswered then the connection is dead and should be aborted.
	///
	/// This is an inclusive value.
	///
	/// If set to zero then keep-alive probes are effectively disabled.
	///
	/// On Linux this is the socket option `TCP_KEEPCNT`.
	/// On Windows this is the registry entry `TcpMaxDataRetransmissions`, and the value is shared with regular retransmission logic and defaults to 5.
	///
	/// A typical value is in the range 3 to 10.
	///
	/// Defaults to five (5).
	pub(crate) inclusive_maximum_number_of_keep_alive_probes: u8,
	
	linger_alarm_wheel: AlarmWheel<LingerAlarmBehaviour, TCBA>,
	
	/// The convention in POSIX systems is for a linger timer out of zero (0) to force a Reset rather than an normal Close and TimeWait.
	///
	/// Defaults to three (3) seconds.
	pub(crate) linger_time: TickDuration,
}

impl<TCBA: TransmissionControlBlockAbstractions> Alarms<TCBA>
{
	#[inline(always)]
	pub(crate) fn new(now: MonotonicMillisecondTimestamp) -> Self
	{
		const keep_alive_time: TickDuration = TickDuration::milliseconds_to_ticks_rounded_up(MillisecondDuration::TenSeconds);
		assert_ne!(keep_alive_time, TickDuration::Zero, "keep_alive_time '{}' should never be zero", keep_alive_time);
		
		const keep_alive_interval: TickDuration = TickDuration::milliseconds_to_ticks_rounded_up(MillisecondDuration::OneSecond);
		assert_ne!(keep_alive_interval, TickDuration::Zero, "keep_alive_interval '{}' should never be zero", keep_alive_interval);
		
		const inclusive_maximum_number_of_keep_alive_probes: u8 = 5;
		assert_ne!(inclusive_maximum_number_of_keep_alive_probes, 0, "inclusive_maximum_number_of_keep_alive_probes '{}' should never be zero", inclusive_maximum_number_of_keep_alive_probes);
		
		Self
		{
			retransmission_time_out_alarm_wheel: AlarmWheel::new(now),
			
			keep_alive_alarm_wheel: AlarmWheel::new(now),
			keep_alive_time,
			keep_alive_interval,
			inclusive_maximum_number_of_keep_alive_probes,
			
			linger_alarm_wheel: AlarmWheel::new(now),
			linger_time: TickDuration::milliseconds_to_ticks_rounded_up(MillisecondDuration::ThreeSeconds),
		}
	}
	
	/// Progresses alarms and returns a monotonic millisecond timestamp that can be used as an input to `incoming_segment()`.
	#[inline(always)]
	pub(crate) fn progress(&self, interface: &Interface<TCBA>) -> MonotonicMillisecondTimestamp
	{
		let now = Tick::now();
		self.retransmission_time_out_alarm_wheel.progress(now, interface);
		self.keep_alive_alarm_wheel.progress(now, interface);
		self.linger_alarm_wheel.progress(now, interface);
		now
	}
	
	#[inline(always)]
	pub(crate) fn retransmission_time_out_alarm_wheel(&self) -> &AlarmWheel<RetransmissionTimeOutAlarmBehaviour, TCBA>
	{
		&self.retransmission_time_out_alarm_wheel
	}
	
	#[inline(always)]
	pub(crate) fn keep_alive_alarm_wheel(&self) -> &AlarmWheel<RetransmissionTimeOutAlarmBehaviour, TCBA>
	{
		&self.keep_alive_alarm_wheel
	}
	
	#[inline(always)]
	pub(crate) fn linger_alarm_wheel(&self) -> &AlarmWheel<RetransmissionTimeOutAlarmBehaviour, TCBA>
	{
		&self.linger_alarm_wheel
	}
}
