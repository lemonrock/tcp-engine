// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Yes, this is anaemic; it exists to make it easier to relate to the TCP RFCs and Finite State Machine (FSM) standards.
///
/// Modelled on the states and their definitions in RFC 793, pages 21 - 22.
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) enum State
{
	/// RFC 793, Page 22: "Represents no connection state at all."
	///
	/// Called `CLOSED` in RFC 793.
	///
	/// Logically occurs both before all other states and after all other states.
	///
	/// Pseudo-state; never actually used.
	Closed,
	
	/// RFC 793, Page 21: "Represents waiting for a connection request from any remote TCP and port."
	///
	/// Called `LISTEN` in RFC 793.
	///
	/// Pseudo-state; never actually used.
	Listen,
	
	/// RFC 793, Page 21: "Represents waiting for a matching connection request after having sent a connection request."
	///
	/// Called `SYN-SENT` in RFC 793.
	SynchronizeSent,
	
	/// RFC 793, Page 21: "Represents waiting for a confirming connection request acknowledgment after having both received and sent a connection request."
	///
	/// Called `SYN-RECEIVED` in RFC 793.
	///
	/// Pseudo-state; never actually used.
	SynchronizeReceived,
	
	/// RFC 793, Page 21: "Represents an open connection, data received can be delivered to the user.
	/// The normal state for the data transfer phase of the connection."
	///
	/// Called `ESTABLISHED` in RFC 793.
	Established,
	
	/// RFC 793, Page 21: "Represents waiting for a connection termination request from the local user."
	///
	/// Called `CLOSE-WAIT` in RFC 793.
	CloseWait,
	
	/// RFC 793, Page 21: "Represents waiting for an acknowledgment of the connection termination request previously sent to the remote TCP (The connection termination request sent to the remote TCP included an acknowledgment of the connection termination request sent from the remote TCP)."
	///
	/// Called `LAST-ACK` in RFC 793.
	LastAcknowledgment,
	
	/// RFC 793, Page 21: "Represents waiting for a connection termination request from the remote TCP, or an acknowledgment of the connection termination request previously sent."
	///
	/// Called `FIN-WAIT-1` in RFC 793.
	FinishWait1,
	
	/// RFC 793, Page 21: "Represents waiting for a connection termination request from the remote TCP."
	///
	/// Called `FIN-WAIT-2` in RFC 793.
	FinishWait2,
	
	/// RFC 793, Page 21: "Represents waiting for a connection termination request acknowledgment from the remote TCP."
	///
	/// Called `CLOSING` in RFC 793.
	Closing,
	
	/// RFC 793, Page 22: "Represents waiting for enough time to pass to be sure the remote TCP received the acknowledgment of its connection termination request."
	///
	/// Called `TIME-WAIT` in RFC 793.
	///
	/// Used to collect the 'garbage' of stray and duplicate segments for the recently closed connection arriving late (traditionaly,for 2 x MSL, ie 4 minutes). If a segment arrives which is a legitimate new connection attempt, then we should cut short the wait.
	TimeWait,
}

impl Default for State
{
	#[inline(always)]
	fn default() -> Self
	{
		State::Closed
	}
}

impl State
{
	#[inline(always)]
	pub(crate) fn is_synchronize_sent(self) -> bool
	{
		self == State::SynchronizeSent
	}
	
	#[inline(always)]
	pub(crate) fn is_established(self) -> bool
	{
		self == State::Established
	}
	
	/// RFC 793 page 32.
	#[inline(always)]
	pub(crate) fn is_non_synchronized(&self) -> bool
	{
		use self::State::*;
		
		self == SynchronizeSent || self == SynchronizeReceived
	}
	
	/// RFC 793 page 32.
	#[inline(always)]
	pub(crate) fn is_synchronized(&self) -> bool
	{
		self >= State::Established
	}
}
