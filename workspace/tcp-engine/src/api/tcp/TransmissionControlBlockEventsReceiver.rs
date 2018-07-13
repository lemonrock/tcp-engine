// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Represents an user of a transmission control block.
///
/// There is an implicit first event, 'created', which occurs just before `SYN` is sent for a client open, or just after `ACK` is received by a server listener.
pub trait TransmissionControlBlockEventsReceiver
{
	/// Either this or `aborted()` is the last event.
	fn closed(&self);
	
	/// Either this or `closed()` is the last event.
	fn aborted(&self);
	
	
	// State Transitions
	
	/// Entered the Established state.
	///
	/// A client opener has established a connection.
	///
	/// * Always occurs prior to `closed()`.
	/// * `aborted()` may occur instead of this.
	/// * Does not occur for server listeners.
	fn entered_state_established(&self);
}
