// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Represents an user of a TCP Socket
pub trait TransmissionControlBlockEventsReceiver
{
	/// A client has established a connection.
	fn client_connection_established(&self);
	
	/// The TimeWait state has begun and the transmission control block is 'lingering'.
	///
	/// This call will be followed by either `finish()` at some point or `finish_forcibly_closed()`.
	fn begin_time_wait(&self);
	
	/// Occurs before either `forcibly_closed()` or `finish()`.
	fn closed(&self);
	
	/// Finish acknowledgment received.
	///
	/// Either this or `forcibly_closed()` occur.
	fn finish(&self);
	
	/// If `is_state_established` is false, then the event is similar to an `ECONNRESET` error when using a POSIX API.
	///
	/// Caused by:-
	/// * Receiving a Reset
	/// * A Keep-Alive time out (no notification made to client peer to avoid revealing internal state).
	/// * Unable to resechedule a keep alive alarm (no notification made to client peer to avoid revealing internal state).
	///
	/// Either this or `finish()` occur.
	fn finish_forcibly_closed(&self, is_state_established: bool);
	
	/// Keep alive gave up.
	fn keep_alive_dead(&self);
}

