// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Creates users of a transmission control block.
pub trait TransmissionControlBlockEventsReceiverCreator
{
	/// The type of tcp receiver created (typically an enumeration or a wrapper around function pointers).
	type EventsReceiver: TransmissionControlBlockEventsReceiver;
	
	/// Create a receiver.
	#[inline(always)]
	fn create<Address: InternetProtocolAddress>(key: &TransmissionControlBlockKey<Address>) -> Self::EventsReceiver;
}

