// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Abstractions so that a TransmissionControlBlock can be used with different platforms and network stacks.
pub trait TransmissionControlBlockAbstractions: Sized
{
	/// Type of tcp receiver creator.
	type EventsReceiverCreator: TransmissionControlBlockEventsReceiverCreator;
	
	/// Internet Protocol Address.
	type Address: InternetProtocolAddress;
	
	/// The type of contiguous packet created.
	type Packet: NetworkPacket;
	
	/// The type of table.
	type PMTUTable: PathMaximumTransmissionUnitTable<Self::Address>;
}
