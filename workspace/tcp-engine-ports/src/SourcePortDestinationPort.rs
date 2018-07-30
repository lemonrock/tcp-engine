// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// A source port-destination port combination, as might be found in a TCP or UDP segment.
#[derive(Default, Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct SourcePortDestinationPort
{
	source_port: NetworkEndianU16,
	destination_port: NetworkEndianU16,
}

impl SourcePortDestinationPort
{
	/// From a `source_port` and a `destination_port`.
	#[inline(always)]
	pub fn from_source_port_destination_port(source_port: NetworkEndianU16, destination_port: NetworkEndianU16) -> Self
	{
		Self
		{
			source_port,
			destination_port,
		}
	}
	
	/// For an incoming segment, converted to a remote port-local port combination.
	#[inline(always)]
	pub fn remote_port_local_port(self) -> RemotePortLocalPort
	{
		unsafe { transmute(self) }
	}
	
	/// Source port.
	#[inline(always)]
	pub fn source_port(&self) -> NetworkEndianU16
	{
		self.source_port
	}
	
	/// Destination port.
	#[inline(always)]
	pub fn destination_port(&self) -> NetworkEndianU16
	{
		self.destination_port
	}
	
	#[doc(hidden)]
	#[inline(always)]
	pub fn to_big_endian_u32(self) -> u32
	{
		unsafe { transmute(self) }
	}
}
