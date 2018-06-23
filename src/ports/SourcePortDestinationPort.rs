// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Default, Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) struct SourcePortDestinationPort
{
	source_port: NetworkEndianU16,
	destination_port: NetworkEndianU16,
}

impl SourcePortDestinationPort
{
	#[inline(always)]
	pub(crate) fn from_source_port_destination_port(source_port: NetworkEndianU16, destination_port: NetworkEndianU16) -> Self
	{
		Self
		{
			source_port,
			destination_port,
		}
	}
	
	#[inline(always)]
	pub(crate) fn remote_port_local_port(self) -> RemotePortLocalPort
	{
		unsafe { transmute(self) }
	}
	
	#[inline(always)]
	pub(crate) fn source_port(&self) -> NetworkEndianU16
	{
		self.source_port
	}
	
	#[inline(always)]
	pub(crate) fn destination_port(&self) -> NetworkEndianU16
	{
		self.destination_port
	}
	
	#[inline(always)]
	pub(crate) fn to_big_endian_u32(self) -> u32
	{
		unsafe { transmute(self) }
	}
}
