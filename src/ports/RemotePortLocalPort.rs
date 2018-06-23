// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Default, Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) struct RemotePortLocalPort
{
	remote_port: NetworkEndianU16,
	
	/// For a listening server, this is the port listened on.
	///
	/// For a client, this is the ephemeral port used.
	local_port: NetworkEndianU16,
}

impl RemotePortLocalPort
{
	#[inline(always)]
	pub(crate) fn from_remote_port_local_port(remote_port: NetworkEndianU16, local_port: NetworkEndianU16) -> Self
	{
		Self
		{
			remote_port,
			local_port,
		}
	}
	
	#[inline(always)]
	pub(crate) fn for_send(&self) -> SourcePortDestinationPort
	{
		SourcePortDestinationPort::from_source_port_destination_port(self.local_port, self.remote_port)
	}
	
	#[inline(always)]
	pub(crate) fn to_tuple(&self) -> (u16, u16)
	{
		(self.remote_port.to_native_endian(), self.local_port.to_native_endian())
	}
	
	#[inline(always)]
	pub(crate) fn remote_port(&self) -> NetworkEndianU16
	{
		self.remote_port
	}
	
	#[inline(always)]
	pub(crate) fn local_port(&self) -> NetworkEndianU16
	{
		self.local_port
	}
}
