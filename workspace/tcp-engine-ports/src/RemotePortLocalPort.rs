// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// A remote port-local port combination.
#[derive(Default, Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct RemotePortLocalPort
{
	remote_port: NetworkEndianU16,
	
	/// For a listening server, this is the port listened on.
	///
	/// For a client, this is the ephemeral port used.
	local_port: NetworkEndianU16,
}

impl RemotePortLocalPort
{
	/// From a `remote_port` and a `local_port`.
	#[inline(always)]
	pub fn from_remote_port_local_port(remote_port: NetworkEndianU16, local_port: NetworkEndianU16) -> Self
	{
		Self
		{
			remote_port,
			local_port,
		}
	}
	
	/// For sending to a remote peer.
	#[inline(always)]
	pub fn for_send(&self) -> SourcePortDestinationPort
	{
		SourcePortDestinationPort::from_source_port_destination_port(self.local_port, self.remote_port)
	}
	
	/// As a tuple in native endian form.
	#[inline(always)]
	pub fn to_tuple(&self) -> (u16, u16)
	{
		(self.remote_port.to_native_endian(), self.local_port.to_native_endian())
	}
	
	/// Remote port.
	#[inline(always)]
	pub fn remote_port(&self) -> NetworkEndianU16
	{
		self.remote_port
	}
	
	/// Local port.
	#[inline(always)]
	pub fn local_port(&self) -> NetworkEndianU16
	{
		self.local_port
	}
	
	#[inline(always)]
	fn to_bytes(&self) -> &[u8; 4]
	{
		unsafe { transmute(self) }
	}
}
