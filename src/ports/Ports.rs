// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


pub(crate) union Ports
{
	remote_port_local_port: RemotePortLocalPort,
	incoming_segment_source_port_destination_port: SourcePortDestinationPort,
}

impl Debug for Ports
{
	#[inline(always)]
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
	{
		unsafe { write!(f, "Ports {{ remote_port: {}, local_port: {} }}", self.remote_port(), self.local_port()) }
	}
}

impl Ports
{
	#[inline(always)]
	pub(crate) fn from_incoming_segment(SEG: &ParsedTcpSegment) -> Self
	{
		Self
		{
			incoming_segment_source_port_destination_port: SEG.source_port_destination_port()
		}
	}
	
	#[inline(always)]
	pub(crate) fn from_remote_port_local_port(remote_port_local_port: RemotePortLocalPort) -> Self
	{
		Self
		{
			remote_port_local_port,
		}
	}
	
	#[inline(always)]
	pub(crate) fn remote_port_local_port(&self) -> RemotePortLocalPort
	{
		unsafe { self.remote_port_local_port }
	}
	
	#[inline(always)]
	pub(crate) fn remote_port(&self) -> NetworkEndianU16
	{
		unsafe { self.remote_port_local_port.remote_port() }
	}
	
	#[inline(always)]
	pub(crate) fn local_port(&self) -> NetworkEndianU16
	{
		unsafe { self.remote_port_local_port.local_port() }
	}
}
