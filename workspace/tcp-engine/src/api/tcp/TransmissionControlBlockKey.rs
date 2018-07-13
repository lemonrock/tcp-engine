// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


#[derive(Debug)]
pub struct TransmissionControlBlockKey<Address: InternetProtocolAddress>
{
	ports: Ports,
	remote_internet_protocol_address: Address,
}

impl<Address: InternetProtocolAddress> TransmissionControlBlockKey<Address>
{
	#[inline(always)]
	pub(crate) fn for_client(remote_internet_protocol_address: Address, remote_port_local_port: RemotePortLocalPort) -> Self
	{
		Self
		{
			ports: Ports::from_remote_port_local_port(remote_port_local_port),
			remote_internet_protocol_address,
		}
	}
	
	#[inline(always)]
	pub(crate) fn from_incoming_segment(source_internet_protocol_address: &Address, SEG: &ParsedTcpSegment) -> Self
	{
		Self
		{
			ports: Ports::from_incoming_segment(SEG.source_port_destination_port()),
			remote_internet_protocol_address: source_internet_protocol_address.clone(),
		}
	}
	
	#[inline(always)]
	pub fn remote_internet_protocol_address(&self) -> &Address
	{
		&self.remote_internet_protocol_address
	}
	
	#[inline(always)]
	pub(crate) fn remote_port_local_port(&self) -> RemotePortLocalPort
	{
		self.ports.remote_port_local_port()
	}
	
	#[inline(always)]
	pub fn remote_port(&self) -> u16
	{
		self.ports.remote_port()
	}
	
	#[inline(always)]
	pub fn local_port(&self) -> u16
	{
		self.ports.local_port()
	}
}
