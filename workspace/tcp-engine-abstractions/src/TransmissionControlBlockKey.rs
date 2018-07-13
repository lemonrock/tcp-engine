// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Key (identifier) of a Transmission Control Block (TCB).
#[derive(Debug)]
pub struct TransmissionControlBlockKey<Address: InternetProtocolAddress>
{
	ports: Ports,
	remote_internet_protocol_address: Address,
}

impl<Address: InternetProtocolAddress> TransmissionControlBlockKey<Address>
{
	/// For a client.
	#[inline(always)]
	pub fn for_client(remote_internet_protocol_address: Address, remote_port_local_port: RemotePortLocalPort) -> Self
	{
		Self
		{
			ports: Ports::from_remote_port_local_port(remote_port_local_port),
			remote_internet_protocol_address,
		}
	}
	
	/// From an incoming segment.
	#[inline(always)]
	pub fn from_incoming_segment(source_internet_protocol_address: &Address, SEG: &TcpSegment) -> Self
	{
		Self
		{
			ports: Ports::from_incoming_segment_source_port_destination_port(SEG.source_port_destination_port()),
			remote_internet_protocol_address: source_internet_protocol_address.clone(),
		}
	}
	
	/// Remote internet protocol address.
	#[inline(always)]
	pub fn remote_internet_protocol_address(&self) -> &Address
	{
		&self.remote_internet_protocol_address
	}
	
	/// Remote port-local port combination.
	#[inline(always)]
	pub fn remote_port_local_port(&self) -> RemotePortLocalPort
	{
		self.ports.remote_port_local_port()
	}
	
	/// Remote port.
	#[inline(always)]
	pub fn remote_port(&self) -> NetworkEndianU16
	{
		self.ports.remote_port()
	}
	
	/// Local port.
	#[inline(always)]
	pub fn local_port(&self) -> NetworkEndianU16
	{
		self.ports.local_port()
	}
}
