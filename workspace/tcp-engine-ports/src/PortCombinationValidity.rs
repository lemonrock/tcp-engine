// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of predicator, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


/// Valid combinations of remote and local ports using port bit sets.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct PortCombinationValidity
{
	valid_remote_ports: PortBitSet,
	valid_local_ports: PortBitSet,
}

impl Default for PortCombinationValidity
{
	#[inline(always)]
	fn default() -> Self
	{
		Self
		{
			valid_remote_ports: PortBitSet::full_except_for_configured_remote_ports_to_drop(),
			valid_local_ports: PortBitSet::empty(),
		}
	}
}

impl PortCombinationValidity
{
	/// Is this port combination invalid?
	#[inline(always)]
	pub fn port_combination_is_invalid(&self, incoming_segment_source_port_destination_port: SourcePortDestinationPort) -> bool
	{
		let (remote_port, local_port) = incoming_segment_source_port_destination_port.remote_port_local_port().to_tuple();
		self.valid_remote_ports.does_not_contain(remote_port) || self.valid_local_ports.does_not_contain(local_port)
	}
}
