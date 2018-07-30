// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


macro_rules! increment_retransmissions
{
	($self: ident, $interface: ident, $now: ident) =>
	{
		{
			match $self.increment_retransmissions()
			{
				None =>
				{
					$self.aborted($interface, $now);
					return None
				}
				
				Some(number_of_transmissions) => number_of_transmissions,
			}
		}
	}
}
