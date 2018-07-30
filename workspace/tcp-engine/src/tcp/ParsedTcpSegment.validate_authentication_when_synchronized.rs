// This file is part of tcp-engine. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT. No part of tcp-engine, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2017 The developers of tcp-engine. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/tcp-engine/master/COPYRIGHT.


macro_rules! validate_authentication_when_synchronized
{
	($self: ident, $transmission_control_block: ident) =>
	{
		{
			use self::Authentication::*;

			match $self.tcp_options.authentication
			{
				None => if $transmission_control_block.authentication_is_required()
				{
					invalid!($self, "TCP RFC 2385 or RFC 5926 authentication is required")
				}
				
				Some(ref authentication) => match authentication
				{
					Rfc5925Authentication { .. } => invalid!($self, "TCP RFC 5925 authentication is not yet supported"),
					
					Rfc2385ObsoleteMD5 { digest } => match $transmission_control_block.md5_authentication_key()
					{
						None => invalid!($self, "TCP RFC 2385 authentication is required"),
						
						Some(md5_authentication_key) => if md5_authentication_key.is_invalid(digest, $self.source_internet_protocol_address, &$self.interface.local_internet_protocol_address, $self.options_length, $self.payload_length, $self.SEG)
						{
							invalid!($self, "TCP RFC 2385 authentication failed")
						}
					}
				},
			}
		}
	}
}
